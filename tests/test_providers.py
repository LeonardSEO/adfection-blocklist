"""Shared account limits, Free-only endpoints, sanitized output and secret isolation."""
import copy
import datetime as dt
import json
import pathlib
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import providers as p
import research as r
import refresh
from test_research import AT, measurement


class ProviderTests(unittest.TestCase):
    def inputs(self):
        registry=r.empty_registry()
        key=r.ensure_indicator(registry,'known.example.org','bootstrap')
        registry['indicators'][key]['status']='historical'
        measurement(registry,'known.example.org')
        return {project:(copy.deepcopy(registry),{'asset_paths':['/specific.js']}) for project in p.PROJECTS}

    def prepare(self,state=None,at=AT,enabled=None):
        return p.prepare(state or {},self.inputs(),enabled or {'urlscan':True,'censys':True},at,'123',{})

    def test_both_projects_share_daily_monthly_reservations_and_reruns(self):
        state,plan=self.prepare()
        row=state['days'][AT[:10]]
        self.assertEqual(row['search'],4)
        self.assertEqual(row['retrieve'],200)
        self.assertLessEqual(row['censys'],2)
        self.assertEqual(state['months'][AT[:7]]['censys'],row['censys'])
        state,second=self.prepare(state)
        self.assertTrue(all(not s['searches'] and not s['censys'] for s in second['projects'].values()))
        self.assertEqual(state['days'][AT[:10]],row)

    def test_month_cap_resets_by_calendar_month_not_workflow_run(self):
        state={'months':{'2026-11':{'censys':100}}}
        state,plan=self.prepare(state)
        self.assertFalse(any(s['censys'] for s in plan['projects'].values()))
        state,plan=self.prepare(state,'2026-12-01T12:00:00+00:00')
        # Old TLS may not be used; add public bootstrap IPs for a December lookup.
        inputs=self.inputs()
        for registry,_ in inputs.values():r.ensure_indicator(registry,'1.1.1.1')
        state,plan=p.prepare(state,inputs,{'urlscan':True,'censys':True},'2026-12-02T12:00:00+00:00','456',{})
        self.assertEqual(state['months']['2026-12']['censys'],1)  # Shared asset is reserved once.

    def test_missing_keys_reserve_no_budget_and_make_no_calls(self):
        state,plan=self.prepare(enabled={'urlscan':False,'censys':False})
        self.assertEqual(state['days'][AT[:10]]['search'],0)
        with patch.object(p,'api_call') as call:
            _,report=p.collect(plan,call=call)
        call.assert_not_called();self.assertEqual(report['status'],'skipped')

    def test_job_retry_cannot_repeat_already_reserved_api_calls(self):
        _,plan=self.prepare()
        with patch.object(p,'api_call') as call:
            _,report=p.collect(plan,attempt=2,call=call)
        call.assert_not_called();self.assertEqual(report['status'],'replay-skipped')

    def test_only_free_endpoints_public_simple_search_and_public_ips(self):
        p.valid_request('urlscan',p.search_url('page.domain:known.example.org'))
        p.valid_request('urlscan',p.provider_url('urlscan','retrieve','12345678-1234-1234-1234-123456789abc'))
        p.valid_request('censys',p.provider_url('censys','certificate','a'*64))
        for provider,url in [('censys','https://api.platform.censys.io/v3/global/search/query'),
                             ('censys','https://api.platform.censys.io/v3/global/asset/host/127.0.0.1'),
                             ('urlscan','https://urlscan.io/api/v1/scan/'),
                             ('urlscan','https://attacker.example.org/api/v1/search/'),
                             ('urlscan',p.search_url('content.identifiers:secret'))]:
            with self.assertRaises(ValueError):p.valid_request(provider,url)

    def test_error_or_redirect_does_not_retry_or_follow_with_credentials(self):
        _,plan=self.prepare()
        seen=[]
        def call(provider,url,seconds):
            seen.append((provider,url));return {'status':302,'headers':{'location':'https://attacker.example.org/'}}
        _,report=p.collect(plan,call=call,sleep=lambda _:None)
        self.assertEqual(len(seen),2) # One urlscan quota request, one Censys lookup.
        self.assertTrue(report['blocked'])
        self.assertNotIn('attacker',json.dumps(report))

    def test_server_quota_reset_beyond_budget_stops_without_extra_calls(self):
        _,plan=self.prepare();clock=[0.]
        def call(provider,url,seconds):
            return {'status':200,'data':{'results':[]},'headers':{'x-rate-limit-remaining':'0','x-rate-limit-reset-after':'3600'}}
        _,report=p.collect(plan,call=call,clock=lambda:clock[0],sleep=lambda n:clock.__setitem__(0,clock[0]+n),seconds=10)
        self.assertLessEqual(report['calls'].get('search',0),1)

    def test_private_scans_and_personal_url_query_are_never_exported(self):
        body={'results':[{'_id':'x','task':{'visibility':'private'},'page':{'domain':'private.example.org'}},
                         {'_id':'y','task':{'visibility':'public','time':AT},'page':{'domain':'public.example.org','url':'https://public.example.org/?token=PRIVATE'}}]}
        clean=p.public_search(body)
        self.assertEqual(len(clean['results']),1);self.assertNotIn('PRIVATE',json.dumps(clean))
        url='https://asset.example.net/specific.js?token=PRIVATE'
        detail={'task':{'visibility':'public','time':AT},'data':{'cookies':['PRIVATE'],'requests':[{'request':{'request':{'url':url}},'response':{'hash':'a'*64,'response':{'url':url,'status':200,'mimeType':'application/javascript','headers':{'secret':'PRIVATE'}}}}]}}
        clean=p.public_result(detail,['/specific.js'])
        self.assertNotIn('PRIVATE',json.dumps(clean));self.assertEqual(len(clean['data']['requests']),1)
        self.assertEqual(p.public_result({**detail,'task':{'visibility':'private'}},['/specific.js'])['data']['requests'],[])

    def test_censys_names_preserve_actual_observation_or_unknown_time(self):
        data={'result':{'resource':{'dns':{'names':['new-root.example.net'],'forward_dns':{'known.example.org':{'resolve_time':AT}}}}}}
        names=p.censys_names(data,'host')
        self.assertIn({'name':'new-root.example.net','observed_at':None},names)
        self.assertIn({'name':'known.example.org','observed_at':AT},names)

    def test_measurement_uses_cache_and_never_authenticates_or_calls_urlscan(self):
        url=p.search_url('page.domain:known.example.org')
        cache={'responses':{url:{'fetched_at':r.utcnow(),'body':{'results':[]}}}}
        with patch.object(refresh,'PROVIDER_SNAPSHOT',cache),patch.object(refresh.subprocess,'run') as run:
            self.assertEqual(json.loads(refresh.fetch(url,time.monotonic()+5)),{'results':[]})
            with self.assertRaises(OSError):refresh.fetch(p.search_url('page.domain:missing.example.org'),time.monotonic()+5)
        run.assert_not_called()

    def test_censys_new_root_enters_measurement_queue_without_auto_admission(self):
        registry=r.empty_registry()
        cache={'censys':[{'url':p.provider_url('censys','host','1.1.1.1'),'kind':'host','value':'1.1.1.1','fetched_at':AT,
                         'names':[{'name':'new-root.example.net','observed_at':AT}]}]}
        with patch.object(refresh,'PROVIDER_SNAPSHOT',cache),patch.object(refresh,'fetch',side_effect=OSError),patch.object(refresh,'task') as task:
            refresh.run(registry,time.monotonic()+5,AT,set())
        self.assertEqual(registry['indicators']['domain:new-root.example.net']['status'],'candidate')
        self.assertEqual([c.args[2] for c in task.call_args_list],['dns','measure'])

    def test_quota_preflight_zero_searches_issues_no_search_request(self):
        _,plan=self.prepare()
        def call(provider,url,seconds):
            return {'status':200,'headers':{},'data':{'limits':{'search':{'day':{'remaining':0}}}}}
        _,report=p.collect(plan,call=call,sleep=lambda _:None)
        self.assertEqual(report['calls'].get('search',0),0)
        self.assertEqual(report['status'],'partial')

    def test_one_censys_lookup_is_reused_by_both_projects(self):
        _,plan=self.prepare()
        def call(provider,url,seconds):
            data={'results':[]} if provider=='urlscan' else {'result':{'resource':{'names':['new-root.example.net']}}}
            return {'status':200,'data':data,'headers':{}}
        with patch.object(p,'utcnow',return_value=AT):
            snapshots,report=p.collect(plan,call=call,sleep=lambda _:None)
        self.assertEqual(report['calls']['censys'],1)
        self.assertTrue(all(any(row['names'] for row in snap['censys']) for snap in snapshots.values()))
        self.assertTrue(p.validate_snapshots(snapshots))

    def test_worker_sends_only_host_bound_key_and_does_not_follow_redirect(self):
        from unittest.mock import MagicMock
        response=MagicMock();response.status=302;response.getheaders.return_value=[('Location','https://attacker.example.org/')]
        connection=MagicMock();connection.getresponse.return_value=response
        sock=MagicMock()
        with patch.dict(p.os.environ,{'URLSCAN_API_KEY':'FAKE-URLSCAN-KEY','CENSYS_PAT':'FAKE-CENSYS-KEY'}), \
             patch.object(p,'resolve_public',return_value=['1.1.1.1']),patch.object(p,'dial',return_value=sock), \
             patch.object(p.ssl,'create_default_context') as context,patch.object(p.http.client,'HTTPConnection',return_value=connection):
            context.return_value.wrap_socket.return_value=sock
            result=p.api_worker('urlscan',p.search_url('page.domain:known.example.org'),10)
        headers=connection.request.call_args.kwargs['headers']
        self.assertEqual(headers['API-Key'],'FAKE-URLSCAN-KEY')
        self.assertNotIn('Authorization',headers)
        connection.request.assert_called_once()
        self.assertNotIn('FAKE',json.dumps(result));self.assertNotIn('attacker',json.dumps(result))

    def test_one_scan_keeps_all_project_assets_when_result_is_cached(self):
        inputs=self.inputs()
        inputs['adfection'][1]['asset_paths']=['/first.js','/second.js']
        _,plan=p.prepare({},inputs,{'urlscan':True,'censys':False},AT,'123',{})
        uid='12345678-1234-1234-1234-123456789abc'
        def call(provider,url,seconds):
            data={'results':[]}
            if 'filename' in url:
                data={'results':[{'_id':uid,'task':{'visibility':'public','time':AT},'page':{'domain':'publisher.example.org'}}]}
            if '/result/' in url:
                rows=[]
                for path in ('/first.js','/second.js'):
                    target='https://asset.example.net'+path
                    rows.append({'request':{'request':{'url':target}},'response':{'hash':'a'*64,'response':{'url':target,'status':200,'mimeType':'application/javascript'}}})
                data={'task':{'visibility':'public','time':AT},'data':{'requests':rows}}
            return {'status':200,'headers':{},'data':data}
        with patch.object(p,'utcnow',return_value=AT):
            snapshots,report=p.collect(plan,call=call,sleep=lambda _:None)
        body=snapshots['adfection']['responses'][p.provider_url('urlscan','retrieve',uid)]['body']
        self.assertEqual(len(body['data']['requests']),2)
        self.assertEqual(report['calls']['retrieve'],1)
