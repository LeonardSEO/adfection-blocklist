"""Evidence-backed opt-in outputs never assert verified malware attribution."""
import copy
import pathlib
import sys
import unittest
from unittest.mock import patch
import json
import time

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import research as r
import refresh
from test_research import AT, measurement


class UnverifiedTests(unittest.TestCase):
    def setUp(self):
        self.registry=r.empty_registry()
        self.policy={'owned_roots':['known.example.org'],'cname_targets':['tenant.elb.amazonaws.com'],'asset_paths':['/specific-pixel.js']}
        self.key=r.ensure_indicator(self.registry,'new.known.example.org','legacy-lead')
        r.observe(self.registry,self.key,'legacy-lead',{'reason':'old report'},'https://example.org/report',None,AT)

    def dns(self,host=None,ip='1.1.1.1',at=AT,status=0):
        key=r.ensure_indicator(self.registry,host) if host else self.key
        return r.observe(self.registry,key,'dns',{'query_type':'A','status':status,'answers':[{'type':1,'data':ip}] if status==0 else []},'https://cloudflare-dns.com/dns-query',at,at)

    def findings(self,at=AT):
        return r.unverified_findings(self.registry,self.policy,at)

    def test_known_owned_subdomain_needs_current_public_dns(self):
        self.assertEqual(self.findings(),{})
        self.dns()
        found=self.findings()
        self.assertEqual(found['new.known.example.org']['rule'],'owned-subdomain-and-public-dns')
        self.assertEqual(self.registry['indicators'][self.key]['status'],'candidate')
        self.assertNotIn('new.known.example.org',r.publication_values(self.registry,'domain'))

    def test_shared_ip_and_certificate_alone_do_not_qualify(self):
        self.dns('unrelated.example.net')
        key=r.ensure_indicator(self.registry,'unrelated.example.net')
        r.observe(self.registry,key,'scan-service',{'ip':'1.1.1.1'},'control',AT,AT)
        self.assertNotIn('unrelated.example.net',self.findings())

    def test_private_latest_nxdomain_and_expired_evidence_are_excluded(self):
        self.dns(); self.assertTrue(self.findings())
        self.assertEqual(self.findings('2026-11-12T12:00:00+00:00'),{})
        self.dns(ip='127.0.0.1',at='2026-11-03T12:01:00+00:00')
        self.assertEqual(self.findings('2026-11-03T12:01:00+00:00'),{})
        self.dns(at='2026-11-03T12:02:00+00:00',status=3)
        self.assertEqual(self.findings('2026-11-03T12:02:00+00:00'),{})

    def test_new_independent_asset_host_can_qualify_without_root_match(self):
        self.dns('new-root.example.net')
        key=r.ensure_indicator(self.registry,'new-root.example.net')
        r.observe(self.registry,key,'asset-scan',{'path':'/specific-pixel.js','scan_id':'control','status':200,'mime_type':'application/javascript','body_sha256':'a'*64},'https://urlscan.io/control',AT,AT)
        self.assertEqual(self.findings()['new-root.example.net']['rule'],'specific-asset-and-public-dns')

    def test_dedicated_cname_can_qualify_without_shared_ip_guess(self):
        self.dns('new-root.example.net')
        key=r.ensure_indicator(self.registry,'new-root.example.net')
        r.observe(self.registry,key,'dns',{'query_type':'CNAME','status':0,'answers':[{'type':5,'data':'tenant.elb.amazonaws.com.'}]},'control',AT,AT)
        self.assertEqual(self.findings()['new-root.example.net']['rule'],'dedicated-cname-and-public-dns')

    def test_matching_live_tls_and_non_generic_http_support_cross_root_lead(self):
        anchor,ids=measurement(self.registry,'anchor.example.org')
        self.registry['indicators'][anchor]['status']='historical'
        candidate,other=measurement(self.registry,'new-root.example.net')
        for key,oids in ((anchor,ids),(candidate,other)):
            old=self.registry['observations'].pop(oids[1]);old['data'].update({'body_bytes':100,'generic':False})
            oid=r.observation_id(old);self.registry['observations'][oid]=old
            self.registry['indicators'][key]['evidence'][1]=oid
        self.dns('new-root.example.net')
        self.assertEqual(self.findings()['new-root.example.net']['rule'],'matching-live-tls-and-http')
        self.registry['indicators'][anchor]['status']='withdrawn'
        self.assertNotIn('new-root.example.net',self.findings())

    def test_allowlist_and_policy_disable_remove_only_opt_in_output(self):
        self.dns()
        self.assertEqual(r.unverified_findings(self.registry,self.policy,AT,['new.known.example.org']),{})
        self.assertEqual(r.unverified_findings(self.registry,{},AT),{})
        document={'version':1,'evaluated_at':AT,'findings':self.findings()}
        self.assertTrue(r.check_unverified(self.registry,self.policy,document))
        document['findings']['fabricated.example.org']={}
        with self.assertRaises(ValueError):r.check_unverified(self.registry,self.policy,document)

    def test_asset_discovery_imports_request_host_and_never_publisher_or_tokens(self):
        reference='12345678-1234-1234-1234-123456789abc'
        search={'results':[{'_id':reference,'page':{'domain':'publisher.example.org'}}]}
        scan={'task':{'time':AT},'data':{'requests':[{'request':{'request':{'url':'https://new-root.example.net/specific-pixel.js?token=PRIVATE'}},'response':{'hash':'a'*64,'response':{'url':'https://new-root.example.net/specific-pixel.js?token=PRIVATE','status':200,'mimeType':'application/javascript'}}}]}}
        with patch.object(refresh,'POLICY',self.policy),patch.object(refresh,'fetch',side_effect=[json.dumps(search).encode(),json.dumps(scan).encode()]):
            refresh.discover_assets(self.registry,time.monotonic()+10,AT,set())
        self.assertIn('domain:new-root.example.net',self.registry['indicators'])
        self.assertNotIn('domain:publisher.example.org',self.registry['indicators'])
        self.assertNotIn('PRIVATE',json.dumps(self.registry))
        self.assertEqual(self.registry['queue'][0]['tasks'],['dns','measure'])

    def test_all_opt_in_formats_are_separate_from_the_regular_subscription(self):
        import build
        import tempfile
        self.dns()
        slug=next(name for name in build.LISTS if name.endswith('-unverified')).removesuffix('-unverified')
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            r.write_json(root/'research/registry.json',self.registry)
            r.write_json(root/'research/project.json',self.policy)
            r.write_json(root/'research/unverified.json',{'version':1,'evaluated_at':AT,'findings':self.findings()})
            (root/'README.md').write_text('Fixture\n')
            with patch.multiple(build,ROOT=root,OUT=root/'lists',ALLOWLIST=root/'allowlist.txt'):
                build.write_all(['historical.example.net'],{'historical.example.net':'historical'})
            paths=list((root/'lists').glob('**/'+slug+'-unverified*.txt'))
            self.assertEqual(len(paths),8)
            self.assertTrue(all('new.known.example.org' in path.read_text() for path in paths))
            self.assertNotIn('new.known.example.org',(root/'lists/domains'/f'{slug}.txt').read_text())

    def test_removed_cname_does_not_keep_an_old_match_alive(self):
        self.dns('new-root.example.net')
        key=r.ensure_indicator(self.registry,'new-root.example.net')
        r.observe(self.registry,key,'dns',{'query_type':'CNAME','status':0,'answers':[{'type':5,'data':'tenant.elb.amazonaws.com.'}]},'control',AT,AT)
        later='2026-11-03T12:01:00+00:00'
        r.observe(self.registry,key,'dns',{'query_type':'CNAME','status':0,'answers':[]},'control',later,later)
        self.assertNotIn('new-root.example.net',self.findings(later))

    def test_failed_asset_request_cannot_poison_opt_in_output(self):
        reference='12345678-1234-1234-1234-123456789abc'
        search={'results':[{'_id':reference}]}
        url='https://unrelated.example.net/specific-pixel.js'
        scan={'task':{'time':AT},'data':{'requests':[{'request':{'request':{'url':url}},'response':{'hash':'a'*64,'response':{'url':url,'status':404,'mimeType':'text/html'}}}]}}
        self.dns('unrelated.example.net')
        with patch.object(refresh,'POLICY',self.policy),patch.object(refresh,'fetch',side_effect=[json.dumps(search).encode(),json.dumps(scan).encode()]):
            refresh.discover_assets(self.registry,time.monotonic()+10,AT,set())
        self.assertNotIn('unrelated.example.net',self.findings())
