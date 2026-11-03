"""Shared Free-account API coordinator. Credentials exist only in the collect job."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import http.client
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import time
import urllib.parse

from research import ROOT, read_json, write_json, utcnow, timestamp, DOMAIN_RE
from probe import public_ip, resolve_public, dial, timeout

PROJECTS = ('adfection', 'pegasus')
LIMITS = {'search': 80, 'retrieve': 200, 'censys': 2}
SECRET_NAMES = {'urlscan': 'URLSCAN_API_KEY', 'censys': 'CENSYS_PAT'}
SNAPSHOT_BASE = 'https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/research/providers/'
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
SHA = re.compile(r'[a-f0-9]{64}')


def search_url(query, size=100):
    return 'https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode(
        {'q': 'task.visibility:public AND date:>now-7d AND (' + query + ')', 'size': min(size, 100)})


def provider_url(provider, kind, value):
    if provider == 'urlscan':
        if kind == 'search':
            return value
        if kind == 'retrieve' and UUID.fullmatch(value):
            return 'https://urlscan.io/api/v1/result/' + value + '/'
        if kind == 'quota':
            return 'https://urlscan.io/api/v1/quotas'
    if provider == 'censys':
        if kind == 'certificate' and SHA.fullmatch(value):
            return 'https://api.platform.censys.io/v3/global/asset/certificate/' + value
        if kind == 'host' and public_ip(value):
            return 'https://api.platform.censys.io/v3/global/asset/host/' + value
    raise ValueError('Unsupported Free API operation')


def valid_request(provider, url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or p.username or p.password or p.port not in (None, 443) or p.fragment:
        raise ValueError('Invalid provider URL')
    if provider == 'urlscan' and p.hostname == 'urlscan.io':
        if p.path == '/api/v1/search/':
            q = urllib.parse.parse_qs(p.query)
            if set(q) != {'q', 'size'} or q['size'] not in (['20'], ['100']):
                raise ValueError('Invalid search parameters')
            expression = q['q'][0]
            if not expression.startswith('task.visibility:public AND date:>now-7d AND (') or not expression.endswith(')'):
                raise ValueError('Only public recent scans may be queried')
            term = expression.split(' AND (', 1)[1][:-1]
            if not ((term.startswith('page.domain:') and DOMAIN_RE.fullmatch(term[12:])) or
                    re.fullmatch(r'filename:"[a-zA-Z0-9_.-]+"', term)):
                raise ValueError('Unsupported Free search expression')
            return
        if not p.query and (p.path == '/api/v1/quotas' or
                            p.path.startswith('/api/v1/result/') and UUID.fullmatch(p.path[15:].rstrip('/'))):
            return
    if provider == 'censys' and p.hostname == 'api.platform.censys.io' and not p.query:
        for kind in ('host', 'certificate'):
            prefix = '/v3/global/asset/' + kind + '/'
            if p.path.startswith(prefix) and provider_url(provider, kind, p.path[len(prefix):]) == url:
                return
    raise ValueError('Only approved Free lookup/search endpoints are allowed')


def api_worker(provider, url, seconds):
    """No redirects, no proxy, authenticated TLS and host-bound credentials."""
    valid_request(provider, url)
    token = os.environ.get(SECRET_NAMES[provider])
    if not token:
        return {'status': 0, 'error': 'missing-secret', 'headers': {}}
    deadline = time.monotonic() + seconds
    p = urllib.parse.urlsplit(url)
    ip = resolve_public(p.hostname, 443, deadline)[0]
    sock = dial(ip, 443, deadline)
    connection = http.client.HTTPConnection(p.hostname, 443, timeout=timeout(deadline))
    try:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=p.hostname)
        connection.sock = sock
        headers = {'User-Agent': 'independent-blocklist/3.0', 'Accept': 'application/json',
                   'Accept-Encoding': 'identity', 'Connection': 'close'}
        headers['API-Key' if provider == 'urlscan' else 'Authorization'] = token if provider == 'urlscan' else 'Bearer ' + token
        connection.request('GET', urllib.parse.urlunsplit(('', '', p.path, p.query, '')), headers=headers)
        response = connection.getresponse()
        result = {'status': response.status, 'headers': {k.lower(): v for k, v in response.getheaders()
                   if k.lower().startswith('x-rate-limit-') or k.lower() == 'retry-after'}}
        if response.status == 200:
            body = response.read(4*1024*1024+1)
            if len(body) > 4*1024*1024:
                raise ValueError('Provider response exceeds size limit')
            result['data'] = json.loads(body)
        return result  # Error bodies and Location headers are deliberately not exposed.
    finally:
        connection.close()
        sock.close()


def api_call(provider, url, seconds):
    valid_request(provider, url)
    try:
        result = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), 'worker', provider, url, str(seconds)],
                                capture_output=True, text=True, timeout=seconds, check=True)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {'status': 0, 'error': 'deadline', 'headers': {}}
    except (subprocess.CalledProcessError, ValueError):
        return {'status': 0, 'error': 'provider-failure', 'headers': {}}


def prepare(state, inputs, enabled, at, run_id, snapshots):
    """Reserve before issuing requests; interrupted runs never refund credits."""
    from refresh import select_seeds
    day = timestamp(at).date().isoformat()
    month = day[:7]
    state = copy.deepcopy(state)
    daily = state.setdefault('days', {}).setdefault(day, {'search': 0, 'retrieve': 0, 'censys': 0, 'reserved': []})
    monthly = state.setdefault('months', {}).setdefault(month, {'censys': 0})
    plan = {'version': 1, 'run_id': run_id, 'at': at, 'projects': {}, 'snapshots': snapshots}
    used_assets = {entry['url'] for snap in snapshots.values() for entry in snap.get('censys', [])
                   if (timestamp(at)-timestamp(entry['fetched_at'])).total_seconds() < 7*86400}
    for project in PROJECTS:
        registry, policy = inputs[project]
        spec = {'searches': [], 'censys': [], 'censys_refs': [], 'limits': {'search': 0, 'retrieve': 0}, 'disabled': []}
        if enabled['urlscan'] and 'urlscan:'+project not in daily['reserved']:
            seeds = [r['value'] for r in registry['indicators'].values() if r['type']=='domain' and r['status'] in ('historical','accepted')]
            spec['searches'] = [{'url': search_url('page.domain:'+seed), 'anchor': seed}
                                for seed in select_seeds(seeds, timestamp(at).date())]
            spec['searches'] += [{'url': search_url('filename:"'+path.rsplit('/',1)[-1]+'"',20), 'asset': path}
                                 for path in policy.get('asset_paths', [])]
            spec['searches'] = spec['searches'][:min(40, LIMITS['search']-daily['search'])]
            spec['limits'] = {'search': len(spec['searches']), 'retrieve': min(100, LIMITS['retrieve']-daily['retrieve'])}
            for name in ('search', 'retrieve'): daily[name] += spec['limits'][name]
            daily['reserved'].append('urlscan:'+project)
        else:
            spec['disabled'].append('urlscan:missing-secret-or-already-reserved')
        if enabled['censys'] and 'censys:'+project not in daily['reserved'] and daily['censys']<2 and monthly['censys']<100:
            assets = []
            for item in registry['indicators'].values():
                for oid in item['evidence']:
                    row = registry['observations'][oid]
                    if row['kind']=='tls' and row['observed_at'] and 0 <= (timestamp(at)-timestamp(row['observed_at'])).total_seconds() <= 7*86400:
                        assets.append(('certificate',row['data']['certificate_sha256']))
                if item['type']=='ip' and public_ip(item['value']): assets.append(('host',item['value']))
            for kind, value in dict.fromkeys(assets):
                url = provider_url('censys',kind,value)
                spec['censys_refs'].append(url)
                if url not in used_assets:
                    spec['censys'].append({'kind':kind,'value':value,'url':url}); used_assets.add(url)
                    daily['censys']+=1; monthly['censys']+=1; break
            daily['reserved'].append('censys:'+project)
        else:
            spec['disabled'].append('censys:missing-secret-or-budget-reserved')
        plan['projects'][project] = spec
    state['version'] = 1
    return state, plan


def public_search(data):
    rows = []
    for row in data.get('results', []):
        task = row.get('task', {})
        if task.get('visibility') != 'public': continue
        page = row.get('page', {})
        rows.append({'_id': row.get('_id'), 'page': {k:page[k] for k in ('domain','ip','port') if k in page},
                     'task': {k:task[k] for k in ('time','visibility') if k in task}})
    return {'results': rows}


def public_result(data, paths):
    task = data.get('task', {})
    if task.get('visibility') != 'public': return {'task': {}, 'data': {'requests': []}}
    rows=[]
    for row in data.get('data', {}).get('requests', []):
        request = row.get('request', {}).get('request', {})
        response = row.get('response', {})
        http = response.get('response', {})
        parsed = urllib.parse.urlsplit(request.get('url',''))
        served = urllib.parse.urlsplit(http.get('url',''))
        if parsed.scheme not in ('https','http') or parsed.path not in paths or not DOMAIN_RE.fullmatch(parsed.hostname or ''):
            continue
        if served.hostname != parsed.hostname or served.path != parsed.path: continue
        # Keep only exact known asset paths. No URL query, cookies, body or arbitrary headers.
        safe = urllib.parse.urlunsplit((parsed.scheme,parsed.hostname,parsed.path,'',''))
        rows.append({'request':{'request':{'url':safe}}, 'response':{'hash':response.get('hash',''),
                     'response':{'url':safe,'status':http.get('status'),'mimeType':http.get('mimeType','')}}})
    return {'task':{k:task[k] for k in ('time','visibility') if k in task},'data':{'requests':rows}}


def censys_names(data, kind):
    resource = data.get('result', {}).get('resource', {})
    if kind == 'host':
        dns = resource.get('dns', {})
        names = {name:info.get('resolve_time') for name,info in dns.get('forward_dns', {}).items()}
        for name in dns.get('names', []): names.setdefault(name,None)
    else:
        parsed = resource.get('parsed', {})
        names = {name:None for name in resource.get('names',parsed.get('extensions',{}).get('subject_alt_name',{}).get('dns_names',[]))}
    return [{'name':name.lower().rstrip('.').removeprefix('*.' ),'observed_at':at} for name,at in names.items()
            if DOMAIN_RE.fullmatch(name.lower().rstrip('.').removeprefix('*.'))][:100]


def collect(plan, attempt=1, call=api_call, clock=time.monotonic, sleep=time.sleep, seconds=600):
    snapshots = copy.deepcopy(plan['snapshots'])
    if attempt != 1: return snapshots, {'status':'replay-skipped','reason':'reserved requests cannot be replayed'}
    deadline = clock()+seconds
    paths={row['asset'] for spec in plan['projects'].values() for row in spec['searches'] if 'asset' in row}
    scan_cache={url:row for snap in snapshots.values() for url,row in snap.get('responses',{}).items()
                if '/result/' in url and 0<=(timestamp(utcnow())-timestamp(row['fetched_at'])).total_seconds()<=7*86400}
    blocked = {}; ready = {}; counters = {}; events = []; available={}; deferred={}
    def request(provider, action, url):
        key=(provider,action)
        if provider in blocked or clock()>=deadline or available.get(action,1)<=0:
            deferred[action]=deferred.get(action,0)+1
            return None
        wait=ready.get(key,0)-clock()
        if wait>0:
            if clock()+wait>=deadline:
                deferred[action]=deferred.get(action,0)+1
                return None
            sleep(wait)
        response=call(provider,url,min(20,max(.01,deadline-clock())))
        if action in available: available[action]-=1
        counters[action]=counters.get(action,0)+1
        status=response['status']; headers=response.get('headers',{})
        events.append({'provider':provider,'action':action,'status':status,'error':response.get('error')})
        pace=6 if action=='search' else 1
        ready[key]=clock()+pace
        if headers.get('x-rate-limit-remaining') == '0':
            try: ready[key]=clock()+max(pace,float(headers['x-rate-limit-reset-after']))
            except (KeyError,ValueError): blocked[provider]='quota-reset-unknown'
        if status in (401,402,403,429) or 300<=status<400:
            blocked[provider]='http-'+str(status)
        return response.get('data') if status==200 else None
    if any(p['searches'] for p in plan['projects'].values()):
        quota=request('urlscan','quota',provider_url('urlscan','quota',''))
        if quota:
            for action in ('search','retrieve'):
                values=[row['remaining'] for window,row in quota.get('limits',{}).get(action,{}).items()
                        if window=='day' and isinstance(row,dict) and isinstance(row.get('remaining'),int)]
                if values: available[action]=min(values)
    for project in PROJECTS:
        spec=plan['projects'][project]
        snap=snapshots.setdefault(project,{'version':1,'responses':{},'censys':[]})
        snap['generated_at']=plan['at']; snap['disabled']=spec['disabled']
        # Reuse only recent public sanitized data, never a raw provider response.
        snap['responses']={url:row for url,row in snap.get('responses',{}).items()
                           if 0<=(timestamp(plan['at'])-timestamp(row['fetched_at'])).total_seconds()<=7*86400}
        retrieved=0
        for search in spec['searches']:
            url=search['url']; data=request('urlscan','search',url)
            if data is None: continue
            clean=public_search(data)
            snap['responses'][url]={'fetched_at':utcnow(),'body':clean}
            if 'asset' not in search: continue
            for row in clean['results']:
                uid=row.get('_id','')
                if not UUID.fullmatch(uid or '') or retrieved>=spec['limits']['retrieve']: continue
                detail=provider_url('urlscan','retrieve',uid)
                if detail in scan_cache:
                    snap['responses'][detail]=scan_cache[detail]
                    continue
                retrieved+=1
                data=request('urlscan','retrieve',detail)
                if data is not None:
                    snap['responses'][detail]={'fetched_at':utcnow(),'body':public_result(data,paths)}
                    scan_cache[detail]=snap['responses'][detail]
        for asset in spec['censys']:
            data=request('censys','censys',asset['url'])
            if data is not None:
                snap.setdefault('censys',[]).append({'url':asset['url'],'kind':asset['kind'],
                    'value':asset['value'],'fetched_at':utcnow(),'names':censys_names(data,asset['kind'])})
        snap['censys']=[row for row in snap.get('censys',[]) if
                        0<=(timestamp(utcnow())-timestamp(row['fetched_at'])).total_seconds()<=7*86400]
    shared={row['url']:row for snapshot in snapshots.values() for row in snapshot.get('censys',[])}
    for project,spec in plan['projects'].items():
        own={row['url'] for row in snapshots[project].get('censys',[])}
        snapshots[project]['censys'].extend(shared[url] for url in spec.get('censys_refs',[]) if url in shared and url not in own)
    report={'status':('skipped' if not events else 'partial' if deferred or blocked or any(e['status']!=200 for e in events) else 'completed'),
            'at':utcnow(),'calls':counters,'events':events,'blocked':blocked,'remaining_daily_allowance':available,'deferred':deferred}
    for snapshot in snapshots.values():
        snapshot['provider_report']=report
        # The public consumer transport accepts at most 4 MiB; retain newest data within 3 MiB.
        while len(json.dumps(snapshot).encode())>3*1024*1024 and snapshot['responses']:
            oldest=min(snapshot['responses'],key=lambda url:snapshot['responses'][url]['fetched_at'])
            del snapshot['responses'][oldest]
    return snapshots, report


def validate_snapshots(snapshots):
    for project in PROJECTS:
        snap=snapshots[project]
        if snap['version']!=1: raise ValueError('Unsupported provider snapshot')
        for url,row in snap.get('responses',{}).items():
            valid_request('urlscan',url)
            if timestamp(row['fetched_at'])>timestamp(utcnow())+dt.timedelta(minutes=5):
                raise ValueError('Future provider observation')
            if '/search/' in url:
                clean=public_search(row['body'])
            else:
                if '/result/' not in url: raise ValueError('Only observations may be published')
                paths=[]
                for request in row['body'].get('data',{}).get('requests',[]):
                    parsed=urllib.parse.urlsplit(request['request']['request']['url'])
                    if parsed.query or parsed.fragment or parsed.username or parsed.password:
                        raise ValueError('Unsanitized URL in provider output')
                    paths.append(parsed.path)
                clean=public_result(row['body'],paths)
            if clean!=row['body']: raise ValueError('Non-public or unsanitized scan output')
        for row in snap.get('censys',[]):
            if row['url']!=provider_url('censys',row['kind'],row['value']):
                raise ValueError('Invalid asset lookup')
            timestamp(row['fetched_at'])
            for name in row['names']:
                if not DOMAIN_RE.fullmatch(name['name']): raise ValueError('Invalid lookup name')
                if name['observed_at']: timestamp(name['observed_at'])
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('prepare','collect','worker','validate'))
    parser.add_argument('args',nargs='*')
    args=parser.parse_args()
    if args.mode=='worker':
        try: result=api_worker(args.args[0],args.args[1],float(args.args[2]))
        except Exception as error: result={'status':0,'error':type(error).__name__,'headers':{}}
        print(json.dumps(result)); return
    if args.mode=='validate':
        validate_snapshots({p:read_json(pathlib.Path(args.args[0])/(p+'.json')) for p in PROJECTS}); return
    directory=ROOT/'research/providers'
    if args.mode=='prepare':
        inputs={}
        for project in PROJECTS:
            root=ROOT if project=='adfection' else pathlib.Path(args.args[0])
            inputs[project]=(read_json(root/'research/registry.json'),read_json(root/'research/project.json'))
        snapshots={p:read_json(directory/(p+'.json'),{'version':1,'responses':{},'censys':[]}) for p in PROJECTS}
        enabled={p:os.environ.get('HAS_'+p.upper())=='true' for p in SECRET_NAMES}
        state,plan=prepare(read_json(directory/'state.json',{}),inputs,enabled,utcnow(),os.environ['GITHUB_RUN_ID'],snapshots)
        write_json(directory/'state.json',state);write_json(pathlib.Path(args.args[1]),plan)
    else:
        snapshots,report=collect(read_json(pathlib.Path(args.args[0])),int(os.environ.get('GITHUB_RUN_ATTEMPT','1')))
        output=pathlib.Path(args.args[1])
        validate_snapshots(snapshots)
        for project,snapshot in snapshots.items():write_json(output/(project+'.json'),snapshot)
        write_json(output/'status.json',report)


if __name__=='__main__': main()
