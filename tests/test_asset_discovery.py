"""Asset discovery retains evidence without exposing tokens or importing publishers."""
import json
import pathlib
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import research as r
import refresh
from test_research import AT


class AssetDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.registry=r.empty_registry()
        self.policy={'asset_paths':['/specific-pixel.js']}

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

    def test_failed_asset_request_is_not_imported_as_evidence(self):
        reference='12345678-1234-1234-1234-123456789abc'
        search={'results':[{'_id':reference}]}
        url='https://unrelated.example.net/specific-pixel.js'
        scan={'task':{'time':AT},'data':{'requests':[{'request':{'request':{'url':url}},'response':{'hash':'a'*64,'response':{'url':url,'status':404,'mimeType':'text/html'}}}]}}
        with patch.object(refresh,'POLICY',self.policy),patch.object(refresh,'fetch',side_effect=[json.dumps(search).encode(),json.dumps(scan).encode()]):
            refresh.discover_assets(self.registry,time.monotonic()+10,AT,set())
        self.assertNotIn('domain:unrelated.example.net',self.registry['indicators'])
