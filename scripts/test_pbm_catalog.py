# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Offline fault-injection precondition checks; no PBM or server fixture."""
import json,pathlib,tempfile,unittest
from unittest.mock import patch
import test_database_pbm_chain as chain

class CatalogTests(unittest.TestCase):
    def observe(self,states,quiet=3,timeout=10):
        now=[0];seen=[0]
        def clock():return now[0]
        def pause(seconds):now[0]+=seconds
        def snapshot(fixture):
            index=min(seen[0],len(states)-1);seen[0]+=1;return states[index]
        with tempfile.TemporaryDirectory() as directory,patch.object(chain.pbm,'OUT',pathlib.Path(directory)),patch.object(chain,'catalog_snapshot',side_effect=snapshot):
            report={}
            try:result=chain.wait_catalog_quiet(None,report,quiet,timeout,clock,pause)
            except Exception as error:return error,report,json.loads((pathlib.Path(directory)/'image.json').read_text())
            return result,report,None

    def test_stable_catalog_requires_full_quiet_window(self):
        state={'chunks':[{'name':'chunk-a'}],'locks':0};result,report,_=self.observe([state])
        self.assertEqual(result,state['chunks']);self.assertEqual(len(report['catalog_quiescence']['observations']),4)
        self.assertEqual(report['catalog_quiescence']['status'],'quiet_window_observed')

    def test_last_slice_publication_restarts_window_and_is_retained(self):
        first={'chunks':[{'name':'a'}],'locks':0};last={'chunks':[{'name':'a'},{'name':'last'}],'locks':0}
        result,report,_=self.observe([first,first,last,last,last,last])
        self.assertEqual(result,last['chunks']);observations=report['catalog_quiescence']['observations']
        self.assertEqual(len(observations),6);self.assertEqual(observations[0]['chunks'],first['chunks'])
        self.assertEqual(observations[-1]['chunks'],last['chunks'])

    def test_active_lock_resets_window(self):
        quiet={'chunks':[{'name':'a'}],'locks':0};busy=dict(quiet,locks=1)
        _,report,_=self.observe([quiet,quiet,busy,quiet,quiet,quiet,quiet])
        self.assertEqual(len(report['catalog_quiescence']['observations']),7)

    def test_busy_or_empty_catalog_times_out_with_observations(self):
        for state in [{'chunks':[{'name':'a'}],'locks':1},{'chunks':[],'locks':0}]:
            error,report,persisted=self.observe([state])
            self.assertIsInstance(error,TimeoutError);self.assertEqual(persisted,report)
            self.assertEqual(report['catalog_quiescence']['status'],'timed_out')
            self.assertEqual(len(report['catalog_quiescence']['observations']),10)

    def test_invalid_bounds_are_refused(self):
        for quiet,timeout in [(0,10),(3,3),(4,2)]:
            with self.assertRaises(ValueError):chain.wait_catalog_quiet(None,{},quiet,timeout)

if __name__=='__main__':unittest.main()
