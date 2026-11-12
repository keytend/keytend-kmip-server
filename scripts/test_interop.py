#!/usr/bin/env python3
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

"""Reproduce five independent client tests. Missing clients fail the run."""
import argparse,hashlib,json,os,pathlib,subprocess,tempfile,time
from image_evidence import local_image_id,packaged_evidence,source_commit,native_sha256
from test_database import ContainerServer
from test_runtime import ROOT,Server
import python_env
parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--skip-build',action='store_true',help='use the frozen prebuilt server binary');parser.add_argument('--engine',default='podman');a=parser.parse_args()
CACHE=ROOT/'.cache'
OUTPUT='interop-image.json' if a.image else 'interop.json'
ART=ROOT/'artifacts';ART.mkdir(exist_ok=True)
(ART/OUTPUT).write_text(json.dumps({'status':'running'}))
def run(name,args,env=None,cwd=ROOT):
    started=time.monotonic()
    p=subprocess.run(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=600)
    (ART/f'{name}.log').write_text(p.stdout)
    print(p.stdout,flush=True)
    if p.returncode:
        (ART/OUTPUT).write_text(json.dumps({'status':'failed','failed_step':name,'exit_code':p.returncode}))
        raise RuntimeError(f'{name} failed with exit {p.returncode}; see artifacts/{name}.log')
    return {'client':name,'status':'passed','duration_seconds':round(time.monotonic()-started,2)}
lock=json.loads((ROOT/'interop/clients.lock.json').read_text())
for name,entry in lock.items():
    dest=CACHE/name
    if not dest.exists():subprocess.run(['git','clone','--quiet',entry['repo'],str(dest)],check=True)
    sha=subprocess.check_output(['git','-C',str(dest),'rev-parse','HEAD'],text=True).strip()
    if sha!=entry['commit']:
        subprocess.run(['git','-C',str(dest),'fetch','--quiet','origin',entry['commit']],check=True)
        subprocess.run(['git','-C',str(dest),'checkout','--quiet',entry['commit']],check=True)
# PyKMIP's dependencies and build backend from the hash-locked interop/requirements.txt; PyKMIP itself
# from its pinned commit, built with that setuptools and nothing else downloaded.
venv=python_env.ensure(lock=python_env.INTEROP_LOCK)
run('install-pykmip',[str(venv/'bin/pip'),'install','--disable-pip-version-check','--no-deps','--no-build-isolation','--no-index','-q',str(CACHE/'PyKMIP')])
run('build-libkmip',['make','-s','-C',str(CACHE/'libkmip'),'libs'])
run('build-libkmip-adapter',['cc','-Wall','-Wextra','-Werror','-I',str(CACHE/'libkmip/include'),str(ROOT/'interop/libkmip.c'),str(CACHE/'libkmip/lib/libkmip.a'),'-lssl','-lcrypto','-o',str(CACHE/'libkmip-test')])
if not a.skip_build:run('build-server',['cargo','build','--locked'])
elif not a.image:assert (ROOT/'target/debug/keytend-kmip-server').is_file(),'build the server before selecting --skip-build'
binary_hash=native_sha256(a.image)
image_id=local_image_id(a.engine,a.image) if a.image else None
image=packaged_evidence(image_id) if image_id else {}
results=[]
with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-interop-') as d:
    with (ContainerServer(d,a.engine,a.image) if a.image else Server(d)) as s:
        env={**os.environ,'KMIP_PKI':str(s.pki),'KMIP_PORT':str(s.port)}
        for name,args,cwd in [
            ('pykmip',[str(venv/'bin/python'),str(ROOT/'interop/pykmip.py')],ROOT),
            ('libkmip',[str(CACHE/'libkmip-test')],ROOT),
            ('ovh',['go','run','-mod=readonly','.'],ROOT/'interop/ovh'),
            # Same OVH implementation, pinned to the tagged v0.9.2 release (qualification profile).
            ('ovh-release',['go','run','-mod=readonly','.'],ROOT/'interop/ovh-release'),
            ('thales',['go','run','-mod=readonly','.'],ROOT/'interop/thales'),
            ('nlnet',['cargo','run','--locked','--manifest-path',str(ROOT/'interop/nlnet/Cargo.toml')],ROOT),
        ]:results.append(run(name,args,env,cwd))
        if a.image:(ART/'interop-image-server.log').write_text(subprocess.check_output([a.engine,'logs',s.name],text=True,stderr=subprocess.STDOUT))
    if not a.image:(ART/'interop-server.log').write_text((pathlib.Path(d)/'server.log').read_text())
(ART/OUTPUT).write_text(json.dumps({'status':'passed','clients':results,'source_revisions':lock,**({'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]} if not a.image else image)},indent=2)+'\n')
print('PASS all five independent clients and the OVH v0.9.2 release profile')
