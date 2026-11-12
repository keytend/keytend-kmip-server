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

"""Build and export a Docker-compatible archive, source fingerprint, SBOM and provenance statement.

--arch selects the image platform (default amd64, written to artifacts/ as before;
other platforms go to artifacts/linux-<arch>/). --build-host builds on another
podman host over SSH, natively for that platform, and transfers the archive back
with its SHA-256 checked on both ends. The provenance statement
(provenance.intoto.json) is a listed file of the release set, covered by the
signatures over its SHA256SUMS (scripts/release_artifacts.py).
Packaging does not imply full conformance or production approval.
"""
import argparse,datetime,hashlib,io,json,os,pathlib,platform,shlex,subprocess,sys,tarfile,tempfile,tomllib,uuid
from image_evidence import PLATFORMS,archive_name,artifacts_dir,base_images,base_indexes,check_platform,dockerfile_arg,source_commit,source_fingerprints
from image_rootfs import RPMDB,Rootfs,elf_info,rpm_packages
from remote_host import Host,deterministic_tar
import release_provenance
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
p=argparse.ArgumentParser();p.add_argument('--engine',default='podman',choices=['podman','docker']);p.add_argument('--tag')
p.add_argument('--arch',default='amd64',choices=sorted(PLATFORMS),help='image platform (default amd64)')
p.add_argument('--build-host',help='build on this podman host over SSH (native for --arch), then transfer and verify the archive')
p.add_argument('--ssh',default='ssh -o BatchMode=yes',help='SSH client command for --build-host')
p.add_argument('--remote-dir',help='remote working root for --build-host: sources, temporary files and the podman image store (default ~/keytend-kmip-server-<arch>)')
a=p.parse_args();a.tag=a.tag or (f'localhost/keytend-kmip-server:{VERSION}' if a.arch=='amd64' else f'localhost/keytend-kmip-server:{VERSION}-{a.arch}')
OUT=artifacts_dir(a.arch);OUT.mkdir(parents=True,exist_ok=True)
def capture(args):return subprocess.check_output(args,cwd=ROOT,text=True)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
def checksum(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def build_failed(log,lines=60):
    """The build output goes only to its log; print the end of it, so a failed CI job shows why."""
    tail=log.read_text(errors='replace').splitlines()[-lines:] if log.exists() else []
    print(f'image build failed; last {len(tail)} lines of {log}:',*tail,sep='\n',file=sys.stderr,flush=True)
sources=source_fingerprints()
# The build context the Dockerfile copies is exactly the fingerprinted runtime sources.
context=deterministic_tar({name:ROOT/name for name in sources})
bases=base_images(a.arch);target=PLATFORMS[a.arch]['platform']
build_args=dict(bases)
build_flags=(['--format','docker'] if a.engine=='podman' else [])+['--platform',target]+[x for k,v in build_args.items() for x in ('--build-arg',f'{k}={v}')]+['-t',a.tag]
archive=OUT/archive_name(VERSION,a.arch);temporary=OUT/f'.image-{uuid.uuid4().hex}.tar'
started=now()
if a.build_host:
    host=Host(a.build_host,a.ssh,a.remote_dir or f'~/keytend-kmip-server-{a.arch}');builder=host.facts(a.engine)
    assert builder['machine'] in {'amd64':['x86_64'],'arm64':['aarch64','arm64']}[a.arch],f"{a.build_host} is {builder['machine']}, not a native {a.arch} host"
    directory=host.mktemp('keytend-kmip-server-build');build=[a.engine,'build',*build_flags,'.']
    try:
        host.push({name:ROOT/name for name in sources},directory)
        try:
            with open(OUT/'image-build.log','wb') as log:host.run(f'cd {shlex.quote(directory)} && '+shlex.join(build),stdout=log,timeout=4*3600)
        except Exception:build_failed(OUT/'image-build.log');raise
        host.run(f'{a.engine} save --format docker-archive --output {shlex.quote(directory)}/image.tar {shlex.quote(a.tag)}' if a.engine=='podman' else f'docker save --output {shlex.quote(directory)}/image.tar {shlex.quote(a.tag)}',timeout=1800)
        remote_id=json.loads(host.text(f'{a.engine} image inspect {shlex.quote(a.tag)}'))[0]['Id']
        try:host.fetch(f'{directory}/image.tar',temporary);temporary.replace(archive)
        finally:
            if temporary.exists():temporary.unlink()
    finally:host.run(f'rm -rf {shlex.quote(directory)}',check=False)
    finished=now()
    # Load the transferred archive so local tooling (inspect, index, scan) sees the same image.
    subprocess.run([a.engine,'load','--input',str(archive)],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    assert json.loads(capture([a.engine,'image','inspect',a.tag]))[0]['Id']==remote_id,'loaded image differs from the image built on '+a.build_host
    # Published metadata (image.json, provenance) records what the builder was, not where: no SSH
    # destination, home directory or image-store path.
    builder_host=dict({k:v for k,v in builder.items() if k not in ('host','root','image_store')},host='remote',remote=True)
else:
    build=[a.engine,'build',*build_flags,'.']
    # Build from the same normalized context as a remote build (0644/0755 modes, no other files), so the
    # image does not depend on the checkout's umask and local and remote builds are comparable.
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-context-') as directory:
        with tarfile.open(fileobj=io.BytesIO(context)) as tar:tar.extractall(directory,filter='data')
        try:
            with open(OUT/'image-build.log','w') as log:subprocess.run(build,cwd=directory,stdout=log,stderr=subprocess.STDOUT,check=True)
        except Exception:build_failed(OUT/'image-build.log');raise
    finished=now()
    try:
        subprocess.run([a.engine,'save']+(['--format','docker-archive'] if a.engine=='podman' else [])+['--output',str(temporary),a.tag],check=True,cwd=ROOT)
        temporary.replace(archive)
    finally:
        if temporary.exists():temporary.unlink()
    builder_host=dict(host='local',machine=platform.machine(),engine=a.engine,engine_version=json.loads(capture([a.engine,'version','--format','json'])).get('Client',{}).get('Version'),remote=False)
inspect=json.loads(capture([a.engine,'image','inspect',a.tag]))[0]
assert inspect['Config']['User']=='10001:10001'
assert inspect['Config']['Labels']['org.opencontainers.image.licenses']=='Apache-2.0'
assert inspect['Config']['Labels']['org.opencontainers.image.authors']=='Jeremiah Jordan'
assert inspect['Config']['Labels']['org.opencontainers.image.base.name']==bases['UBI_MICRO'],'image was not built from the pinned base for '+a.arch
sha=checksum(archive);(OUT/f'{archive.name}.sha256').write_text(f'{sha}  {archive.name}\n')
# Read the notices, the server binary and the RPM database from the exported archive; the runtime root
# ships no shell or rpm tools, and a foreign-architecture image need not run here.
rootfs=Rootfs(archive);assert rootfs.config_id==inspect['Id'].removeprefix('sha256:')
check_platform(rootfs.config,a.arch)
for name in ['LICENSE','NOTICE']:
    assert rootfs.read(f'/usr/share/licenses/keytend-kmip-server/{name}')==(ROOT/name).read_bytes(), 'image distribution notice differs: '+name
machine,_=elf_info(rootfs.read('/usr/local/bin/keytend-kmip-server'))
assert machine==PLATFORMS[a.arch]['elf_machine'],f'server binary ELF machine {machine} is not {a.arch}'
metadata=json.loads(capture(['cargo','metadata','--locked','--format-version','1']))
packages={p['id']:p for p in metadata['packages']};nodes={n['id']:n for n in metadata['resolve']['nodes']};root=metadata['resolve']['root'];required=set()
def visit(id):
    if id in required:return
    required.add(id)
    for d in nodes[id]['deps']:
        if any(kind['kind']!='dev' for kind in d['dep_kinds']):visit(d['pkg'])
visit(root)
components=[]
for id in sorted(required):
    item=packages[id]
    if id==root:continue
    c={'type':'library','name':item['name'],'version':item['version'],'purl':f'pkg:cargo/{item["name"]}@{item["version"]}'}
    if item.get('license'):c['licenses']=[{'expression':item['license']}]
    components.append(c)
release=dict(line.split('=',1) for line in rootfs.read('/etc/os-release').decode().splitlines() if '=' in line)
distro='rhel-'+release['VERSION_ID'].strip('"')
rpms=rpm_packages(rootfs.read(RPMDB))
for name,fields in sorted(rpms.items()):
    c={'type':'library','name':name,'version':f"{fields['version']}-{fields['release']}",'purl':release_provenance.rpm_purl(name,fields,distro),
       'properties':[{'name':'rpm:sourcerpm','value':fields.get('sourcerpm','')}]}
    # RPM License tags mix SPDX and Fedora legacy names, so they are recorded verbatim as names.
    if fields.get('license'):c['licenses']=[{'license':{'name':fields['license']}}]
    components.append(c)
sbom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'serialNumber':'urn:uuid:'+str(uuid.uuid4()),'metadata':{'component':{'type':'application','name':'keytend-kmip-server','version':VERSION,'licenses':[{'license':{'id':'Apache-2.0'}}],'copyright':'Copyright 2026 Jeremiah Jordan'},'properties':[{'name':'keytend-kmip-server:scope','value':'Rust server build graph excluding dev edges, and installed container OS packages; no client SDKs'},{'name':'keytend-kmip-server:platform','value':target},{'name':'keytend-kmip-server:image-archive-sha256','value':sha}]},'components':components}
(OUT/'sbom.cdx.json').write_text(json.dumps(sbom,indent=2)+'\n')
# A release names the product repository's commit (release_candidate.py --product), which
# it has checked holds exactly these sources; otherwise this checkout's commit.
commit=os.environ.get('KMIP_SOURCE_COMMIT') or capture(['git','rev-parse','HEAD']).strip();dirty=bool(capture(['git','status','--porcelain','--untracked-files=no']).strip())
manifest={'image_tag':a.tag,'image_id':inspect['Id'],'platform':inspect.get('Os','linux')+'/'+inspect.get('Architecture','unknown'),'arch':a.arch,'archive':archive.name,'sha256':sha,'size_bytes':archive.stat().st_size,'user':inspect['Config']['User'],'healthcheck':inspect.get('Healthcheck',inspect['Config'].get('Healthcheck')),'base_images':bases,'build_host':builder_host,'license':'Apache-2.0','copyright':'Copyright 2026 Jeremiah Jordan','distribution_notices':['/usr/share/licenses/keytend-kmip-server/LICENSE','/usr/share/licenses/keytend-kmip-server/NOTICE'],'source_commit':commit,'source_dirty':source_commit()[1]}
assert manifest['platform']==target,manifest['platform']
(OUT/'image.json').write_text(json.dumps(manifest,indent=2)+'\n')
statement=release_provenance.statement(archive_name=archive.name,archive_sha256=sha,image_id=inspect['Id'],platform=target,commit=commit,dirty=dirty,
    build_command=build,build_args=build_args,base_images=bases,base_indexes=base_indexes(),build_packages=dockerfile_arg('BUILD_PACKAGES').split(),
    runtime_packages=rpms,distro=distro,context_sha256=hashlib.sha256(context).hexdigest(),source_sha256=sources,
    cargo_lock_sha256=sources['Cargo.lock'],dockerfile_sha256=sources['Dockerfile'],builder_sha256=checksum(pathlib.Path(__file__)),
    builder_host=builder_host,started=started,finished=finished,invocation='urn:uuid:'+str(uuid.uuid4()),
    byproducts={'image.json':checksum(OUT/'image.json'),'sbom.cdx.json':checksum(OUT/'sbom.cdx.json'),'image-build.log':checksum(OUT/'image-build.log')})
release_provenance.check(statement,archive.name,sha,inspect['Id'])
(OUT/'provenance.intoto.json').write_text(json.dumps(statement,indent=2)+'\n')
print(json.dumps({k:manifest[k] for k in ['image_tag','image_id','platform','sha256','size_bytes','source_commit','source_dirty']},indent=2))
