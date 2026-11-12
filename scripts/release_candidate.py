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

"""Qualify one release candidate and write one self-contained bundle.

One run over one clean commit, in this order. Every qualification test runs the
server from the release image: harnesses that start a server executable get the image
run as one (scripts/image_server.py). cargo test tests the source code, not the image.

1. preflight: licence check, kind/kubectl, the pinned helm, and that the base image
   and package pins are current (scripts/check_image_updates.py);
2. rust: cargo test, Clippy and the replay unit tests;
3. build: `cargo build --locked`, a compile check; the executable is recorded, never run;
4. image: scripts/package.py builds and exports the image archive per platform;
5. conformance: on the image, the strict replay, the Profiles 4.1 variation and
   corrected-fixture replays, the configuration replays (3DES, Interop),
   the HTTPS transports, the legacy notes and the case inventory; the variation replay
   also on an emulated FIPS host (labelled `fips-emulated`) and on each other platform's
   native host;
6. integration: scripts/test_integration_parallel.py against the image;
7. kubernetes: disposable kind cluster, deployment and storage rotation with the Kustomize base, then
   the Helm chart end to end in its own namespace on the same cluster (scripts/test_helm_chart.py);
8. security: image scan (fails on an unreviewed finding), image hardening, the image
   FIPS test and TLS inventory, and the dependency scan;
9. java: the keytend-kmip Java client suite (scripts/test_java_release.py) on the
   pinned JDKs against the image; its reports are copied to java/;
10. release: the test reports archive (scripts/release_reports.py), the release set
   with that archive under reports/, two signatures over SHA256SUMS (cosign and
   OpenPGP) and its verification (scripts/release_artifacts.py). The reports are
   release artifacts.

The run exits 1 if any step failed; manifest.json records every step with its log.
Steps that cannot run in a mode are recorded as not run, with the reason.

External tools and caches come from scripts/toolchain.py. The run and its steps use the
scripts' virtual environment (scripts/python_env.py).
--platforms adds image platforms (default amd64 only). A non-amd64 image is built
natively on --arm64-host over SSH (scripts/package.py --build-host); its archive is
transferred back with its SHA-256 checked, and its runtime tests run on that host
(scripts/remote_image_tests.py). --soak-duration starts the Java soak detached after
the earlier steps pass.

--ci runs one job of the release workflow (.github/workflows/release.yml) on a
GitHub-hosted runner, writing a partial bundle to --bundle:

- cargo runs in the pinned UBI builder (scripts/ci_builder.py), and there is no build
  phase: nothing runs a native executable;
- the image phase loads the archives of the workflow's image job (artifacts/, from
  scripts/package.py) instead of building, and checks their image IDs;
- the platform phase runs the image tests of each non-amd64 platform on this host
  (a runner of that platform; --arm64-host local);
- kind uses the runner's Docker (--kind-provider docker), the JDKs are those named by
  KEYTEND_JDK_<major> (scripts/toolchain.py), and the TLS probe's OpenSSL client is the
  pinned UBI image's;
- --integration-groups runs a slice of the integration matrix;
- the release phase merges the other jobs' bundles (--merge), compares the arm64
  replay with the amd64 one, checks that the slices covered the whole integration
  matrix, packs the reports and assembles the release set without signing it (the
  workflow's release job signs it).
"""
import argparse,atexit,datetime,hashlib,json,os,pathlib,shlex,shutil,signal,socket,subprocess,sys,time,tomllib
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
sys.path.insert(0,str(ROOT/'scripts'))
from image_evidence import PLATFORMS,artifacts_dir,archive_name,base_images
from image_server import wrapper as image_wrapper,remove as remove_containers
import python_env,toolchain

PHASES=['preflight','rust','build','image','conformance','integration','kubernetes','security','java','release']
# Steps recorded as not run, with the reason.
NOT_RUN={
    ('rust','test_requirement_matrix'):'not run: the requirement ledger it reads is not published',
    ('conformance','requirement-matrix'):'not run: the requirement ledger it reads is not published',
    ('java','soak'):'not run in CI: the 24-hour Java soak runs only in a local release run (--soak-duration)',
    ('build','cargo'):'not run in CI: every test runs the release image; the rust job builds and tests the source',
}

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def utc():return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')

class Run:
    def __init__(self,bundle,save=lambda:None):
        """save writes the manifest; it runs as each step starts and ends, so a run that is killed
        leaves a manifest whose interrupted step reads exit 'running' (a failure)."""
        self.bundle=bundle;self.phases={};self.save=save;self.after=lambda:None;bundle.mkdir(parents=True,exist_ok=True)
    def output(self,o):
        """Bundle-relative name of a step output; one written elsewhere in the checkout is copied to outputs/."""
        path=pathlib.Path(o)
        if path.is_relative_to(self.bundle):return str(path.relative_to(self.bundle))
        if path.is_absolute() and path.is_relative_to(ROOT):
            copy=self.bundle/'outputs'/path.relative_to(ROOT);copy.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,copy)
            return str(copy.relative_to(self.bundle))
        return str(o)
    def step(self,phase,name,cmd,env=None,timeout=None,outputs=(),mark_running=True):
        log=self.bundle/'logs'/f'{phase}-{name}.log';log.parent.mkdir(exist_ok=True)
        start=time.time();print(f'[{phase}] {name}: {" ".join(map(str,cmd))}',flush=True)
        if mark_running:self.phases.setdefault(phase,{})[name]={'command':list(map(str,cmd)),'exit':'running','log':str(log.relative_to(self.bundle))};self.save()
        with open(log,'w') as out:
            # Server settings reach a step only when the run sets them (env, or the command's own `env`),
            # never from the shell that started the run.
            inherited={k:v for k,v in os.environ.items() if not k.startswith('KMIP_')}
            inherited['KEYTEND_HARNESS_RUN']=self.bundle.name
            try:code=subprocess.run(list(map(str,cmd)),cwd=ROOT,stdout=out,stderr=subprocess.STDOUT,env={**inherited,**(env or {})},timeout=timeout).returncode
            except subprocess.TimeoutExpired:code='timeout'
        record={'command':list(map(str,cmd)),'exit':code,'seconds':round(time.time()-start,1),'log':str(log.relative_to(self.bundle)),'log_sha256':sha(log),
                'outputs':{self.output(o):sha(o) for o in outputs if pathlib.Path(o).exists()}}
        self.phases.setdefault(phase,{})[name]=record;self.save();self.after();print(f'[{phase}] {name}: exit {code}',flush=True)
        return code==0
    def check(self,phase,name,problems):
        """A step that is a check of this run's own records; the problems are its log."""
        log=self.bundle/'logs'/f'{phase}-{name}.log';log.parent.mkdir(exist_ok=True)
        log.write_text(''.join(p+'\n' for p in problems) or 'passed\n')
        self.phases.setdefault(phase,{})[name]={'command':['(internal check)'],'exit':1 if problems else 0,'seconds':0,'log':str(log.relative_to(self.bundle)),'log_sha256':sha(log),'outputs':{}}
        print(f'[{phase}] {name}: {"failed" if problems else "passed"}',flush=True)
        return not problems
    def skip(self,phase,name,reason):
        self.phases.setdefault(phase,{})[name]={'exit':None,'not_run':reason}
        print(f'[{phase}] {name}: {reason}',flush=True)
    def failed(self):
        return [f'{p}/{n}' for p,steps in self.phases.items() for n,r in steps.items() if 'not_run' not in r and r['exit']!=0]

def main():
    a=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument('--engine',default='podman',choices=['podman','docker'])
    a.add_argument('--phases',nargs='+',default=PHASES,choices=PHASES+['platform'])
    a.add_argument('--platforms',nargs='+',default=['amd64'],choices=sorted(PLATFORMS),help='image platforms; amd64 is always first and drives the existing phases')
    a.add_argument('--arm64-host',help='SSH destination of a native arm64 podman host that builds and tests the arm64 image ("local": this host)')
    a.add_argument('--ssh',default='ssh -o BatchMode=yes',help='SSH client command for --arm64-host')
    a.add_argument('--arm64-remote-dir',default='~/keytend-kmip-server-arm64',help='working root on --arm64-host (sources, temporary files, podman image store)')
    a.add_argument('--soak-duration',default=None,help='ISO 8601 duration, e.g. PT24H; starts the Java catalog soak detached (only a completed 24-hour run earns PASS)')
    a.add_argument('--kind',default='kind',help='kind executable (default: from PATH, the Debian package; with --ci, the pinned release binary)')
    a.add_argument('--kubectl',default='kubectl',help='kubectl executable (default: from PATH, the Debian package; with --ci, the pinned release binary)')
    a.add_argument('--kind-node-image',default=toolchain.KIND_NODE_IMAGE,help='node image for kind create cluster')
    a.add_argument('--kind-provider',choices=['podman','docker'],help='container engine of the kind cluster (default podman in a delegated user scope; docker with --ci)')
    a.add_argument('--allow-dirty',action='store_true',help='development only; the manifest records it and the candidate cannot qualify')
    a.add_argument('--ci',action='store_true',help='one job of the release workflow on a GitHub-hosted runner (see above)')
    a.add_argument('--job',help='with --ci: the workflow job, recorded in the manifest (default: the phases)')
    a.add_argument('--bundle',type=pathlib.Path,help='bundle directory (default artifacts/release/<commit>-<time>)')
    a.add_argument('--integration-groups',nargs='+',help='run only these groups of the integration matrix')
    a.add_argument('--integration-workers',type=int,help='concurrent integration groups (test_integration_parallel.py --workers)')
    a.add_argument('--db-slots',type=int,help='concurrent database groups (test_integration_parallel.py --db-slots)')
    a.add_argument('--merge',nargs='+',type=pathlib.Path,default=[],help='with --ci, release phase: the bundles of the other jobs')
    args=a.parse_args()
    # Steps run in the scripts' virtual environment: this restarts the run in it, its bin/ first on PATH.
    python_env.activate()
    args.kind_provider=args.kind_provider or ('docker' if args.ci else 'podman')
    if 'amd64' not in args.platforms and not args.ci:raise SystemExit('--platforms must include amd64')
    args.platforms=[x for x in ['amd64'] if x in args.platforms]+sorted(set(args.platforms)-{'amd64'})
    head=git('rev-parse','HEAD');short=head[:9];dirty=bool(git('status','--porcelain'))
    stamp=utc()
    bundle=(args.bundle or ROOT/'artifacts/release'/f'{short}-{stamp}').resolve();run=Run(bundle)
    # Tag with the release version, so a loaded release archive carries the tag the documentation uses.
    image='localhost/keytend-kmip-server:'+VERSION
    manifest={'schema':1,'commit':head,'dirty':dirty,'started_at':stamp,'image_tag':image,'platforms':args.platforms,'images':{},'phases':run.phases}
    def tag(arch):return image if arch=='amd64' else f'{image}-{arch}'
    def remote(arch):return ['--build-host',args.arm64_host,'--ssh',args.ssh,'--remote-dir',args.arm64_remote_dir] if arch=='arm64' and args.arm64_host else []
    def kept(arch):return bundle/('image.docker.tar' if arch=='amd64' else f'image-linux-{arch}.docker.tar')
    def save():write_manifest(bundle,manifest)
    run.save=save
    def after():
        # A harness that killed its server wrapper leaves the container behind; remove it.
        left=remove_containers(args.engine,bundle.name)
        if left:print(f'removed {len(left)} server container(s) left by the step',flush=True)
    run.after=after
    def summarize():
        """The run's outcome so far; the reports archive packs it, so it is set before packing."""
        manifest['finished_at']=utc();manifest['failed_steps']=run.failed()
        manifest['not_run']=[f'{p}/{n}: {r["not_run"]}' for p,steps in run.phases.items() for n,r in steps.items() if 'not_run' in r]
        return manifest['failed_steps']
    def others():return [x for x in args.platforms if x!='amd64' and x in manifest['images']]
    if dirty and not args.allow_dirty:raise SystemExit('working tree is not clean; commit first')
    source_env={}
    if args.ci:
        # The workflow's own identity; the release phase merges the jobs' records.
        manifest['ci']={'job':args.job or '-'.join(args.phases),'phases':args.phases,'host':socket.gethostname(),'runner':f"{os.environ.get('RUNNER_OS','')}/{os.environ.get('RUNNER_ARCH','')}",
            'run':{k.lower().removeprefix('github_'):os.environ.get(k) for k in ['GITHUB_REPOSITORY','GITHUB_WORKFLOW_REF','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_SHA']}}
        if 'kubernetes' in args.phases:
            args.kind,args.kubectl=(str(toolchain.fetch_kube_tool(name)) if getattr(args,name)==name else getattr(args,name) for name in ('kind','kubectl'))
    # A new release checkout finds the shared cache without a hand-made symlink.
    manifest['cache']={'canonical':str(toolchain.canonical_cache()),'link':toolchain.ensure_cache_link()}
    if manifest['cache']['link']=='differs':raise SystemExit(f'{ROOT/".cache"} is not the shared cache {manifest["cache"]["canonical"]}')
    manifest['tools']={**toolchain.tools_record(args.kind,args.kubectl),'python':python_env.record()}
    cargo=['python3','scripts/ci_builder.py','run','cargo'] if args.ci else ['cargo']
    if 'preflight' in args.phases:
        run.step('preflight','license',['python3','scripts/check_license.py'])
        if not args.ci:
            # The Kubernetes tools the kubernetes phase will use, with their versions (recorded in the manifest).
            run.step('preflight','kubernetes-tools',['sh','-c',f'{args.kind} version && {args.kubectl} version --client'])
            # Downloads and checks the pinned helm on first use; the kubernetes phase runs the chart with it.
            run.step('preflight','helm',['python3','scripts/helm_tool.py','fetch'],timeout=600)
            # Base images and packages are refreshed before each release: a stale or unpublished pin, or a
            # check that cannot reach the registry or repositories, fails (the workflow's check job does this in CI).
            run.step('preflight','image-pins',['python3','scripts/check_image_updates.py','--engine',args.engine],timeout=1200,
                     outputs=[ROOT/'artifacts/image-updates.json'])
        if args.soak_duration:
            # The soak starts detached hours later; fetch and verify its signed client release now.
            run.step('preflight','soak-client',['python3','scripts/keytend_kmip_release.py'],timeout=3600)
    if 'rust' in args.phases:
        run.step('rust','test',[*cargo,'test','--locked'],timeout=7200)
        run.step('rust','clippy',[*cargo,'clippy','--locked','--all-targets','--','-D','warnings'],timeout=3600)
        run.step('rust','test_oasis_profile_replay',['python3','scripts/test_oasis_profile_replay.py'],env={'PYTHONPATH':str(ROOT/'scripts')})
        if 'test_requirement_matrix' not in run.phases['rust']:run.skip('rust','test_requirement_matrix',NOT_RUN['rust','test_requirement_matrix'])
    if 'build' in args.phases:
        if args.ci:
            run.skip('build','cargo',NOT_RUN['build','cargo'])
        else:
            # A compile check of the commit. The executable is a build artifact only: every test runs the image.
            built=ROOT/'target/debug/keytend-kmip-server'
            if built.is_symlink():built.unlink()
            if run.step('build','cargo',['cargo','build','--locked']):manifest['build']={'debug_executable_sha256':sha(built),'executed':False}
    save()
    # From here on every test runs the image. A sentinel stands in for the native executable at its
    # build path and logs any call (the rust phase, which tests the source, has run by now).
    sentinel=None
    if set(args.phases)&{'conformance','integration','kubernetes','security','java','platform'}:
        sentinel=NativeSentinel(ROOT/'target/debug/keytend-kmip-server',bundle/'native-calls.log').guard(lambda:remove_containers(args.engine,bundle.name))
    if 'image' in args.phases:
        for arch in args.platforms:
            name='package' if arch=='amd64' else f'package-{arch}'
            if args.ci:
                # The image job's archive (scripts/package.py), loaded rather than rebuilt.
                packaged=json.loads((artifacts_dir(arch)/'image.json').read_text())
                if packaged['image_tag']!=tag(arch):raise SystemExit(f"{artifacts_dir(arch)/'image.json'} is {packaged['image_tag']}, not {tag(arch)}")
                ok=run.step('image','load' if arch=='amd64' else f'load-{arch}',[args.engine,'load','--input',artifacts_dir(arch)/packaged['archive']],timeout=1800)
            else:
                ok=run.step('image',name,['python3','scripts/package.py','--engine',args.engine,'--tag',tag(arch),'--arch',arch,*remote(arch)],env=source_env,timeout=4*7200)
            if ok:
                shutil.copy2(artifacts_dir(arch)/archive_name(VERSION,arch),kept(arch))
                packaged=json.loads((artifacts_dir(arch)/'image.json').read_text())
                assert sha(kept(arch))==packaged['sha256'],'bundle archive differs from the package manifest'
                image_id=subprocess.check_output([args.engine,'image','inspect','--format','{{.Id}}',tag(arch)],text=True).strip()
                assert image_id.removeprefix('sha256:')==packaged['image_id'].removeprefix('sha256:'),f'{tag(arch)} is {image_id}, not the packaged {packaged["image_id"]}'
                manifest['images'][arch]={'tag':tag(arch),'image_id':image_id,
                    'archive':kept(arch).name,'archive_sha256':packaged['sha256'],'build_host':packaged['build_host'].get('host')}
        if 'amd64' in manifest['images']:
            manifest['image_archive_sha256']=manifest['images']['amd64']['archive_sha256'];manifest['image_id']=manifest['images']['amd64']['image_id']
    save()
    # Every harness runs the server from the image: the wrapper behaves as the server executable
    # (scripts/image_server.py), and runs the image by ID.
    server=server_fips=None
    if manifest.get('image_id'):
        image_id=manifest['image_id'].removeprefix('sha256:')
        server=image_wrapper(bundle,image_id,args.engine,run=bundle.name)
        server_fips=image_wrapper(bundle,image_id,args.engine,fips=True,run=bundle.name)
    def precondition(phase,missing):
        """With --ci a requested phase whose inputs are missing fails, rather than running no step."""
        missing=[m for m in missing if m]
        if args.ci and phase in args.phases and missing:run.check(phase,'precondition',missing)
    precondition('conformance',['' if server else 'no amd64 image (image phase)'])
    for phase in ('integration','kubernetes','java'):precondition(phase,['' if manifest.get('image_id') else 'no amd64 image (image phase)'])
    precondition('security',['' if server else 'no amd64 image (image phase)'])
    precondition('platform',['' if others() else 'no non-amd64 image (image phase with --platforms)','' if args.arm64_host else 'no --arm64-host (local on a native runner)'])
    save()
    def platform_tests(arch,phase):
        """Image tests of a non-amd64 platform on its native host (remote_image_tests.py; --arm64-host local runs them here)."""
        if not args.arm64_host:return
        remote_tests=['python3','scripts/remote_image_tests.py','--host',args.arm64_host,'--ssh',args.ssh,'--remote-dir',args.arm64_remote_dir,'--arch',arch]
        if phase=='conformance':
            # Default-mode variation replay through the image of another platform, on its native host.
            out=bundle/f'conformance-image-{arch}';out.mkdir(exist_ok=True)
            if run.step('conformance',f'image-{arch}-variations',[*remote_tests,'--tests','variations','--output',out/'remote-tests.json'],timeout=8*3600,outputs=[out/'remote-tests.json']):
                shutil.copy2(artifacts_dir(arch)/'variations.json',out/'variations.json')
                compare(arch)
        else:
            # Hardening, the FIPS image test and the scan run on the platform's native host.
            out=bundle/f'security-{arch}';out.mkdir(exist_ok=True)
            reports=[artifacts_dir(arch)/r for r in ['image-hardening/report.json','image-fips/report.json','image-vulnerabilities/summary.json']]
            if run.step('security',f'image-{arch}-remote',[*remote_tests,'--tests','hardening','fips','scan','--output',out/'remote-tests.json'],timeout=4*3600,outputs=[out/'remote-tests.json',*reports]):
                for report in reports:
                    if report.exists():shutil.copy2(report,out/f'{report.parent.name}-{report.name}')
    def compare(arch):
        out=bundle/f'conformance-image-{arch}'
        if (bundle/'conformance-image'/'variations.json').exists() and (out/'variations.json').exists():
            run.step('conformance',f'image-{arch}-vs-amd64',['python3','scripts/compare_replays.py',bundle/'conformance-image'/'variations.json',out/'variations.json','--output',out/'comparison-with-amd64.json'],outputs=[out/'comparison-with-amd64.json'])
    if 'conformance' in args.phases and server:
        out=bundle/'conformance-image';out.mkdir(exist_ok=True)
        run.step('conformance','image-variations',['python3','scripts/oasis_profile_replay.py','--binary',server,'--image',image,'--diagnose','--output',out/'variations.json'],timeout=7200,outputs=[out/'variations.json'])
        run.step('conformance','image-corrected',['python3','scripts/oasis_profile_replay.py','--binary',server,'--image',image,'--corrected-fixtures','--output',out/'corrected.json'],timeout=7200,outputs=[out/'corrected.json'])
        if not args.ci:
            for arch in others():platform_tests(arch,'conformance')
        # FIPS mode with the image's RHEL 9 FIPS provider, on an emulated FIPS host (labelled as such).
        run.step('conformance','image-variations-fips-emulated',['python3','scripts/oasis_profile_replay.py','--binary',server_fips,'--image',image,'--diagnose','--output',out/'variations-fips-emulated.json'],timeout=7200,outputs=[out/'variations-fips-emulated.json'])
        run.step('conformance','image-strict',['python3','scripts/oasis_conformance.py','--binary',server,'--image',image,'--report-only','--output',out/'strict.json'],timeout=7200,outputs=[out/'strict.json'])
        for name,cmd in EXTRA_REPLAYS:
            run.step('conformance',name,[c.replace('{binary}',str(server)).replace('{image}',image).replace('{out}',str(bundle)) for c in cmd],timeout=7200)
        if (out/'variations.json').exists() and (out/'strict.json').exists():
            # Configuration-dependent and corrected-fixture cases are reported from
            # the runs under that setting or with corrected fixtures, never as failed.
            extra=[]
            for name,report in (('3des','variations-3des.json'),('interop','variations-interop.json'),('fips','variations-fips-emulated.json')):
                if (out/report).exists():extra+=['--configured',f'{name}={out/report}']
            if (out/'corrected.json').exists():extra+=['--corrected',out/'corrected.json']
            run.step('conformance','inventory',['python3','scripts/oasis_inventory.py',out/'strict.json',out/'variations.json',*extra,'--output',bundle/'oasis-case-inventory.json'],outputs=[bundle/'oasis-case-inventory.json'])
            if 'requirement-matrix' not in run.phases['conformance']:run.skip('conformance','requirement-matrix',NOT_RUN['conformance','requirement-matrix'])
    save()
    if 'integration' in args.phases and manifest.get('image_id'):
        groups=args.integration_groups or []
        # Fixture images are rebuilt from this commit's sources, never reused by tag.
        ibm=f'localhost/keytend-kmip-server-ibm-client:{sha(ROOT/"integration/ibm/client.c")[:12]}'
        if not groups or 'ibm-client' in groups:
            run.step('integration','ibm-client-image',['python3','-c',f'import sys;sys.path.insert(0,"scripts");import test_ibm_client as t;t.build_client("{args.engine}","{ibm}")'],timeout=3600)
        if not groups or any(g.startswith('pbm') for g in groups):
            run.step('integration','pbm-fixture-image',['python3','scripts/build_pbm_fixture.py','--engine',args.engine],timeout=3600)
        options=[*(['--groups',*groups] if groups else []),*(['--workers',str(args.integration_workers)] if args.integration_workers else []),*(['--db-slots',str(args.db_slots)] if args.db_slots else [])]
        attempts=set((ROOT/'artifacts/integration-qualification').glob('attempt-*'))
        run.step('integration','matrix',['python3','scripts/test_integration_parallel.py','--image',image,'--ibm-client-image',ibm,*options],timeout=6*3600)
        # The attempt's summary and each group's record and logs (not the copied reports below them).
        for attempt in set((ROOT/'artifacts/integration-qualification').glob('attempt-*'))-attempts:
            out=bundle/'integration'/(manifest['ci']['job'] if args.ci else '');out.mkdir(parents=True,exist_ok=True)
            for path in sorted(attempt.iterdir()):
                if path.is_file() and path.suffix in {'.json','.log'}:shutil.copy2(path,out/path.name)
        if args.ci:manifest['integration_groups']=groups or sorted(integration_groups())
    save()
    if 'kubernetes' in args.phases and manifest.get('image_id'):
        if args.ci:
            run.step('kubernetes','tools',['sh','-c',f'{args.kind} version && {args.kubectl} version --client && python3 scripts/helm_tool.py fetch'],timeout=600)
        cluster=f'keytend-{short}';kubeconfig=bundle/'kind.kubeconfig'
        env={'KIND_EXPERIMENTAL_PROVIDER':args.kind_provider}
        if os.sep in args.kubectl:env['PATH']=f'{pathlib.Path(args.kubectl).parent}:{os.environ["PATH"]}'
        create=[args.kind,'create','cluster','--name',cluster,'--image',args.kind_node_image,'--kubeconfig',kubeconfig]
        # Rootless podman runs kind inside a delegated user scope.
        if args.kind_provider=='podman':create=['systemd-run','--user','--scope','-p','Delegate=yes','env','KIND_EXPERIMENTAL_PROVIDER=podman',*create]
        if run.step('kubernetes','create-cluster',create,env=env,timeout=1800):
            try:
                run.step('kubernetes','load-image',[args.kind,'load','image-archive',bundle/'image.docker.tar','--name',cluster],env=env,timeout=1800)
                pki=bundle/'kube-pki'
                run.step('kubernetes','pki',['sh','-c',f'scripts/dev-pki.sh {pki} && {server} generate-master-key --output {pki}/master.key'])
                run.step('kubernetes','deploy',['python3','scripts/test_kubernetes.py','--kubeconfig',kubeconfig,'--image',image,'--pki',pki,'--kind-node',f'{cluster}-control-plane','--engine',args.kind_provider,'--kubectl',args.kubectl],env=env,timeout=3600)
                run.step('kubernetes','storage-rotation',['python3','scripts/test_kubernetes_storage_rotation.py','--kubeconfig',kubeconfig,'--pki',pki,'--binary',server,'--kubectl',args.kubectl],env=env,timeout=3600)
                # The chart in its own namespace; the image generates keys and checkpoints as an operator would.
                run.step('kubernetes','helm-chart',['python3','scripts/test_helm_chart.py','--kubeconfig',kubeconfig,'--image',image,'--pki',pki,'--binary',server,'--kubectl',args.kubectl],
                         env=env,timeout=3600,outputs=[ROOT/'artifacts/helm-chart.json'])
            finally:
                run.step('kubernetes','delete-cluster',[args.kind,'delete','cluster','--name',cluster],env=env,timeout=900)
    save()
    # A soak only earns credit for a candidate whose earlier steps all passed.
    earlier=run.failed()
    if args.soak_duration and args.ci:
        run.skip('java','soak',NOT_RUN['java','soak'])
    elif args.soak_duration and manifest.get('image_id') and earlier:
        manifest['soak']={'started':False,'reason':'not started: earlier steps failed: '+', '.join(earlier)}
    elif args.soak_duration and manifest.get('image_id'):
        soak=bundle/'java-soak';log=bundle/'logs'/'soak.log';log.parent.mkdir(exist_ok=True)
        proc=subprocess.Popen(['python3','scripts/test_java_soak.py','--image',image,'--duration',args.soak_duration,'--output',str(soak)],cwd=ROOT,stdout=open(log,'w'),stderr=subprocess.STDOUT,start_new_session=True)
        manifest['soak']={'started':True,'pid':proc.pid,'duration':args.soak_duration,'output':str(soak.relative_to(bundle)),'log':str(log.relative_to(bundle)),'status':'running; result recorded by the soak itself'}
    save()
    if 'security' in args.phases:
        if manifest.get('image_id'):
            # Fails on any finding not reviewed in image/trivyignore.yaml (docs/container-image.md).
            run.step('security','image-scan',['python3','scripts/scan_image.py','--engine',args.engine,'--image',image],timeout=3600)
            run.step('security','image-hardening',['python3','scripts/test_image_hardening.py','--engine',args.engine,'--image',image],timeout=3600,outputs=[ROOT/'artifacts/image-hardening/report.json'])
            # Emulated FIPS host (RHEL test switch plus --fips) and a test-only probe image; not a FIPS validation.
            run.step('security','image-fips',['python3','scripts/test_image_fips.py','--engine',args.engine,'--image',image],timeout=3600,outputs=[ROOT/'artifacts/image-fips/report.json'])
            # Live TLS inventory of the image listeners, default mode and emulated FIPS mode. The client is the
            # OpenSSL 3.5 command of the pinned UBI image the image build uses.
            client=['--openssl-image',base_images('amd64')['UBI_BUILDER']]
            for mode,flags in (('default',[]),('fips-emulated',['--fips'])):
                out=bundle/f'tls-probe-image-{mode}'
                run.step('security',f'tls-probe-image-{mode}',['python3','scripts/tls_profile_probe.py','--binary',server,'--engine',args.engine,'--image',image,'--image-id',manifest['image_id'].removeprefix('sha256:'),
                    '--image-archive',bundle/'image.docker.tar','--fixtures','image-rsa,image-ecdsa','--output',out,*client,*flags],timeout=3600,outputs=[out/'summary.json'])
        if not args.ci:
            for arch in others():platform_tests(arch,'security')
        run.step('security','dependencies',['python3','scripts/scan_dependencies.py'],timeout=3600)
    save()
    if 'platform' in args.phases:
        # CI: a native runner of each other platform runs that platform's image tests.
        for arch in others():platform_tests(arch,'conformance');platform_tests(arch,'security')
    save()
    if 'java' in args.phases and manifest.get('image_id'):
        javas=[x for java in toolchain.javas() for x in ('--java',str(java))]
        run.step('java','suite',['python3','scripts/test_java_release.py','--engine',args.engine,'--image',image,*javas],timeout=4*3600,outputs=[ROOT/'artifacts/java-release-summary.json'])
        # Copied whether or not the suite passed: a failed run's reports explain it.
        java_out=bundle/'java';java_out.mkdir(exist_ok=True)
        for name in ['java-release-summary.json','java-catalog','java-release-wrapping','https-image.json','catalog-probes.json']:
            source=ROOT/'artifacts'/name
            if source.is_dir():shutil.copytree(source,java_out/name,dirs_exist_ok=True)
            elif source.is_file():shutil.copy2(source,java_out/name)
        if args.ci:run.skip('java','soak',NOT_RUN['java','soak'])
    save()
    # Checked before the release phase, so the packed manifest records it.
    if sentinel:
        calls=sentinel.calls();sentinel.remove()
        replaced=['not verified: a build replaced the stand-in during the run, so later calls were not seen'] if sentinel.replaced else []
        run.check('runtime','no-native-server',[f'a step ran the native executable: {c}' for c in calls]+replaced)
        if 'build' in manifest:manifest['build']['executed']=True if calls else None if replaced else False
        save()
    if 'release' in args.phases and args.merge:
        merge(manifest,run,args.merge)
        # Every phase ran in one of the workflow's jobs.
        ran={phase for part in manifest['ci']['parts'].values() for phase in part['phases']}
        needed=['rust','image','conformance','integration','kubernetes','security','java']+(['platform'] if len(manifest['platforms'])>1 else [])
        run.check('release','phases',[f'no job ran the {p} phase' for p in needed if p not in ran])
        for arch in [x for x in manifest['platforms'] if x!='amd64']:compare(arch)
        # Every group of the integration matrix ran in one of the workflow's slices.
        ran=[g for part in manifest['ci']['parts'].values() for g in part.get('integration_groups',[])]
        missing,twice=sorted(integration_groups()-set(ran)),sorted({g for g in ran if ran.count(g)>1})
        run.check('integration','coverage',[f'group not run: {g}' for g in missing]+[f'group run twice: {g}' for g in twice])
        save()
    precondition('release',['' if manifest['images'] else 'no images (image phase)','' if args.merge or not args.ci else 'no --merge parts'])
    if 'release' in args.phases and manifest['images']:
        built=[arch for arch in args.platforms if arch in manifest['images']]
        release=bundle/'release'
        reports=bundle/'reports'/f'keytend-kmip-server-{VERSION}-test-reports.tar.gz'
        save()
        hosts=[args.arm64_host] if args.arm64_host and args.arm64_host!='local' else []
        hosts+=[part['host'] for part in manifest.get('ci',{}).get('parts',{}).values() if part.get('host') and not part['host'].startswith('<')]
        summarize();save()
        pack_reports(run,reports,hosts)
        extra=['--extra',reports] if reports.exists() else []
        if run.step('release','assemble',['python3','scripts/release_artifacts.py','assemble','--dir',release,'--platforms',*built,*extra],timeout=3600,outputs=[release/'SHA256SUMS',release/'index/image-index.json']):
            # The release workflow signs in its own job, with its OIDC identity and the CI signing subkey.
            if not args.ci and run.step('release','sign',['python3','scripts/release_artifacts.py','sign','--dir',release],timeout=3600):
                # Every requested platform must be in the verified set; a missing one fails here.
                run.step('release','verify',['python3','scripts/release_artifacts.py','verify','--dir',release,'--require-platforms',*args.platforms],timeout=3600,outputs=[release/'verification.json'])
        if (release/'index/image-index.json').exists():manifest['image_index']=json.loads((release/'index/image-index.json').read_text())['index_digest']
    failed=summarize()
    save();print(json.dumps({'bundle':str(bundle),'failed_steps':failed,'not_run':manifest['not_run']},indent=1))
    if failed:raise SystemExit(1)

def write_manifest(bundle,manifest):
    """Write manifest.json whole: a temporary file renamed over it, so a kill cannot truncate it."""
    temporary=bundle/'.manifest.json.partial'
    temporary.write_text(json.dumps(manifest,indent=1)+'\n');temporary.replace(bundle/'manifest.json')

def pack_reports(run,reports,hosts):
    """The reports archive (release_reports.py). The step is not saved as running first: the
    archive packs manifest.json, which must not show its own packing as unfinished."""
    return run.step('release','reports',['python3','scripts/release_reports.py','--bundle',run.bundle,'--output',reports,*[x for h in sorted(set(hosts)) for x in ('--host',h)]],
                    timeout=3600,outputs=[reports],mark_running=False)

class NativeSentinel:
    """Put a stand-in for the native executable at `path` that logs each call to `log` and exits 99.

    The executable is hard-coded as the default of the harnesses that can run one natively, so the
    stand-in must take that path; a different target directory or PATH would not catch those calls.
    A built executable is renamed aside (the directory entry moves, so cargo's hard link in deps/
    is untouched) and the stand-in is a new file, never written through an existing file or link.
    remove() puts the build back, unless a newer build replaced the stand-in during the run. An aside
    copy a killed run left behind is resolved first, in the same way."""
    MARK=b'#!/bin/sh\n# release_candidate.py: every test runs the image'
    def __init__(self,path,log):
        self.path,self.log=pathlib.Path(path),pathlib.Path(log);self.aside=self.path.with_name(self.path.name+'.release-run-aside')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.resolve()
        if self.is_stub():self.path.unlink()
        elif self.path.exists() or self.path.is_symlink():os.replace(self.path,self.aside)
        with open(self.path,'xb') as stub:
            stub.write(self.MARK+f"""; a call to the native executable is a defect.
echo "$0 $*" >> {shlex.quote(str(self.log))}
exit 99
""".encode())
        self.path.chmod(0o755);self.installed=True;self.replaced=False
    def is_stub(self):
        return self.path.is_file() and not self.path.is_symlink() and self.path.read_bytes().startswith(self.MARK)
    def resolve(self):
        """An aside copy goes back when the path is missing or is the stand-in; a build at the path is newer."""
        if not (self.aside.exists() or self.aside.is_symlink()):return
        if self.is_stub():self.path.unlink()
        if self.path.exists() or self.path.is_symlink():self.aside.unlink()
        else:os.replace(self.aside,self.path)
    def guard(self,cleanup=lambda:None):
        """Remove the stand-in at exit, and on SIGTERM or SIGHUP (which atexit misses) also run cleanup,
        then exit. An ignored SIGHUP (nohup) stays ignored."""
        atexit.register(self.remove)
        def stopped(signum,frame):
            self.remove();cleanup();raise SystemExit(128+signum)
        for signum in (signal.SIGTERM,signal.SIGHUP):
            if signal.getsignal(signum) is not signal.SIG_IGN:signal.signal(signum,stopped)
        return self
    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []
    def remove(self):
        # A build at the path while the stand-in should be there means cargo replaced it during the run:
        # calls after that were not seen.
        if self.installed and not self.is_stub():self.replaced=True
        if self.is_stub():self.path.unlink()
        self.resolve();self.installed=False

def integration_groups():
    """Every group of the integration matrix (scripts/test_integration_parallel.py)."""
    import test_integration_parallel
    return set(test_integration_parallel.jobs_for('image','ibm-client',ROOT))

def merge(manifest,run,parts):
    """Merge the partial bundles of the workflow's other jobs (release_reports.py --part archives, or
    their directories) into this one. Each job's logs go under logs/<job>/, and a file another job also
    wrote with other content under <directory>/<job>/; a step name more than one job used gets the job appended."""
    import tarfile,tempfile
    with tempfile.TemporaryDirectory(prefix='release-parts-') as scratch:
        directories=[]
        for i,part in enumerate(parts):
            if part.is_file():
                directory=pathlib.Path(scratch)/str(i);directory.mkdir()
                with tarfile.open(part) as tar:tar.extractall(directory,filter='data')
                part=directory
            directories.append(part)
        merge_directories(manifest,run,directories)

def merge_directories(manifest,run,parts):
    bundle=run.bundle;loaded=[]
    for part in parts:
        record=json.loads((part/'manifest.json').read_text());loaded.append((part,record,record['ci']['job']))
    jobs={}
    for _,record,job in loaded:
        for phase,steps in record['phases'].items():
            for name in steps:jobs.setdefault((phase,name),[]).append(job)
    manifest['ci']['parts']={}
    for part,record,job in loaded:
        moved={}
        for path in sorted(p for p in part.rglob('*') if p.is_file() and p!=part/'manifest.json'):
            rel=path.relative_to(part);target=rel
            if rel.parts[0]=='logs' or (bundle/rel).exists() and (bundle/rel).read_bytes()!=path.read_bytes():
                target=pathlib.Path(rel.parts[0],job,*rel.parts[1:]) if len(rel.parts)>1 else pathlib.Path(f'{job}-{rel}')
            (bundle/target).parent.mkdir(parents=True,exist_ok=True)
            if not (bundle/target).exists():shutil.copy2(path,bundle/target)
            moved[rel.as_posix()]=target.as_posix()
        for phase,steps in record['phases'].items():
            for name,step in steps.items():
                key=name if len(jobs[phase,name])==1 and name not in run.phases.get(phase,{}) else f'{name} ({job})'
                step=dict(step,job=job)
                if 'log' in step:step['log']=moved.get(step['log'],step['log'])
                if 'outputs' in step:step['outputs']={moved.get(k,k):v for k,v in step['outputs'].items()}
                run.phases.setdefault(phase,{})[key]=step
        # A job that was killed or timed out has no finish time; its steps may be missing.
        if not record.get('finished_at'):run.check('release',f'finished-{job}',[f'{job} did not finish: its record ends at the last step it saved'])
        # Every job tested the images this job assembles.
        for arch,entry in record.get('images',{}).items():
            assembled=manifest['images'].setdefault(arch,entry)
            differ=[f'{job} tested {arch} {entry.get(k)} as {k}, not {assembled.get(k)}' for k in ('image_id','archive_sha256') if entry.get(k)!=assembled.get(k)]
            if differ:run.check('release',f'image-{arch}-{job}',differ)
        for key in ('image_id','image_archive_sha256'):
            if key in record:
                manifest.setdefault(key,record[key])
                if record[key]!=manifest[key]:run.check('release',f'{key}-{job}',[f'{job} has {key} {record[key]}, not {manifest[key]}'])
        manifest['started_at']=min(manifest['started_at'],record['started_at'])
        manifest['platforms']=sorted(set(manifest['platforms'])|set(record['platforms']),key=lambda x:(x!='amd64',x))
        manifest['dirty']=manifest['dirty'] or record['dirty']
        if record['commit']!=manifest['commit']:run.check('release',f'commit-{job}',[f'{job} ran {record["commit"]}, not {manifest["commit"]}'])
        manifest['ci']['parts'][job]={**{k:v for k,v in record['ci'].items() if k not in ('job','run')},'phases':record['ci'].get('phases',[]),'tools':record.get('tools'),'started_at':record['started_at'],
            'finished_at':record.get('finished_at'),**({'integration_groups':record['integration_groups']} if 'integration_groups' in record else {})}


# Additional separately labelled replays (legacy 1.1/1.2 notes, HTTPS JSON/XML
# transports). Placeholders {binary} and {out} are substituted.
EXTRA_REPLAYS=[
    # The Symmetric Key Foundry profiles need 3DES; this run uses that setting.
    ('image-variations-3des',['env','KMIP_TRIPLE_DES=enabled','python3','scripts/oasis_profile_replay.py','--binary','{binary}','--image','{image}','--output','{out}/conformance-image/variations-3des.json']),
    # Interop exists only in test mode; the Query traces that list it use that setting.
    ('image-variations-interop',['env','KMIP_INTEROP_TEST_MODE=true','python3','scripts/oasis_profile_replay.py','--binary','{binary}','--image','{image}','--output','{out}/conformance-image/variations-interop.json']),
    ('image-https-transports',['python3','scripts/oasis_https_replay.py','--binary','{binary}','--image','{image}','--output','{out}/conformance-image/https.json']),
    # Legacy 1.1/1.2 notes: default run plus every recorded configuration and corrected-document
    # run, with reported statuses; fails if any case changed status or is untriaged.
    ('image-legacy-notes',['python3','scripts/oasis_legacy_inventory.py','--rerun','{binary}','--image','{image}','--outdir','{out}/conformance-image/legacy']),
    ('legacy-ledger-tests',['python3','scripts/test_oasis_legacy_replay.py']),
    ('corpus-proofs',['python3','scripts/oasis_corpus_proofs.py','--output','{out}/oasis-corpus-proofs.json']),
]
if __name__=='__main__':main()
