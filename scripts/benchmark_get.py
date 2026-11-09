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

"""Bounded Get-only development measurements; no production capacity or SLO claim."""
import argparse,concurrent.futures,datetime,hashlib,json,math,os,pathlib,shutil,socket,ssl,statistics,subprocess,tempfile,threading,time,collections,random,uuid
from network_fixture import NetworkServer,metrics
import test_database
from image_evidence import ROOT,source_commit,local_image_id,packaged_evidence
from wire import create_key,key_value


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',help='tested image; required for container measurements only')
    p.add_argument('--binary',type=pathlib.Path,default=ROOT/'target/debug/keytend-kmip-server',help='owned native binary (also fingerprinted)')
    p.add_argument('--native',action='store_true',help='direct native TCP control; no image execution credit')
    p.add_argument('--seconds',type=float,default=10)
    p.add_argument('--concurrency',type=int,nargs='+',default=[1,4,16,64])
    p.add_argument('--host-network',action='store_true',help='container loopback listener without rootless published-port forwarding')
    p.add_argument('--max-connections',type=int,default=64)
    p.add_argument('--mode',choices=['persistent','fresh-tls','reused-tls'],nargs='+',default=['persistent','fresh-tls'])
    p.add_argument('--diagnostic-connections',action='store_true')
    p.add_argument('--forwarding-forensics',type=pathlib.Path,metavar='STRACE',help='capture owned pasta metadata and socket-only syscalls using this strace binary')
    p.add_argument('--diagnostic-pasta-no-splice',action='store_true',help='forensic treatment only: disable pasta local socket splicing for this owned fixture')
    p.add_argument('--client-timeout',type=float,default=5,help='TCP/TLS/request socket deadline in seconds; failures remain counted')
    p.add_argument('--error-backoff-ms',type=float,default=0,help='bounded exponential backoff with jitter after errors; errors remain failures')
    p.add_argument('--requests-per-connection',type=int,default=16,help='Get count before reconnect in reused-tls mode')
    p.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/get-benchmark')
    a=p.parse_args()
    if not 1<=a.seconds<=60 or any(not 1<=n<=128 for n in a.concurrency):p.error('seconds must be 1..60 and concurrency 1..128')
    if a.native and a.host_network:p.error('native and host-network are mutually exclusive')
    if a.forwarding_forensics and (a.native or a.host_network):p.error('forwarding forensics requires published container ports')
    if a.diagnostic_pasta_no_splice and not a.forwarding_forensics:p.error('no-splice is a diagnostic treatment requiring forwarding forensics')
    if not a.native and not a.image:p.error('--image is required for containers')
    if not 0<=a.error_backoff_ms<=1000 or not 1<=a.requests_per_connection<=1024:p.error('backoff must be 0..1000ms and reuse count 1..1024')
    if not .05<=a.client_timeout<=30:p.error('client-timeout must be .05..30 seconds')
    if not 1<=a.max_connections<=1024:p.error('max-connections must be 1..1024')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    test_database.ART=out # Keep benchmark container logs separate from published DB evidence.
    binary=a.binary.resolve()
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    binary_hash=sha(binary)
    evidence={'image_execution_credit':False,'source_commit':source_commit()[0]}if a.native else packaged_evidence(local_image_id('podman',a.image))
    report=dict(status='running',started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),runtime_binary_sha256=binary_hash,**evidence,transport_fixture='direct-native'if a.native else'container-host-network'if a.host_network else'rootless-podman-port-forward',configured_max_connections=a.max_connections,error_backoff_ms=a.error_backoff_ms,client_timeout_seconds=a.client_timeout,requests_per_connection=a.requests_per_connection,phases=[],limits=['Development Get-only closed-loop workload; no mixed-operation, database, HA, saturation or sustained-capacity qualification.','One Python client process; client CPU/GIL, TLS, TTLV parsing and local port forwarding can limit throughput.','Server fixture: two CPU quota, 256MiB memory,128 pids; not all host cores.','Older 24h soak workloads may run concurrently; background load is recorded, not controlled. No production latency/RPS targets supplied.','Fresh TLS authenticates each request; reused-tls reconnects after the configured Get count; persistent keeps its socket. Each measured attempt includes any TCP/TLS setup it needs. Closed-loop clients do not model a fixed arrival rate.','Diagnostic TCP polling and debug logs add overhead when selected; latency includes successful attempts only and excludes failed attempts and backoff. Every failed attempt remains an error even if a later attempt succeeds.','No latency/RPS pass threshold. Zero observed errors in a bounded run is not a reliability guarantee.'])
    if a.native:report['limits'][2]='Direct native control has no container CPU/memory quota and gives no image execution credit.'
    path=out/'summary.json'
    def save():path.write_text(json.dumps(report,indent=2)+'\n')
    save()
    report['diagnostic_pasta_no_splice']=a.diagnostic_pasta_no_splice
    try:
        report['host']={'logical_cpus':os.cpu_count(),'load_before':list(os.getloadavg())}
        report['concurrent_soaks']=subprocess.check_output(['systemctl','--user','list-units','--type=service','--state=running','--plain','--no-legend','keytend-java-soak-*'],text=True).splitlines()
        with tempfile.TemporaryDirectory(prefix='keytend-get-benchmark-')as directory:
            class BenchmarkServer(test_database.ContainerServer):
                def __init__(self,directory,engine,image):
                    test_database.Server.__init__(self,directory,binary=binary)
                    self.max_connections=a.max_connections
                    self.log_path=out/'database-kmip.log'
                    self.engine=engine;self.image=image;self.name='keytend-get-'+uuid.uuid4().hex[:12]
                    self.tls=self.root/'server-tls';self.tls.mkdir(mode=0o700)
                    for name in ['server.pem','server.key','ca.pem','master.key','policy.json']:shutil.copy(self.pki/name,self.tls/name)
                def base(self):
                    args=super().base()
                    if a.host_network:args+=['--network','host']
                    if a.diagnostic_pasta_no_splice:args+=['--network','pasta:--no-splice']
                    return args+['-e','RUST_LOG=keytend_kmip_server=debug']if a.diagnostic_connections else args
                def start(self):
                    args=self.base()+['-d','--name',self.name]
                    if not a.host_network:args+=['-p',f'127.0.0.1:{self.port}:5696','-p',f'127.0.0.1:{self.health}:8080']
                    args+=[self.image,'serve','--listen',f'127.0.0.1:{self.port}'if a.host_network else'0.0.0.0:5696','--health-listen',f'127.0.0.1:{self.health}'if a.host_network else'0.0.0.0:8080','--max-connections',str(a.max_connections),'--cert','/tls/server.pem','--key','/tls/server.key','--ca','/tls/ca.pem','--master-key','/tls/master.key','--policy','/tls/policy.json']
                    test_database.command(args)
                    until=time.monotonic()+20
                    while time.monotonic()<until:
                        try:
                            with socket.create_connection(('127.0.0.1',self.health),timeout=.3)as c:
                                c.sendall(b'GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n');assert c.recv(128).startswith(b'HTTP/1.1 200')
                            with socket.create_connection(('127.0.0.1',self.port),timeout=.3):pass
                            return
                        except (OSError,AssertionError):time.sleep(.1)
                    raise RuntimeError('benchmark server not ready')
            server=NetworkServer(directory,binary,max_connections=a.max_connections)if a.native else BenchmarkServer(directory,'podman',a.image)
            if not a.native:report['owned_container']=server.name;save()
            if a.diagnostic_connections:os.environ['RUST_LOG']='keytend_kmip_server=debug'
            capture=None
            try:
                server.start()
                inspected={}if a.native else json.loads(subprocess.check_output(['podman','inspect',server.name]))[0]
                if a.forwarding_forensics:
                    from forwarding_forensics import ForwardingCapture
                    capture=ForwardingCapture(out,server,inspected,a.forwarding_forensics)
                    capture.start()
                report['container_resources']={k:inspected.get('HostConfig',{}).get(k)for k in ['Memory','CpuQuota','CpuPeriod','NanoCpus','PidsLimit']}
                report['diagnostic_connections']=a.diagnostic_connections
                with server.connect()as c:identifier=create_key(c,(2,1));expected=key_value(c,identifier,(2,1))
                assert len(expected)==32
                ctx=ssl.create_default_context(cafile=str(server.pki/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(server.pki/'client.pem',server.pki/'client.key')
                class ConnectFailure(Exception):
                    def __init__(self,stage,error):self.stage=stage;self.error=error
                def connect():
                    try:raw=socket.create_connection(('127.0.0.1',server.port),timeout=a.client_timeout)
                    except OSError as error:
                        if capture:capture.client(None,('127.0.0.1',server.port),'tcp_connect',error)
                        raise ConnectFailure('tcp_connect',error)from error
                    local=raw.getsockname();peer=raw.getpeername()
                    try:
                        connection=ctx.wrap_socket(raw,server_hostname='localhost')
                        if capture:capture.client(local,peer,'tls_succeeded')
                        return connection
                    except Exception as error:
                        if capture:capture.client(local,peer,'tls_handshake',error)
                        raw.close();raise ConnectFailure('tls_handshake',error)from error
                def counters():
                    try:return metrics(server)
                    except Exception as error:return {'unavailable':repr(error)}
                report['host']['ephemeral_port_range']=pathlib.Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().strip()
                report['host']['tcp_tw_reuse']=pathlib.Path('/proc/sys/net/ipv4/tcp_tw_reuse').read_text().strip()
                for mode in a.mode:
                    for concurrency in a.concurrency:
                        before=counters();state={}
                        def start():state['start']=time.perf_counter();state['end']=state['start']+a.seconds
                        barrier=threading.Barrier(concurrency,action=start)
                        def worker():
                            samples=[];errors=collections.Counter();examples={};connection=None;protocols=set();connection_errors=0;opened=0;used=0;failures=0
                            rng=random.Random()
                            try:
                                barrier.wait(timeout=30)
                                while time.perf_counter()<state['end']:
                                    began=time.perf_counter()
                                    try:
                                        if connection is None:
                                            connection=connect();opened+=1;used=0;protocols.add(connection.version())
                                        actual=key_value(connection,identifier,(2,1))
                                        if actual!=expected:raise AssertionError('exact key mismatch')
                                        samples.append((time.perf_counter()-began)*1000);used+=1;failures=0
                                    except Exception as error:
                                        stage=error.stage if isinstance(error,ConnectFailure)else'get'
                                        original=error.error if isinstance(error,ConnectFailure)else error
                                        key=(stage,type(original).__name__,getattr(original,'errno',None));errors[key]+=1
                                        if len(examples)<8:examples[key]=str(original)[:240]
                                        if stage!='get':connection_errors+=1
                                        if connection is not None:connection.close();connection=None
                                        failures+=1
                                        if a.error_backoff_ms:
                                            delay=min(1,a.error_backoff_ms/1000*2**min(failures-1,8))
                                            time.sleep(min(max(0,state['end']-time.perf_counter()),rng.uniform(delay/2,delay)))
                                        elif mode=='persistent':break
                                    finally:
                                        if connection is not None and (mode=='fresh-tls'or mode=='reused-tls'and used>=a.requests_per_connection):
                                            connection.close();connection=None
                            except Exception as error:
                                key=('worker',type(error).__name__,getattr(error,'errno',None));errors[key]+=1;examples[key]=str(error)[:240]
                            finally:
                                if connection is not None:connection.close()
                            return samples,errors,protocols,connection_errors,examples,opened
                        connection_samples=[]
                        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)as pool:
                            futures=[pool.submit(worker)for _ in range(concurrency)]
                            last_sample=0
                            while a.diagnostic_connections and not all(f.done()for f in futures):
                                if state and time.perf_counter()-last_sample>=1:
                                    last_sample=time.perf_counter();sample={'elapsed_seconds':last_sample-state['start'],'server_counters':counters()}
                                    command=['cat','/proc/net/tcp','/proc/net/tcp6']if a.native else['sh','-c',f'p=$(podman inspect -f {{{{.State.Pid}}}} {server.name}) && cat /proc/$p/net/tcp /proc/$p/net/tcp6']
                                    result=subprocess.run(command,text=True,capture_output=True,timeout=5)
                                    sample['inspection_exit_code']=result.returncode
                                    sample['inspection_error']=result.stderr[:240]if result.returncode else None
                                    rows=[line.split()for line in result.stdout.splitlines()if len(line.split())>=4 and ':'in line.split()[0]]
                                    counts={}
                                    for row in rows:
                                        port=row[1].rsplit(':',1)[-1]
                                        if port==format(server.port if a.native or a.host_network else 5696,'04X'):counts[row[3]]=counts.get(row[3],0)+1
                                    sample['server_tcp_states_hex']=counts
                                    result=subprocess.run(['ss','-tanH','state','time-wait'],text=True,capture_output=True,timeout=5)
                                    sample['host_time_wait_sockets']=len(result.stdout.splitlines())if result.returncode==0 else None
                                    sample['ss_exit_code']=result.returncode
                                    host_counts={}
                                    for table in ['/proc/net/tcp','/proc/net/tcp6']:
                                        for line in pathlib.Path(table).read_text().splitlines()[1:]:
                                            row=line.split()
                                            if int(row[2].rsplit(':',1)[-1],16)==server.port:host_counts[row[3]]=host_counts.get(row[3],0)+1
                                    sample['host_tcp_states_to_fixture_port_hex']=host_counts
                                    connection_samples.append(sample)
                                time.sleep(.2)
                            results=[f.result()for f in futures]
                        elapsed=time.perf_counter()-state.get('start',time.perf_counter())
                        samples=sorted(v for r in results for v in r[0]);errors=sum((r[1]for r in results),collections.Counter())
                        until=time.monotonic()+2;stable_since=time.monotonic()
                        after=counters()
                        while time.monotonic()<until:
                            time.sleep(.02);current=counters()
                            if current.get('active')!=0 or current.get('tcp_accepted_total')!=after.get('tcp_accepted_total'):stable_since=time.monotonic()
                            after=current
                            if time.monotonic()-stable_since>=.1:break
                        phase_counters={'available':'tcp_accepted_total'in before and 'tcp_accepted_total'in after,'quiescent_after':after.get('active')==0,'before':before,'after':after,'delta':{k:after[k]-before[k]for k in before if k.endswith('_total')and isinstance(before[k],int)and isinstance(after.get(k),int)}}
                        def percentile(q):return samples[min(len(samples)-1,max(0,math.ceil(len(samples)*q)-1))]if samples else None
                        phase=dict(connection_mode=mode,concurrency=concurrency,requested_seconds=a.seconds,observed_seconds=elapsed,successful_gets=len(samples),observed_successful_rps=len(samples)/elapsed if elapsed>0 else 0,error_count=sum(errors.values()),error_types=sorted({k[1]for k in errors}),error_details=[dict(stage=k[0],type=k[1],errno=k[2],count=n,example=next((r[4][k]for r in results if k in r[4]),None))for k,n in sorted(errors.items(),key=lambda item:str(item[0]))],client_tls_setups=sum(r[5]for r in results),server_counters=phase_counters,connection_setup_errors=sum(r[3]for r in results),tls_versions=sorted({v for r in results for v in r[2]}),latency_ms=dict(mean=statistics.fmean(samples)if samples else None,p50=percentile(.5),p95=percentile(.95),p99=percentile(.99),maximum=samples[-1]if samples else None))
                        phase['connection_samples']=connection_samples
                        report['phases'].append(phase);save();print(mode,concurrency,'responses',len(samples),'errors',sum(errors.values()),flush=True)
            finally:
                try:
                    if capture:capture.stop()
                finally:
                    server.stop()
                    if not a.native:
                        report['owned_container_removed']=not server.container_exists();save()
                        assert report['owned_container_removed'],'Owned benchmark container was not removed'
                        if capture:capture.after_cleanup()
                    if a.native and (server.root/'server.log').exists():shutil.copyfile(server.root/'server.log',out/'native-server.log')
        report['host']['load_after']=list(os.getloadavg())
        report['status']='completed_with_errors'if any(p['error_count']or not p['successful_gets']for p in report['phases'])else'completed_measurements_only'
        if any(not p['server_counters']['available']for p in report['phases']):report['status']='missing_server_counters'
    except BaseException as error:report['status']='failed';report['error_type']=type(error).__name__;raise
    finally:report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    if report['status']!='completed_measurements_only':raise SystemExit(1)


if __name__=='__main__':main()
