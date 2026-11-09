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

"""Released Java certificate metadata with independent JCA parsing and durable recovery."""
import argparse, datetime, json, os, pathlib, shutil, subprocess, tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha


def fixtures(directory):
    key=ec.generate_private_key(ec.SECP256R1());at=datetime.datetime.now(datetime.timezone.utc)
    pairs=[(NameOID.COMMON_NAME,' #é,plus+slash\\ '),(NameOID.ORGANIZATION_NAME,'org'),(NameOID.ORGANIZATIONAL_UNIT_NAME,'first'),(NameOID.ORGANIZATIONAL_UNIT_NAME,'second'),(NameOID.EMAIL_ADDRESS,'test@example.org'),(NameOID.COUNTRY_NAME,'US'),(NameOID.STATE_OR_PROVINCE_NAME,'state'),(NameOID.LOCALITY_NAME,'town'),(NameOID.USER_ID,'uid'),(NameOID.SERIAL_NUMBER,'subject-serial'),(NameOID.TITLE,'title'),(NameOID.DOMAIN_COMPONENT,'example'),(NameOID.DN_QUALIFIER,'qualifier')]
    rich=x509.Name([x509.NameAttribute(oid,value) for oid,value in pairs])
    grouped=x509.Name([x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME,'a'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'b')]),x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME,'second')])])
    names=[x509.DNSName('a.example'),x509.RFC822Name('test@example.org'),x509.UniformResourceIdentifier('https://example.org/a'),x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1')),x509.DirectoryName(grouped),x509.RegisteredID(x509.ObjectIdentifier('1.2.3.4'))]
    result={}
    for name,subject in [('rich',rich),('grouped',grouped),('empty',x509.Name([]))]:
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(rich).public_key(key.public_key()).serial_number((1<<158)+123).not_valid_before(at-datetime.timedelta(days=1)).not_valid_after(at+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName(names),critical=True).add_extension(x509.IssuerAlternativeName(names),critical=False).sign(key,hashes.SHA256()))
        path=directory/(name+'.der');path.write_bytes(cert.public_bytes(serialization.Encoding.DER));result[path.name]=sha(path)
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');parser.add_argument('--java',action='append',required=True);a=parser.parse_args()
    _,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    config=local_image_id(a.engine,a.image) if a.image else None
    evidence=packaged_evidence(config) if config else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    mode='image' if config else 'native';out=ROOT/'artifacts/certificate-identity';out.mkdir(parents=True,exist_ok=True)
    classes=pathlib.Path(tempfile.mkdtemp(prefix='java-certificate-identity-'+mode+'-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerCertificateIdentity.java')],check=True)
    compiled={str(p.relative_to(ROOT)):sha(p) for p in classes.rglob('*.class')};logs=[];lanes=[]
    (out/(mode+'.json')).write_text(json.dumps({'status':'running'})+'\n')
    with tempfile.TemporaryDirectory(prefix='keytend-certificate-') as directory:
        fixture_dir=pathlib.Path(directory)/'fixtures';fixture_dir.mkdir(mode=0o700);fixtures(fixture_dir)
        retained=out/(mode+'-fixtures');retained.mkdir(exist_ok=True)
        fixture_hashes={}
        for path in fixture_dir.glob('*.der'):
            saved=retained/path.name;shutil.copyfile(path,saved);fixture_hashes[str(saved.relative_to(ROOT))]=sha(saved)
        server=HttpsContainer(directory,a.engine,a.image) if config else HttpsServer(directory)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        manifests=[pathlib.Path(directory)/('jdk'+str(i)+'.tsv') for i in range(len(a.java))]
        try:
            server.start()
            for phase in ['create','restart','restore']:
                if phase!='create':
                    server.stop()
                    if phase=='restore':
                        clean=pathlib.Path(directory)/'clean';clean.mkdir(mode=0o700);shutil.copyfile(backup,clean/'kmip.sqlite');(clean/'kmip.sqlite').chmod(0o600);server.data=clean
                    server.start()
                for index,(java,manifest) in enumerate(zip(a.java,manifests)):
                    log=out/(mode+'-jdk'+str(index)+'-'+phase+'.log');logs.append(log)
                    with log.open('w') as stream:
                        subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerCertificateIdentity',str(server.pki),str(server.port),str(server.https),'create' if phase=='create' else 'verify',str(manifest),str(fixture_dir)],check=True,stdout=stream,stderr=subprocess.STDOUT,timeout=180)
                    assert len(log.read_text().splitlines())==24
                    lanes.append({'phase':phase,'jdk':subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'cases':72})
                if phase=='create':
                    if config:
                        subprocess.run(ContainerServer.base(server)+[a.image,'backup','--database','/data/kmip.sqlite','--master-key','/tls/master.key','--output','/data/backup.sqlite'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);backup=server.data/'backup.sqlite'
                    else:
                        backup=pathlib.Path(directory)/'backup.sqlite';subprocess.run([str(binary),'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    backup_hash=sha(backup)
        finally:
            server.stop()
            if (pathlib.Path(directory)/'server.log').exists():
                log=out/(mode+'-server.log');shutil.copyfile(pathlib.Path(directory)/'server.log',log);logs.append(log)
    report=dict(status='passed',scope='X.509 identity attributes through the unchanged Java release on six final editions, TLS and HTTPS TTLV/JSON/XML, three JDKs. JCA checks complete serial DER, exact distinguished names, all retained GeneralNames and repeated CN/OU values. Rich, multi-valued RDN and empty subject fixtures; 1.4+ Import, restart and clean backup restore. No draft Java, cryptographic trust or full certificate-family credit.',client_artifact=artifact,**evidence,compiled_adapter_sha256=compiled,lanes=lanes,java_cases_per_phase=72*len(a.java),negative_register_observations=72*len(a.java),fixture_sha256=fixture_hashes,encrypted_backup_sha256=backup_hash,log_sha256={str(p.relative_to(ROOT)):sha(p) for p in logs})
    (out/(mode+'.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS certificate metadata',mode,report['java_cases_per_phase'],'released Java cases per phase; restart and clean backup restore')

if __name__=='__main__':main()
