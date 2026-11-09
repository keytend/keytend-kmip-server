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

"""Generate public DSA/ECC certificate fixtures in an isolated disposable GnuPG home."""
import hashlib,json,pathlib,subprocess,tempfile
from check_license import HEADER
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    fixtures={};version=subprocess.check_output(['gpg','--version'],text=True).splitlines()[0]
    for name,algorithm,digest,bits,signature in [('dsa2048','dsa2048','SHA256',2048,11),('p256','nistp256','SHA256',256,14),('p384','nistp384','SHA384',384,15),('p521','nistp521','SHA512',521,16)]:
        with tempfile.TemporaryDirectory(prefix='keytend-pgp-public-') as directory:
            home=pathlib.Path(directory);home.chmod(0o700)
            command=['gpg','--batch','--homedir',str(home),'--pinentry-mode','loopback','--passphrase','','--cert-digest-algo',digest]
            def run(args,**kwargs):
                try:return subprocess.check_output(command+args,stderr=subprocess.PIPE,**kwargs)
                except subprocess.CalledProcessError as error:raise RuntimeError(error.stderr.decode() if isinstance(error.stderr,bytes) else error.stderr) from error
            try:
                run(['--quick-generate-key','Keytend '+name+' <fixture@keytend-kmip-server.invalid>',algorithm,'cert,sign','0'])
                rows=run(['--with-colons','--list-secret-keys'],text=True).splitlines();fingerprint=next(row.split(':')[9] for row in rows if row.startswith('fpr:'))
                if name!='dsa2048':run(['--quick-add-key',fingerprint,algorithm,'encr','0'])
                public=run(['--armor','--export',fingerprint])
                inspected=subprocess.check_output(['gpg','--batch','--no-autostart','--homedir',str(home),'--with-colons','--import-options','show-only','--dry-run','--import'],input=public,stderr=subprocess.PIPE).decode()
                assert fingerprint in inspected
                checked=run(['--with-colons','--check-sigs',fingerprint],text=True).splitlines()
                verified=sum(row.startswith('sig:!:') for row in checked);assert verified>=1
                fixtures[name]={'armored':public.decode(),'fingerprint':fingerprint,'sha256':hashlib.sha256(public).hexdigest(),'algorithm':5 if name=='dsa2048' else 6,'bits':bits,'signature_algorithms':[signature],'generator_verified_signatures':verified}
            finally:subprocess.run(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    result={'generator':version,'purpose':'Public transferable-key fixtures, never secret exports; EC fixtures include an ECDH subkey. No v3 key generation.','fixtures':fixtures}
    path=ROOT/'tests/fixtures/pgp-certificates.json';path.write_text(json.dumps(result,indent=2)+'\n');path.with_suffix('.json.license').write_text(HEADER)
    print('Generated',len(fixtures),'public fixtures with',version)
if __name__=='__main__':main()
