#!/usr/bin/env bash
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

# Disposable certificates for tests only. Never use this CA in production.
set -euo pipefail
umask 077
out=${1:-.cache/pki}
mkdir -p "$out"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/ca.key" -out "$out/ca.pem" -days 7 -subj /CN=keytend-kmip-server-test-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign > /dev/null 2>&1
for name in server client other unlisted; do
  openssl req -new -newkey rsa:2048 -nodes -keyout "$out/$name.key" -out "$out/$name.csr" -subj "/CN=$name" > /dev/null 2>&1
  if [ "$name" = server ]; then
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,DNS:keytend-kmip-server\n' > "$out/$name.ext"
  else
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$out/$name.ext"
  fi
  openssl x509 -req -in "$out/$name.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" -CAcreateserial -out "$out/$name.pem" -days 7 -extfile "$out/$name.ext" > /dev/null 2>&1
done
python3 - "$out" <<'PY'
import hashlib,json,os,pathlib,ssl,sys
p=pathlib.Path(sys.argv[1])
principals={hashlib.sha256(ssl.PEM_cert_to_DER_cert((p/f'{n}.pem').read_text())).hexdigest():{'name':principal,'operations':list(range(1,67)) if n=='client' else [8,10,11,12,24,30]} for n,principal in [('client','database'),('other','other-tenant')]}
# The KMIP 3.0 profile traces authenticate as administrator/password (Profiles
# 3.0 section 4: a test case may assume a matching server configuration).
# users.json holds only a salted PBKDF2-HMAC-SHA-256 verifier for this
# test-only user, the form `keytend-kmip-server password-verifier` prints
# (docs/fips.md).
salt=os.urandom(16)
admin={'username':'administrator','administrator':True,'password_verifier':{'algorithm':'PBKDF2-HMAC-SHA-256','iterations':600000,'salt':salt.hex(),'hash':hashlib.pbkdf2_hmac('sha256',b'password',salt,600000).hex()}}
(p/'users.json').write_text(json.dumps({'users':{f:[admin] for f,principal in principals.items() if principal['name']=='database'}},indent=2)+'\n')
(p/'policy.json').write_text(json.dumps({'principals':principals},indent=2)+'\n')
PY
