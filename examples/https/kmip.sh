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

# Shell helpers for the HTTPS JSON and XML examples (docs/clients/https.md).
# Source this file from bash or zsh, from any directory:
#
#   . path/to/checkout/examples/https/kmip.sh
#
#   kmip REQUEST [NAME=VALUE ...]  POST a request file to the server and print the
#                                  response. $NAME in the file is replaced by VALUE.
#                                  A file name without a directory that is not in
#                                  the current directory is taken from this one.
#                                  Fails, printing nothing on standard output, when
#                                  the exchange fails or the HTTP status is not
#                                  200; a refused KMIP operation is still HTTP 200,
#                                  so check its ResultStatus.
#   field TAG                      print the first value of TAG in a JSON response
#                                  read from standard input ("None" if absent); the
#                                  value of a structure is printed as a JSON list
#   pretty                         indent a JSON or XML response read from standard
#                                  input, one element per line
#   hex TEXT, unhex                text to hex, and hex on standard input to text
#
# Settings, read on every call:
#   KMIP_PKI     test certificates (default: .cache/dev-pki in this checkout)
#   KMIP_CLIENT  client certificate name in KMIP_PKI (default: client)
#   KMIP_URL     endpoint (default: https://localhost:5697/kmip)
#
# Each request may take 10 seconds to connect (TCP and TLS) and 30 seconds in all.
#
# Needs curl and Python 3.

KMIP_EXAMPLES=$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)
export KMIP_PKI="${KMIP_PKI:-$(dirname -- "$(dirname -- "$KMIP_EXAMPLES")")/.cache/dev-pki}"

kmip() {
  local request=${1:?usage: kmip REQUEST [NAME=VALUE ...]} body response code type=application/json
  shift
  case $request in
    */*) ;;
    *) [ -f "$request" ] || request=$KMIP_EXAMPLES/$request ;;
  esac
  case $request in *.xml) type=text/xml ;; esac
  body=$(python3 -c 'import string, sys
path, *pairs = sys.argv[1:]
values = dict(p.split("=", 1) for p in pairs if "=" in p)
try:
    print(string.Template(open(path).read()).substitute(values))
except KeyError as e:
    sys.exit(f"kmip: {path} needs {e.args[0]}=VALUE")' "$request" "$@") || return 1
  response=$(printf '%s' "$body" | curl -sS --connect-timeout 10 --max-time 30 \
    --cacert "$KMIP_PKI/ca.pem" \
    --cert "$KMIP_PKI/${KMIP_CLIENT:-client}.pem" --key "$KMIP_PKI/${KMIP_CLIENT:-client}.key" \
    -H "Content-Type: $type" --data-binary @- -w '\n%{http_code}' \
    "${KMIP_URL:-https://localhost:5697/kmip}") || return 1
  code=${response##*$'\n'}
  response=${response%$'\n'*}
  if [ "$code" != 200 ]; then
    printf 'kmip: HTTP %s%s\n' "$code" "${response:+: $response}" >&2
    return 1
  fi
  printf '%s\n' "$response"
}

field() {
  python3 -c 'import json, sys
def find(node, tag):
    if node.get("tag") == tag:
        return node["value"]
    for child in node["value"] if isinstance(node.get("value"), list) else []:
        if (found := find(child, tag)) is not None:
            return found
text = sys.stdin.read()
if not text.strip():
    sys.exit("field: no response on standard input")
value = find(json.loads(text), sys.argv[1])
print(json.dumps(value) if isinstance(value, list) else value)' "${1:?usage: field TAG}"
}

pretty() {
  python3 -c 'import json, sys
text = sys.stdin.read()
if text.lstrip().startswith("<"):
    import xml.dom.minidom
    print(xml.dom.minidom.parseString(text).toprettyxml(indent="  ").strip())
    sys.exit()
def lines(node, indent):
    head = indent + "{\"tag\": " + json.dumps(node["tag"])
    if "type" in node:
        head += ", \"type\": " + json.dumps(node["type"])
    value = node.get("value")
    if not isinstance(value, list):
        return [head + ", \"value\": " + json.dumps(value) + "}"]
    out = [head + ", \"value\": ["]
    for i, child in enumerate(value):
        out += lines(child, indent + "  ")
        if i < len(value) - 1:
            out[-1] += ","
    out[-1] += "]}"
    return out
print("\n".join(lines(json.loads(text), "")))'
}

hex() { printf '%s' "$1" | od -v -An -tx1 | tr -d ' \n'; }

unhex() { python3 -c 'import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode())'; }
