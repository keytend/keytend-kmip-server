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

"""Client side of the KMIP HTTPS binding for the harnesses: a native or
container server with the HTTPS listener enabled, the JSON/XML/TTLV request
encoders and response decoders, and a checked POST to /kmip."""
import datetime,http.client,json,os,ssl,xml.etree.ElementTree as ET
from test_database import ContainerServer
from test_runtime import Server,free_port
from wire import *
# Load the replay's registry-spelling fallback first (harness registry "Rekey"
# versus the normalized "ReKey" the server and the OASIS traces write).
import oasis_profile_replay  # noqa: F401
import profile_text_codec

SERVER_XML_MASKS=('ProtectionStorageMask',)
MEDIA={'TTLV':'application/octet-stream','JSON':'application/json','XML':'text/xml'}
KINDS=['','Structure','Integer','LongInteger','BigInteger','Enumeration','Boolean','TextString','ByteString','DateTime','Interval','DateTimeExtended','Identifier','Reference','NameReference']

class HttpsServer(Server):
    def __init__(self,*args,**kw):super().__init__(*args,**kw);self.https=free_port()
    def start(self):
        previous=os.environ.get('KMIP_HTTPS_LISTEN');os.environ['KMIP_HTTPS_LISTEN']=f'127.0.0.1:{self.https}'
        try:super().start()
        finally:
            if previous is None:os.environ.pop('KMIP_HTTPS_LISTEN',None)
            else:os.environ['KMIP_HTTPS_LISTEN']=previous
class HttpsContainer(ContainerServer):
    def __init__(self,*args,**kw):super().__init__(*args,**kw);self.https=free_port()
    def base(self):return super().base()+['-e','KMIP_HTTPS_LISTEN=0.0.0.0:5697','-p',f'127.0.0.1:{self.https}:5697']

def encoded(n,fmt):
    if fmt=='TTLV':return encode(n)
    def value(n):
        tag,kind,v=n
        if kind==1:return [obj(c) for c in v]
        if kind==8:return v.hex()
        if kind==4:return ('0x' if fmt=='JSON' else '')+v.hex()
        if kind==9:return '0x'+format(v&0xffffffffffffffff,'016x') if fmt=='JSON' else datetime.datetime.fromtimestamp(v,datetime.timezone.utc).isoformat()
        if kind in [3,11] and fmt=='JSON' and abs(v)>=1<<52:return '0x'+format(v&0xffffffffffffffff,'016x')
        if kind==5:return '0x'+format(v,'08x')
        return v
    def obj(n):return {'tag':'0x'+format(n[0],'06x'),'type':KINDS[n[1]],'value':value(n)}
    if fmt=='JSON':return json.dumps(obj(n),ensure_ascii=False,separators=(',',':')).encode()
    def element(n):
        e=ET.Element('TTLV',{'tag':'0x'+format(n[0],'06x'),'type':KINDS[n[1]]})
        if n[1]==1:
            for c in n[2]:e.append(element(c))
        else:
            v=value(n);e.set('value',('true' if v else 'false') if n[1]==6 else str(v))
        return e
    return ET.tostring(element(n),encoding='utf-8',xml_declaration=True)

def decoded(data,fmt):
    if fmt=='TTLV':return decode(data)
    def node_from(tag,kind,value):
        tag=int(tag,16);kind=KINDS.index(kind)
        if kind==1:return node(tag,kind,value)
        if kind in [4,8]:value=bytes.fromhex(value.removeprefix('0x'))
        elif kind==6:value=value in [True,'true','1','0x0000000000000001']
        elif kind in [2,3,5,9,10,11]:
            if kind==9 and isinstance(value,str) and not value.startswith('0x'):
                value=int(datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp())
            else:
                value=int(value,16) if isinstance(value,str) and value.startswith('0x') else int(value)
                if kind in [2,3,9,11] and value>=(1<<(31 if kind==2 else 63)):value-=1<<(32 if kind==2 else 64)
        return node(tag,kind,value)
    if fmt=='JSON':
        # Names are edition-specific: read the declared version, then decode
        # under that edition's names and type list (Profiles 5.5.1).
        message=profile_text_codec.decode_json(data,'3.0')
        pv=[v for h in children(message,0x42007a) for v in children(h,0x420069)]
        edition=f'{get(pv[0],0x42006a)[2]}.{get(pv[0],0x42006b)[2]}' if pv else '3.0'
        return profile_text_codec.decode_json(data,edition)
    # XML too, under the declared edition. The server writes Cryptographic Usage, Storage Status
    # and Protection Storage Masks by name by default (docs/encodings.md), one more
    # mask field than Profiles 5.4.1.6.4 lists, so the harness reads that one as a mask as well.
    message=profile_text_codec.decode_xml(data,'3.0',SERVER_XML_MASKS)
    pv=[v for h in children(message,0x42007a) for v in children(h,0x420069)]
    edition=f'{get(pv[0],0x42006a)[2]}.{get(pv[0],0x42006b)[2]}' if pv else '3.0'
    return profile_text_codec.decode_xml(data,edition,SERVER_XML_MASKS)

def context(s,identity='client',cert=True):
    ctx=ssl.create_default_context(cafile=str(s.pki/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    if cert:ctx.load_cert_chain(s.pki/f'{identity}.pem',s.pki/f'{identity}.key')
    return ctx
# REQ:90b1b6201fdb8f93 every KMIP reply, including KMIP failures, is sent with HTTP status 200
# REQ:1e51f734585fcf96 TTLV replies use Content-Type application/octet-stream
# REQ:97f36fea59220a7c XML replies use Content-Type text/xml
# REQ:800ec54d1e8c7951 JSON replies use Content-Type application/json
# REQ:56f9e1e0af156911 replies carry a Content-Length equal to the body length
# REQ:fe99bf6be8ee87f7 replies carry Cache-Control: no-cache
# REQ:800d3dfc2593224c a TTLV body is the binary TTLV message itself (decoded with the binary codec)
def post(s,n,fmt='JSON',accept=None,identity='client',http10=False):
    c=http.client.HTTPSConnection('localhost',s.https,context=context(s,identity),timeout=15)
    if http10:c._http_vsn=10;c._http_vsn_str='HTTP/1.0'
    data=encoded(n,fmt);output=accept or fmt
    try:
        c.request('POST','/kmip',data,{'Content-Type':MEDIA[fmt],'Accept':MEDIA[output],'Cache-Control':'no-cache'})
        r=c.getresponse();body=r.read()
        assert r.status==200,(r.status,body)
        assert r.headers['Content-Type']==MEDIA[output] and r.headers['Cache-Control']=='no-cache'
        assert int(r.headers['Content-Length'])==len(body)
        return decoded(body,output)
    finally:c.close()
