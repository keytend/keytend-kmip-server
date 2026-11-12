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

"""Replay the OASIS MSGENC traces through the server's real HTTPS transport.

Separately labelled mode ("profiles-4.1-variations-over-https"). It does not
change the strict report or the TTLV variation report. The Profiles 4.1
comparator, fixtures and trace loading are imported from
scripts/oasis_profile_replay.py unchanged; only the transport differs.

Transport rules (Profiles 1.3-3.0 section 5.3, identical across editions):
the client POSTs to /kmip over TLS with HTTP/1.0 or HTTP/1.1, a Content-Type of
application/octet-stream (TTLV), application/json (JSON) or text/xml (XML), a
Content-Length and Cache-Control: no-cache. The server SHALL return 200 when a
KMIP response is available, with the same Content-Type rule, a Content-Length
and Cache-Control: no-cache. MSGENC-HTTPS-M-1 sends TTLV in the body;
MSGENC-JSON-M-1 and MSGENC-XML-M-1 send their declared encoding (sections 5.4
and 5.5 define the encodings; section 5.3 is the only transport the Profiles
give for them). Sections 5.4/5.5 also make Maximum Response Size refer to the
TTLV-equivalent length, which a separate probe checks against the binary port.

Requests are encoded and responses decoded by scripts/profile_text_codec.py,
written from the Profiles text and independent of the server's Rust codec.
Each JSON/XML trace runs in two request forms: "normative" (tag and
enumeration names, as in the Profiles' normative JSON wire example and the
trace files) and "numeric" (0x tags, generic TTLV XML elements, JSON Numbers).
Read-only exchanges are also sent to the binary KMIP port, and the decoded
responses must be logically identical apart from the time stamp and server
correlation value (sections 5.4/5.5: "logically the same as if the message
encoding was in TTLV form").

Negative transport tests check HTTP status codes (RFC 9110/9112, because the
Profiles only require 200 when a KMIP response exists) and the KMIP failure the
server returns for unparseable bodies (KMIP 1.0-1.4 section 11.1 General
Errors: "Message cannot be parsed" -> a header and a Batch Item without
Operation, Operation Failed, Invalid Message).
"""
import argparse,copy,hashlib,json,os,pathlib,re,socket,subprocess,tempfile,xml.etree.ElementTree as ET
import oasis_profile_replay as P
import oasis_validate as V
from oasis_conformance import TAGS,Unsupported,encode_xml,fixture_constants
from image_evidence import source_commit
from test_runtime import ROOT,Server,free_port
from wire import encode,decode,connect,node
import profile_text_codec as C

MEDIA={'TTLV':'application/octet-stream','JSON':'application/json','XML':'text/xml'}
DECLARED={'MSGENC-HTTPS':'TTLV','MSGENC-JSON':'JSON','MSGENC-XML':'XML'}
READ_ONLY={'Query','DiscoverVersions'}

class HttpsServer(Server):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.https=free_port()
    def start(self):
        previous=os.environ.get('KMIP_HTTPS_LISTEN');os.environ['KMIP_HTTPS_LISTEN']=f'127.0.0.1:{self.https}'
        try:super().start()
        finally:
            if previous is None:os.environ.pop('KMIP_HTTPS_LISTEN',None)
            else:os.environ['KMIP_HTTPS_LISTEN']=previous

# ---------- minimal HTTP/1.x client on the TLS socket ----------
class HttpResponse:
    def __init__(self,version,status,reason,headers,body):
        self.version=version;self.status=status;self.reason=reason;self.headers=headers;self.body=body
    def get(self,name):
        found=[v for k,v in self.headers if k==name.lower()]
        return found
    def one(self,name):
        found=self.get(name);return found[0] if len(found)==1 else None
    def persistent(self,request_version):
        tokens={t.strip().lower() for v in self.get('connection') for t in v.split(',')}
        if 'close' in tokens:return False
        return self.version=='1.1' if request_version=='1.1' else 'keep-alive' in tokens

def read_response(sock,head=False,limit=16*1024*1024):
    buf=b''
    while b'\r\n\r\n' not in buf:
        part=sock.recv(4096)
        if not part:raise EOFError('connection closed before a complete HTTP response head' if buf else 'connection closed without an HTTP response')
        buf+=part
        if len(buf)>65536:raise AssertionError('HTTP response head too large')
    head_bytes,rest=buf.split(b'\r\n\r\n',1)
    lines=head_bytes.decode('latin-1').split('\r\n')
    m=re.fullmatch(r'HTTP/(1\.[01]) (\d{3}) ?(.*)',lines[0])
    if not m:raise AssertionError(f'invalid HTTP status line {lines[0]!r}')
    headers=[]
    for line in lines[1:]:
        if not line or line[0] in ' \t' or ':' not in line:raise AssertionError(f'invalid HTTP header line {line!r}')
        k,v=line.split(':',1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",k):raise AssertionError(f'invalid header name {k!r}')
        headers.append((k.lower(),v.strip(' \t')))
    r=HttpResponse(m.group(1),int(m.group(2)),m.group(3),headers,b'')
    lengths=r.get('content-length')
    if head or r.status in (204,304) or r.status<200:
        if rest:raise AssertionError('bytes after a bodiless response')
        return r
    if len(lengths)>1:raise AssertionError('multiple Content-Length fields in the response')
    if lengths:
        if not re.fullmatch(r'\d+',lengths[0]):raise AssertionError('invalid Content-Length '+lengths[0])
        n=int(lengths[0])
        if n>limit:raise AssertionError('response body too large for the harness')
        body=rest
        while len(body)<n:
            part=sock.recv(min(65536,n-len(body)))
            if not part:raise EOFError(f'connection closed after {len(body)} of {n} body bytes')
            body+=part
        if len(body)>n:raise AssertionError(f'{len(body)-n} bytes beyond Content-Length')
        r.body=body
    else:
        body=rest
        while True:
            part=sock.recv(65536)
            if not part:break
            body+=part
            if len(body)>limit:raise AssertionError('response body too large for the harness')
        r.body=body
    return r

def request_bytes(method,body,media,http='1.0',path='/kmip',host=None,extra=()):
    if http=='1.0':
        # The informative MSGENC-HTTPS wire encoding (Profiles 5.3.3.1).
        headers=[('Pragma','no-cache'),('Cache-Control','no-cache'),('Connection','keep-alive')]
    else:headers=[('Host',host or 'localhost'),('Cache-Control','no-cache')]
    if media is not None:headers.append(('Content-Type',media))
    if body is not None:headers.append(('Content-Length',str(len(body))))
    headers+=list(extra)
    return (f'{method} {path} HTTP/{http}\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers)+'\r\n').encode('latin-1')+(body or b'')

class Transport:
    """Sequential KMIP exchanges over one HTTPS connection when the server keeps it."""
    def __init__(self,server,encoding,form,http):
        self.server=server;self.encoding=encoding;self.form=form;self.http=http;self.sock=None
        self.connections=0;self.reused=0;self.checks=set()
    def close(self):
        if self.sock is not None:self.sock.close();self.sock=None
    def exchange(self,req_node,version,trace=None):
        if self.encoding=='TTLV':body=encode(req_node)
        elif self.encoding=='JSON':body=C.encode_json(req_node,self.form,trace)
        else:body=C.encode_xml_text(req_node,self.form,trace)
        if self.sock is None:self.sock=connect(self.server.pki,self.server.https);self.connections+=1
        else:self.reused+=1
        self.sock.settimeout(15)
        self.sock.sendall(request_bytes('POST',body,MEDIA[self.encoding],self.http,host=f'localhost:{self.server.https}'))
        r=read_response(self.sock)
        check_kmip_reply(r,self.encoding,self.checks)
        if not r.persistent(self.http):self.close()
        return decode_body(r.body,self.encoding,version),r

def check_kmip_reply(r,encoding,checks):
    """Profiles 5.3.2 server rules for a response that carries a KMIP message."""
    if r.status!=200:raise AssertionError(f'HTTP status {r.status} {r.reason}; Profiles 5.3.2 requires 200 when a KMIP response is available; body {r.body[:200]!r}')
    ctype=r.one('content-type')
    if ctype is None:raise AssertionError('response has no single Content-Type (Profiles 5.3.2)')
    media,_,params=ctype.partition(';')
    if media.strip().lower()!=MEDIA[encoding]:raise AssertionError(f'response Content-Type {ctype!r}, Profiles 5.3.2 requires {MEDIA[encoding]!r}')
    if params.strip():checks.add(f'Content-Type parameters present: {params.strip()}')
    if r.one('content-length') is None:raise AssertionError('response has no single Content-Length (Profiles 5.3.2)')
    cache=[t.strip().lower() for v in r.get('cache-control') for t in v.split(',')]
    if 'no-cache' not in cache:raise AssertionError(f'response Cache-Control {r.get("cache-control")} lacks no-cache (Profiles 5.3.2)')
    checks.add('200, Content-Type, Content-Length and Cache-Control: no-cache (Profiles 5.3.2)')

def decode_body(body,encoding,version):
    if encoding=='TTLV':
        actual=V.strict_decode(body)
        if actual!=decode(body):raise AssertionError('strict and lenient TTLV decoders disagree')
        return actual
    try:n=C.decode_json(body,version) if encoding=='JSON' else C.decode_xml(body,version)
    except C.CodecError as e:raise AssertionError(f'{encoding} response violates the Profiles encoding: {e}')
    # The message must also be representable in TTLV (Profiles 5.4/5.5).
    try:
        if V.strict_decode(encode(n))!=n:raise AssertionError('TTLV re-encoding changed the message')
    except (OverflowError,ValueError) as e:raise AssertionError(f'{encoding} response is not representable in TTLV: {e}')
    return n

def masked(n):
    """Drop values Profiles 4.1.1 lets vary between two otherwise equal responses."""
    tag,kind,v=n
    if kind!=1:return n
    out=[]
    for c in v:
        if tag==TAGS['ResponseHeader'] and c[0] in (TAGS['TimeStamp'],TAGS['ServerCorrelationValue']):out.append((c[0],c[1],None))
        else:out.append(masked(c))
    return (tag,kind,out)

def read_only(req_xml):
    ops=[P.xval(b,'Operation') for b in req_xml.findall('BatchItem')]
    return bool(ops) and all(o in READ_ONLY for o in ops)

def run_case_https(server,replay,version,messages,inventory,entry,transport):
    """Mirror of oasis_profile_replay.run_case with the HTTPS exchange."""
    transformations=entry['transformations'];entry['completed_exchanges']=0
    messages,omitted=P.omit_interop(messages,version,inventory);transformations+=omitted
    if any(e.get('value')=='Interop' for m in messages if m.tag=='RequestMessage' for e in m.iter('Operation')):
        raise Unsupported('Interop used inside the test body; no permitted omission','test_only_control_operation')
    replay.vars.update(fixture_constants(messages));uid_kind=12 if version.startswith('3') else 7
    entry['binary_equivalence']=[]
    with server.connect() as binary:
        try:
            for i in range(0,len(messages),2):
                if messages[i].tag!='RequestMessage' or i+1>=len(messages) or messages[i+1].tag!='ResponseMessage':raise Unsupported('non-alternating message trace')
                replay.exchange_index=i//2;entry['failed_exchange']=i//2
                req_xml,used=replay.prepare_request(messages[i])
                later=messages[i+2:]
                notes=[];P.rederive_inputs(replay,req_xml,messages[i+1],binary,version,uid_kind,notes,later)
                for note in notes:replay.variations.add(note)
                req=encode_xml(req_xml,replay.vars)
                actual,_=transport.exchange(req,version,req_xml)
                replay.last_actual=actual
                # Checked before the trace comparison so that it also covers an
                # exchange whose trace comparison fails.
                if read_only(req_xml):
                    other=V.strict_decode(P.exchange_raw(binary,req))
                    if masked(other)!=masked(actual):raise AssertionError(f'exchange {i//2}: {transport.encoding} response differs from the binary-port response to the same request (Profiles 5.4/5.5 logical equivalence)')
                    entry['binary_equivalence'].append(i//2)
                exact_items=replay.compare_message(messages[i+1],actual,req_xml)
                replay.harvest(req_xml,actual,req)
                for item in exact_items:
                    for o in replay.obligations:
                        if o.roundtrip is None and any(o.value==u for u in used.get(item,[])):o.roundtrip=f'in-trace round trip at exchange {i//2}'
                if not P.observes_attributes(later):P.fetch_material(replay,binary,version,uid_kind)
                replay.resolve()
                entry['completed_exchanges']+=1
            P.fetch_material(replay,binary,version,uid_kind);replay.resolve()
        finally:transport.close()
    entry.pop('failed_exchange',None)

def lanes_for(cid,encodings,forms=('normative','numeric'),https=('1.0','1.1')):
    """MSGENC traces run in their declared encoding with every form and HTTP
    version; other traces use the selected encodings, forms and versions."""
    base=re.sub(r'-M-\d+$','',cid) if cid.startswith('MSGENC') else None
    if base in DECLARED:chosen,forms,https=[DECLARED[base]],('normative','numeric'),('1.0','1.1')
    else:chosen=encodings
    out=[]
    for enc in chosen:
        for form in (['binary'] if enc=='TTLV' else forms):
            for http in https:out.append((enc,form,http))
    return out

# ---------- Maximum Response Size probe (Profiles 5.4/5.5) ----------
def query_request(version,mrs=None):
    major,minor=(int(x) for x in version.split('.'))
    header=[node(TAGS['ProtocolVersion'],1,[node(TAGS['ProtocolVersionMajor'],2,major),node(TAGS['ProtocolVersionMinor'],2,minor)])]
    if mrs is not None:header.append(node(TAGS['MaximumResponseSize'],2,mrs))
    if major<3:header.append(node(TAGS['BatchCount'],2,1))
    payload=[node(TAGS['QueryFunction'],5,1),node(TAGS['QueryFunction'],5,2)]
    item=node(TAGS['BatchItem'],1,[node(TAGS['Operation'],5,24),node(TAGS['RequestPayload'],1,payload)])
    return node(TAGS['RequestMessage'],1,[node(TAGS['RequestHeader'],1,header),item])
def outcome(resp):
    bi=P.sub(resp,'BatchItem');return (P.val(bi,'ResultStatus'),P.val(bi,'ResultReason'))
def mrs_probe(server,version):
    """The same limit must give the same result in every encoding, measured in TTLV bytes."""
    rows=[]
    with server.connect() as b:
        full=V.strict_decode(P.exchange_raw(b,query_request(version)))
        size=len(encode(full))
        for limit in (size,size-1):
            binary=outcome(V.strict_decode(P.exchange_raw(b,query_request(version,limit))))
            row={'version':version,'maximum_response_size':limit,'ttlv_response_length':size,'binary_port':list(binary),'https':{}}
            for enc in ('TTLV','JSON','XML'):
                t=Transport(server,enc,'numeric','1.1')
                try:
                    resp,r=t.exchange(query_request(version,limit),version)
                    row['https'][enc]={'outcome':list(outcome(resp)),'body_length':len(r.body)}
                except (AssertionError,EOFError,OSError) as e:row['https'][enc]={'error':str(e)}
                finally:t.close()
            same=all(v.get('outcome')==list(binary) for v in row['https'].values())
            expect=(0,None) if limit==size else (1,2)
            row['status']='passed' if same and binary==expect else 'failed'
            if not same:row['detail']='an encoding gave a different result from the binary port for the same TTLV limit'
            elif binary!=expect:row['detail']=f'binary port result {binary} for a limit {"equal to" if limit==size else "one byte below"} the TTLV response length'
            rows.append(row)
    return rows

# ---------- negative transport tests ----------
def kmip_invalid_message(r,encoding):
    check_kmip_reply(r,encoding,set())
    resp=decode_body(r.body,encoding,'1.4')
    bi=P.sub(resp,'BatchItem')
    if resp[0]!=TAGS['ResponseMessage'] or P.sub(resp,'ResponseHeader') is None or bi is None:raise AssertionError('not a KMIP Response Message with a header and Batch Item')
    if P.val(bi,'Operation') is not None:raise AssertionError('Batch Item carries an Operation; 1.x section 11.1 specifies one without Operation')
    if (P.val(bi,'ResultStatus'),P.val(bi,'ResultReason'))!=(1,4):raise AssertionError(f'result {(P.val(bi,"ResultStatus"),P.val(bi,"ResultReason"))}, expected Operation Failed / Invalid Message')
    return 'KMIP Operation Failed / Invalid Message, no Operation (1.x section 11.1)'

def negative_cases(version='2.1'):
    good=query_request(version)
    ttlv=encode(good);js=C.encode_json(good,'numeric');xm=C.encode_xml_text(good,'normative')
    cases=[]
    def add(name,raw,statuses,why,check=None,head=False):cases.append({'name':name,'raw':raw,'statuses':statuses,'why':why,'check':check,'head':head})
    def allow(r):
        if r.status==405 and not any(t.strip()=='POST' for v in r.get('allow') for t in v.split(',')):raise AssertionError('405 without Allow: POST (RFC 9110 15.5.6 MUST)')
    add('control: valid JSON Query is answered',request_bytes('POST',js,MEDIA['JSON'],'1.1'),{200},'Profiles 5.3.2',lambda r:check_kmip_reply(r,'JSON',set()))
    add('control: Content-Type charset=utf-8 parameter is accepted',request_bytes('POST',js,'application/json; charset=utf-8','1.1'),{200},'RFC 8259 section 8.1 (JSON is UTF-8)',lambda r:None)
    # Content-Type
    for media in ('text/plain','application/x-www-form-urlencoded','application/kmip','application/json; charset=iso-8859-1'):
        add(f'Content-Type {media!r}',request_bytes('POST',js,media,'1.1'),{415},'RFC 9110 15.5.16; Profiles 5.3 lists only three media types')
    add('Content-Type absent',request_bytes('POST',ttlv,None,'1.1'),{415,200},'RFC 9110 8.3: MAY assume application/octet-stream or reject')
    add('two Content-Type fields',request_bytes('POST',js,MEDIA['JSON'],'1.1',extra=[('Content-Type','text/xml')]),{400,415},'RFC 9110 5.3: Content-Type is singleton')
    add('JSON body labelled application/octet-stream',request_bytes('POST',js,MEDIA['TTLV'],'1.1'),{200},'parsed as TTLV, which fails',lambda r:kmip_invalid_message(r,'TTLV'))
    # Malformed bodies: a KMIP response is available, so 200 (Profiles 5.3.2).
    bodies=[
        ('JSON','truncated JSON',js[:len(js)//2]),
        ('JSON','JSON trailing garbage',js+b' x'),
        ('JSON','JSON duplicate value property',b'{"tag":"RequestMessage","value":[],"value":[]}'),
        ('JSON','JSON unknown type name',js.replace(b'"Integer"',b'"Integr"',1)),
        ('JSON','JSON Integer hex without fixed width',js.replace(b'"value":2',b'"value":"0x2"',1)),
        ('JSON','JSON fractional Integer',js.replace(b'"value":2',b'"value":2.5',1)),
        ('JSON','JSON not UTF-8',b'{"tag":"RequestMessage\xff","value":[]}'),
        ('JSON','JSON array root',b'[]'),
        ('JSON','empty JSON body',b''),
        ('XML','unclosed XML',xm[:-20]),
        ('XML','XML internal entity DTD',b'<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><RequestMessage>&b;</RequestMessage>'),
        ('XML','XML external entity',b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="&x;"/></ProtocolVersion></RequestHeader></RequestMessage>'),
        ('XML','XML element text',xm.replace(b'<RequestHeader>',b'<RequestHeader>text',1)),
        ('XML','XML foreign namespace',xm.replace(b'<RequestMessage>',b'<RequestMessage xmlns="urn:example">',1)),
        ('XML','two XML roots',xm+xm),
        ('XML','empty XML body',b''),
        ('TTLV','truncated TTLV',ttlv[:-8]),
        ('TTLV','TTLV length beyond body',ttlv[:4]+(len(ttlv)+64).to_bytes(4,'big')+ttlv[8:]),
        ('TTLV','empty TTLV body',b''),
    ]
    for enc,name,body in bodies:
        add(name,request_bytes('POST',body,MEDIA[enc],'1.1'),{200},'Profiles 5.3.2 (200 when a KMIP response is available); KMIP 1.x 11.1',lambda r,enc=enc:kmip_invalid_message(r,enc))
    # Size
    add('TTLV Content-Length above the 1 MiB server limit (no body sent)',request_bytes('POST',None,MEDIA['TTLV'],'1.1',extra=[('Content-Length',str(1024*1024+1))]),{413},'RFC 9110 15.5.14')
    add('JSON Content-Length above the 8 MiB server limit (no body sent)',request_bytes('POST',None,MEDIA['JSON'],'1.1',extra=[('Content-Length',str(8*1024*1024+1))]),{413},'RFC 9110 15.5.14')
    add('XML Content-Length above the 8 MiB server limit (no body sent)',request_bytes('POST',None,MEDIA['XML'],'1.1',extra=[('Content-Length',str(8*1024*1024+1))]),{413},'RFC 9110 15.5.14')
    # Framing
    add('Content-Length absent',request_bytes('POST',None,MEDIA['TTLV'],'1.1'),{411},'RFC 9110 15.5.12; Profiles 5.3.1 requires clients to send it')
    add('two different Content-Length values',request_bytes('POST',ttlv,MEDIA['TTLV'],'1.1',extra=[('Content-Length',str(len(ttlv)+8))]),{400},'RFC 9112 6.3 item 5: invalid framing, MUST respond 400')
    add('non-numeric Content-Length',request_bytes('POST',None,MEDIA['TTLV'],'1.1',extra=[('Content-Length','12a')]),{400},'RFC 9112 6.3 item 5')
    add('chunked Transfer-Encoding',(f'POST /kmip HTTP/1.1\r\nHost: localhost\r\nContent-Type: {MEDIA["TTLV"]}\r\nTransfer-Encoding: chunked\r\n\r\n{len(ttlv):x}\r\n').encode()+ttlv+b'\r\n0\r\n\r\n',{400,411},'Profiles 5.3.1 requires Content-Length; RFC 9112 6.3 allows 411')
    add('HTTP/1.1 without Host',f'POST /kmip HTTP/1.1\r\nContent-Type: {MEDIA["TTLV"]}\r\nContent-Length: {len(ttlv)}\r\n\r\n'.encode()+ttlv,{400},'RFC 9112 3.2: MUST respond 400')
    add('HTTP/1.0 without Host is answered',f'POST /kmip HTTP/1.0\r\nContent-Type: {MEDIA["TTLV"]}\r\nContent-Length: {len(ttlv)}\r\n\r\n'.encode()+ttlv,{200},'Profiles 5.3.2 requires HTTP/1.0 support',lambda r:check_kmip_reply(r,'TTLV',set()))
    # Method and target
    for method in ('GET','PUT','DELETE','OPTIONS','PATCH','TRACE','post'):
        body=None if method in ('GET','TRACE') else ttlv
        add(f'method {method}',request_bytes(method,body,MEDIA['TTLV'] if body else None,'1.1'),{405,501},'Profiles 5.3.1 POST only; RFC 9110 15.5.6 (405 + Allow) or 9.1 (501)',allow)
    add('method HEAD',request_bytes('HEAD',None,None,'1.1'),{405,501},'RFC 9110 15.5.6; no body in a HEAD response',allow,head=True)
    for path in ('/','/kmip/','/kmipx','/kmip?x=1'):
        add(f'target {path}',request_bytes('POST',ttlv,MEDIA['TTLV'],'1.1',path=path),{404},'Profiles 5.3.2 SHOULD support /kmip; other targets are not KMIP resources')
    add('Accept image/png',request_bytes('POST',ttlv,MEDIA['TTLV'],'1.1',extra=[('Accept','image/png')]),{406},'RFC 9110 15.5.7')
    add('HTTP/2.0 request line',f'POST /kmip HTTP/2.0\r\nHost: localhost\r\nContent-Type: {MEDIA["TTLV"]}\r\nContent-Length: {len(ttlv)}\r\n\r\n'.encode()+ttlv,{400,505},'RFC 9110 15.6.6')
    return cases

def run_negatives(server):
    results=[]
    for c in negative_cases():
        row={'name':c['name'],'expected_status':sorted(c['statuses']),'basis':c['why']}
        try:
            with connect(server.pki,server.https) as s:
                s.settimeout(15);s.sendall(c['raw'])
                try:r=read_response(s,head=c['head'])
                except EOFError as e:raise AssertionError(f'no HTTP response: {e}')
            row['status_code']=r.status
            problems=[]
            if r.status not in c['statuses']:problems.append(f'HTTP {r.status}, expected {sorted(c["statuses"])}')
            if r.status==200 and r.one('content-length') is None:problems.append('no Content-Length')
            if not any('no-cache' in v for v in r.get('cache-control')):
                # Profiles 5.3.2 governs responses carrying KMIP messages. An
                # error without one must still not be reusable from a cache when
                # its status is heuristically cacheable (RFC 9111 4.2.2, RFC 9110
                # 15.1); a 400/411/413/415 is not.
                if r.status in (200,203,204,206,300,301,308,404,405,410,414,501):problems.append('no Cache-Control: no-cache')
                else:row['observation']=f'HTTP {r.status} without Cache-Control (not heuristically cacheable; RFC 9111 4.2.2)'
            if c['head'] and r.body:problems.append('HEAD response with a body')
            if not problems and c['check']:
                note=c['check'](r)
                if note:row['kmip']=note
            row['status']='failed' if problems else 'passed'
            if problems:row['detail']='; '.join(problems)
        except (AssertionError,OSError) as e:row.update(status='failed',detail=str(e))
        results.append(row)
    return results

def run_persistence(server):
    """HTTP/1.0 and HTTP/1.1 connection handling (Profiles 5.3.2: both versions)."""
    body=encode(query_request('1.4'));rows=[]
    def lane(name,first,second,expect_open,basis,check=None):
        row={'name':name,'basis':basis}
        try:
            with connect(server.pki,server.https) as s:
                s.settimeout(15);s.sendall(first);r=read_response(s);row['status_code']=r.status
                if check:check(r)
                if expect_open:
                    s.sendall(second);r2=read_response(s)
                    if r2.status!=200:raise AssertionError(f'second request HTTP {r2.status}')
                    check_kmip_reply(r2,'TTLV',set());decode_body(r2.body,'TTLV','1.4')
                else:
                    try:rest=s.recv(1)
                    except OSError:rest=b''
                    if rest:raise AssertionError('connection stayed open and sent more bytes')
            row['status']='passed'
        except (AssertionError,OSError,EOFError) as e:row.update(status='failed',detail=str(e))
        rows.append(row)
    def keep_alive(r):
        if r.version!='1.0':raise AssertionError(f'HTTP/{r.version} response to an HTTP/1.0 request')
        if not r.persistent('1.0'):raise AssertionError('no Connection: keep-alive on the response')
        check_kmip_reply(r,'TTLV',set())
    good=request_bytes('POST',body,MEDIA['TTLV'],'1.0')
    lane('HTTP/1.0 keep-alive request: a second request is answered on the same connection',good,good,True,'Profiles 5.3.3.1 informative wire encoding (HTTP/1.0, Connection: keep-alive); RFC 9112 C.2.2',keep_alive)
    plain=f'POST /kmip HTTP/1.0\r\nContent-Type: {MEDIA["TTLV"]}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body
    lane('HTTP/1.0 without keep-alive: the server closes after the response',plain,None,False,'RFC 9112 9.3',lambda r:check_kmip_reply(r,'TTLV',set()))
    v11=request_bytes('POST',body,MEDIA['TTLV'],'1.1')
    lane('HTTP/1.1: a second request is answered on the same connection',v11,v11,True,'RFC 9112 9.3 (persistent by default)',lambda r:check_kmip_reply(r,'TTLV',set()))
    lane('HTTP error reply closes the connection',request_bytes('POST',body,'text/plain','1.1'),None,False,'server policy: Connection: close after a transport error',lambda r:None if r.status==415 and not r.persistent('1.1') else (_ for _ in ()).throw(AssertionError(f'HTTP {r.status}, persistent={r.persistent("1.1")}')))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--versions',nargs='+',default=['1.3','1.4','2.0','2.1','3.0'])
    parser.add_argument('--filter',default='MSGENC',help='Trace name substring (default: the MSGENC traces)')
    parser.add_argument('--encodings',nargs='+',default=['JSON','XML'],choices=['TTLV','JSON','XML'],help='Encodings for non-MSGENC traces')
    parser.add_argument('--forms',nargs='+',default=['normative','numeric'],choices=['normative','numeric'],help='Request forms for non-MSGENC traces')
    parser.add_argument('--http-versions',nargs='+',default=['1.0','1.1'],choices=['1.0','1.1'],help='HTTP versions for non-MSGENC traces')
    parser.add_argument('--binary',type=pathlib.Path,default=ROOT/'target/debug/keytend-kmip-server')
    parser.add_argument('--image',help='the image that --binary runs (scripts/image_server.py), recorded as the server under test');parser.add_argument('--engine',default='podman')
    parser.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/oasis-https-replay.json')
    parser.add_argument('--diagnose',action='store_true')
    parser.add_argument('--skip-binary-baseline',action='store_true',help='Do not also run each trace over the binary port')
    a=parser.parse_args()
    inventory=json.loads(P.INVENTORY.read_text())
    subprocess.run(['python3',str(ROOT/'scripts/fetch_specs.py')],check=True,stdout=subprocess.DEVNULL)
    from image_evidence import runtime_evidence
    runtime=runtime_evidence(a.binary,a.image,a.engine)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    sequences={(v,c) for seq in inventory['sequences'] for v in seq['versions'] for c in seq['chain']}
    report=[];probes=[];negatives=[]
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-https-replay-') as d:
        server=HttpsServer(d,binary=a.binary,draft=True);base_policy=json.loads((server.pki/'policy.json').read_text())
        endpoint=None
        def configure(label,operations=None,client_endpoint=None):
            server.stop();server.data=pathlib.Path(d)/'data'/label;server.data.mkdir(parents=True,mode=0o700)
            policy=copy.deepcopy(base_policy)
            for principal in policy['principals'].values():
                if principal['name']!='database':continue
                if operations is not None:principal['operations']=operations
                # Same server-to-client fixture as oasis_profile_replay.py: a
                # trace whose Query lists Notify/Put needs a client endpoint.
                if client_endpoint:principal['client_endpoint']=client_endpoint
                principal['name']=f'oasis-{label}'
            (server.pki/'policy.json').write_text(json.dumps(policy));server.start()
        run=0
        for version in a.versions:
            entries=P.load_entries(version,a.filter);corpus_keys=P.corpus_private_keys(P.load_entries(version,''))
            for name in sorted(entries):
                cid=P.case_id(name)
                try:root=ET.fromstring(entries[name])
                except ET.ParseError as e:
                    report.append({'version':version,'case':name,'lane':'(all)','status':'failed','detail':'XML parse error: '+str(e)});continue
                if root.tag!='KMIP':continue
                messages=[e for e in root if e.tag in ('RequestMessage','ResponseMessage')]
                fixture=inventory['authorization_fixtures'].get(cid)
                wants_endpoint=P.query_expects_server_to_client(messages)
                if wants_endpoint and endpoint is None:endpoint=P.ClientEndpoint(server.pki)
                lanes=[('binary-port',None,None)]*(not a.skip_binary_baseline)+lanes_for(cid,a.encodings,a.forms,a.http_versions)
                first=len(report)
                for lane in lanes:
                    label='TTLV over the KMIP port (variation replay)' if lane[0]=='binary-port' else f'{lane[0]} over HTTPS/{lane[2]} ({lane[1]} form)'
                    entry={'version':version,'case':name,'lane':label,'transformations':[]}
                    if fixture:entry['transformations'].append(fixture['label'])
                    if wants_endpoint:entry['transformations'].append(inventory['server_to_client_fixture']['label'])
                    if (version,cid) in sequences:
                        report.append({**entry,'status':'unexecuted','category':'sequence_not_replayed','detail':'sequenced cases are replayed only by oasis_profile_replay.py'});continue
                    run+=1;configure(f'{version}-{run}',fixture['client_operations'] if fixture else None,endpoint.policy(server.pki,version) if wants_endpoint else None)
                    replay=P.Replay(version,corpus_keys);replay.last_actual=None
                    transport=None if lane[0]=='binary-port' else Transport(server,*lane)
                    try:
                        if transport is None:P.run_case(server,replay,version,copy.deepcopy(messages),inventory,entry)
                        else:run_case_https(server,replay,version,copy.deepcopy(messages),inventory,entry,transport)
                        open_=P.finish(replay)
                        entry['obligations']=[o.record() for o in replay.obligations]
                        if open_:entry['status']='unverified';entry['detail']='; '.join(f'{o.kind} at {o.path}: {o.info.get("unverifiable","not verified")}' for o in open_)
                        else:entry['status']='passed'
                    except Unsupported as e:entry.update(status='unexecuted',detail=str(e),category=e.category)
                    except (AssertionError,ValueError,KeyError,ET.ParseError,OSError,EOFError) as e:
                        entry.update(status='failed',detail=str(e) or type(e).__name__,category='transport_or_trace_mismatch')
                        if replay.last_actual is not None and a.diagnose:entry['actual_response']=P.render(replay.last_actual)
                    if transport is not None:
                        entry['transport']={'connections':transport.connections,'reused_connection_requests':transport.reused,'checks':sorted(transport.checks)}
                    entry['variations']=sorted(replay.variations|P.HARNESS_NOTES);P.HARNESS_NOTES.clear()
                    report.append(entry);server.stop()
                    print(version,P.case_id(name),label,entry['status'],(entry.get('detail') or '')[:160],flush=True)
                case_rows=report[first:];base=[r for r in case_rows if 'KMIP port' in r['lane']]
                for r in case_rows:
                    if r['status']=='failed' and re.search(r'ResponsePayload.*(/Operation: expected at least|expected Operation \w+ not present)',r.get('detail','')):
                        r['failure_family']='Query Operation list lacks operations the trace lists (operation implementation, not transport)'
                    if base and r is not base[0]:
                        r['same_result_as_binary_port']=(r['status'],r.get('detail'),r.get('completed_exchanges'))==(base[0]['status'],base[0].get('detail'),base[0].get('completed_exchanges'))
            if a.filter=='MSGENC' or 'MSGENC' in a.filter:
                run+=1;configure(f'{version}-probe-{run}')
                try:probes+=mrs_probe(server,version)
                except (AssertionError,OSError,EOFError) as e:probes.append({'version':version,'status':'failed','detail':str(e)})
                server.stop()
        run+=1;configure(f'negative-{run}')
        try:negatives=run_negatives(server)+run_persistence(server)
        finally:server.stop()
    for n in negatives:print('negative',n['status'],n['name'],n.get('status_code'),n.get('detail',''),flush=True)
    for p in probes:print('mrs-probe',p['version'],p.get('maximum_response_size'),p['status'],p.get('detail',''),flush=True)
    def count(rows):return {s:sum(r['status']==s for r in rows) for s in ['passed','unverified','failed','unexecuted']}
    https_rows=[r for r in report if 'HTTPS' in r['lane']];baseline=[r for r in report if 'KMIP port' in r['lane']]
    summary={'https_lanes':count(https_rows),'binary_port_baseline':count(baseline),'maximum_response_size_probe':count(probes),'negative_transport':count(negatives)}
    failed=any(r['status']=='failed' for r in report+probes+negatives)
    a.output.write_text(json.dumps({'status':'failed' if failed else 'passed','mode':'profiles-4.1-variations-over-https',
        'conformance_credit':'none; separately labelled transport replay, the strict and TTLV variation reports are unchanged',
        'selection':{'versions':a.versions,'filter':a.filter,'encodings':a.encodings,'forms':a.forms,'http_versions':a.http_versions},**runtime,'source_commit':source_commit()[0],
        'summary':summary,'cases':report,'maximum_response_size_probe':probes,'negative_transport':negatives},indent=2)+'\n')
    print(summary)
if __name__=='__main__':main()
