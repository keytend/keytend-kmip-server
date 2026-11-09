// Copyright 2026 Jeremiah Jordan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dev.keytend.kmip.interop;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.net.URI;
import java.nio.file.*;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.*;
import java.security.interfaces.*;
import java.util.*;

/** Certificate metadata through the unchanged released JAR, with a JCA parser oracle. */
public final class ServerCertificateIdentity {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static String hash(byte[]value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    static String name(int tag){return switch(Tag.fromCode(tag).orElseThrow()) {
        case CRYPTOGRAPHIC_ALGORITHM->"Cryptographic Algorithm";
        case CRYPTOGRAPHIC_LENGTH->"Cryptographic Length";
        case CRYPTOGRAPHIC_USAGE_MASK->"Cryptographic Usage Mask";
        case CERTIFICATE_TYPE->"Certificate Type";
        case CERTIFICATE_LENGTH->"Certificate Length";
        case DIGITAL_SIGNATURE_ALGORITHM->"Digital Signature Algorithm";
        default->throw new IllegalArgumentException("attribute");
    };}
    static Ttlv attrs(int code,Ttlv...values){
        if(code>=20)return structure(ATTRIBUTES,values);
        return structure(TEMPLATE_ATTRIBUTE,Arrays.stream(values).map(v->structure(ATTRIBUTE,text(ATTRIBUTE_NAME,name(v.tag())),v.retag(ATTRIBUTE_VALUE))).toArray(Ttlv[]::new));
    }
    static Ttlv certificate(byte[]der){return structure(CERTIFICATE,enumeration(CERTIFICATE_TYPE,1),bytes(CERTIFICATE_VALUE,der));}
    static int[] metadata(byte[]der)throws Exception{
        var c=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        var key=c.getPublicKey();int algorithm,bits;
        if(key instanceof RSAPublicKey rsa){algorithm=4;bits=rsa.getModulus().bitLength();}
        else if(key instanceof ECPublicKey ec){algorithm=6;bits=ec.getParams().getCurve().getField().getFieldSize();}
        else throw new AssertionError("fixture public-key family");
        int signature=switch(c.getSigAlgOID()){
            case "1.2.840.113549.1.1.11"->5;
            case "1.2.840.113549.1.1.12"->6;
            case "1.2.840.10045.4.3.2"->14;
            default->throw new AssertionError("fixture issuer signature");
        };
        return new int[]{algorithm,bits,signature};
    }
    static byte[] content(byte[] encoded,int tag){
        require((encoded[0]&255)==tag,"DER tag");int first=encoded[1]&255,offset=2,length=first;
        if(first>=128){int count=first&127;require(count>=1&&count<=3,"DER width");length=0;for(int i=0;i<count;i++)length=(length<<8)|(encoded[offset++]&255);}
        require(offset+length==encoded.length,"DER size");return Arrays.copyOfRange(encoded,offset,encoded.length);
    }
    static List<byte[]> alternativeNames(X509Certificate c,String oid)throws Exception{
        byte[] extension=c.getExtensionValue(oid);if(extension==null)return List.of();byte[] seq=content(content(extension,4),0x30);List<byte[]> result=new ArrayList<>();
        for(int at=0;at<seq.length;){int end=at+2,first=seq[at+1]&255,len=first;if(first>=128){int width=first&127;require(width>=1&&width<=3,"GeneralName length");len=0;for(int j=0;j<width;j++)len=(len<<8)|(seq[end++]&255);}end+=len;require(end<=seq.length,"GeneralName bounds");result.add(Arrays.copyOfRange(seq,at,end));at=end;}return result;
    }
    static byte[] serial(X509Certificate c){byte[] value=c.getSerialNumber().toByteArray();require(value.length<128,"fixture serial size");byte[] der=new byte[value.length+2];der[0]=2;der[1]=(byte)value.length;System.arraycopy(value,0,der,2,value.length);return der;}
    static void names(Ttlv value,Tag distinguished,Tag alternative,byte[] expected,List<byte[]>alternatives){
        require(Arrays.equals(value.require(distinguished).bytesValue(),expected),"distinguished name DER");List<byte[]>found=value.children().stream().filter(n->n.tag()==alternative.code()).map(Ttlv::bytesValue).toList();require(found.size()==alternatives.size(),"alternative name count");for(int i=0;i<found.size();i++)require(Arrays.equals(found.get(i),alternatives.get(i)),"alternative name DER");
    }
    static void identity(KmipClient client,int code,String id,byte[]der)throws Exception{
        var c=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        var request=Requests.getAttributes().uniqueIdentifier(id);
        Tag[] tags={X_509_CERTIFICATE_IDENTIFIER,X_509_CERTIFICATE_SUBJECT,X_509_CERTIFICATE_ISSUER};
        String[] labels={"X.509 Certificate Identifier","X.509 Certificate Subject","X.509 Certificate Issuer"};
        if(code<20)for(int i=0;i<tags.length;i++)request.add(text(ATTRIBUTE_NAME,labels[i]));
        var p=client.call(request.build()).requirePayload();Map<Integer,Ttlv>values=new HashMap<>();List<Ttlv>direct=code>=20?p.require(ATTRIBUTES).children():List.of();
        if(code<20){for(var a:p.children())if(a.tag()==ATTRIBUTE.code()){require(a.child(ATTRIBUTE_INDEX).isEmpty(),"singleton identity index");for(int i=0;i<labels.length;i++)if(labels[i].equals(a.require(ATTRIBUTE_NAME).textValue()))values.put(tags[i].code(),a.require(ATTRIBUTE_VALUE));}}
        else for(var a:direct)values.put(a.tag(),a);
        require(Arrays.equals(values.get(X_509_CERTIFICATE_IDENTIFIER.code()).require(CERTIFICATE_SERIAL_NUMBER).bytesValue(),serial(c)),"full serial DER");
        require(Arrays.equals(values.get(X_509_CERTIFICATE_IDENTIFIER.code()).require(ISSUER_DISTINGUISHED_NAME).bytesValue(),c.getIssuerX500Principal().getEncoded()),"issuer identity DER");
        names(values.get(X_509_CERTIFICATE_ISSUER.code()),ISSUER_DISTINGUISHED_NAME,ISSUER_ALTERNATIVE_NAME,c.getIssuerX500Principal().getEncoded(),alternativeNames(c,"2.5.29.18"));
        byte[]subject=c.getSubjectX500Principal().getEncoded();if(subject.length==2&&subject[1]==0)subject=new byte[0];
        names(values.get(X_509_CERTIFICATE_SUBJECT.code()),SUBJECT_DISTINGUISHED_NAME,SUBJECT_ALTERNATIVE_NAME,subject,alternativeNames(c,"2.5.29.17"));
        if(code>=20){
            String[]oids={"2.5.4.3","2.5.4.10","2.5.4.11","1.2.840.113549.1.9.1","2.5.4.6","2.5.4.8","2.5.4.7","0.9.2342.19200300.100.1.1","2.5.4.5","2.5.4.12","0.9.2342.19200300.100.1.25","2.5.4.46"};
            Map<String,String>aliases=new HashMap<>();for(int i=0;i<oids.length;i++)aliases.put(oids[i],"A"+i);
            for(int side=0;side<2;side++){
                var principal=side==0?c.getSubjectX500Principal():c.getIssuerX500Principal();var parsed=new javax.naming.ldap.LdapName(principal.getName("RFC2253",aliases));
                for(int field=0;field<oids.length;field++){
                    List<String>expected=new ArrayList<>();for(var rdn:parsed.getRdns()){var attribute=rdn.toAttributes().get("A"+field);if(attribute!=null){var all=attribute.getAll();while(all.hasMore())expected.add((String)all.next());}}
                    int tag=0x420108+side*12+field;List<String>actual=direct.stream().filter(n->n.tag()==tag).map(Ttlv::textValue).sorted().toList();Collections.sort(expected);require(actual.equals(expected),"repeated name field "+tag);
                }
            }
        }
    }
    static void verify(KmipClient c,int code,String id,byte[]expected)throws Exception{
        identity(c,code,id,expected);
        byte[]der=c.get(id).requirePayload().require(CERTIFICATE).require(CERTIFICATE_VALUE).bytesValue();
        require(hash(der).equals(hash(expected)),"certificate bytes changed");
        var request=Requests.getAttributes().uniqueIdentifier(id);
        int[]tags={CERTIFICATE_TYPE.code(),CERTIFICATE_LENGTH.code(),CRYPTOGRAPHIC_ALGORITHM.code(),CRYPTOGRAPHIC_LENGTH.code(),DIGITAL_SIGNATURE_ALGORITHM.code()};
        for(int tag:tags)request.add(code<20?text(ATTRIBUTE_NAME,name(tag)):enumeration(ATTRIBUTE_REFERENCE,tag));
        var payload=c.call(request.build()).requirePayload();Map<Integer,Integer>observed=new HashMap<>();
        if(code<20){for(var a:payload.children())if(a.tag()==ATTRIBUTE.code()){
            require(a.child(ATTRIBUTE_INDEX).isEmpty(),"X509 metadata unexpectedly indexed");
            String attribute=a.require(ATTRIBUTE_NAME).textValue();
            for(int tag:tags)if(name(tag).equals(attribute))observed.put(tag,a.require(ATTRIBUTE_VALUE).intValue());
        }}else for(var a:payload.require(ATTRIBUTES).children())observed.put(a.tag(),a.intValue());
        int[]m=metadata(der);Map<Integer,Integer>wanted=Map.of(tags[0],1,tags[1],der.length,tags[2],m[0],tags[3],m[1],tags[4],m[2]);
        require(observed.equals(wanted),"certificate metadata differs from independent JCA observation: "+observed+" expected "+wanted);
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]),fixtures=Path.of(args[5]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{11,12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t";int count=0;
                if(create)for(String file:List.of("rich.der","grouped.der","empty.der")){
                    byte[]der=Files.readAllBytes(fixtures.resolve(file));int[]m=metadata(der);
                    String id=c.call(Requests.register().add(enumeration(OBJECT_TYPE,1),attrs(code,enumeration(CRYPTOGRAPHIC_ALGORITHM,m[0]),integer(CRYPTOGRAPHIC_LENGTH,m[1]),integer(CRYPTOGRAPHIC_USAGE_MASK,0),integer(CERTIFICATE_LENGTH,der.length)),certificate(der)).build()).uniqueIdentifier();
                    verify(c,code,id,der);
                    var invalid=c.execute(Requests.register().add(enumeration(OBJECT_TYPE,1),attrs(code,enumeration(CRYPTOGRAPHIC_ALGORITHM,m[0]),integer(CRYPTOGRAPHIC_LENGTH,m[1]),integer(CRYPTOGRAPHIC_USAGE_MASK,0),integer(CERTIFICATE_LENGTH,der.length+1)),certificate(der)).build());
                    require(invalid.status()==1&&Objects.equals(invalid.reason(),7),"conflicting certificate length accepted");
                    if(code>=14){var exported=c.call(Requests.export().uniqueIdentifier(id).build()).requirePayload();c.destroy(id);
                        c.call(Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true)).build());verify(c,code,id,der);}
                    rows.add(prefix+file+"\t"+id);count++;
                }else for(String row:saved)if(row.startsWith(prefix)){
                    String[]columns=row.split("\t");verify(c,code,columns[3],Files.readAllBytes(fixtures.resolve(columns[2])));count++;
                }
                require(count==3,"certificate manifest completeness");
                System.out.println("PASS released SDK certificate "+version+" "+transport+" "+args[3]+" "+count+" cases");
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
