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
public final class ServerCertificate {
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
    static void verify(KmipClient c,int code,String id,byte[]expected)throws Exception{
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
                if(create)for(String file:List.of("rsa.der","ec.der","mixed.der")){
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
