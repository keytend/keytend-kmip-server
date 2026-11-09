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
import java.security.MessageDigest;
import java.util.*;

/** Released SDK PGP Certificate Type 2, separate from the PGP Key object. */
public final class ServerPgpCertificate {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static String hash(byte[]data)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));}
    static void verify(KmipClient client,int code,String id,byte[]bytes,int algorithm,int bits,int signature)throws Exception{
        var result=client.get(id).requirePayload();require(result.require(UNIQUE_IDENTIFIER).textValue().equals(id),"identity");
        var cert=result.require(CERTIFICATE);require(cert.require(CERTIFICATE_TYPE).intValue()==2,"certificate type");require(hash(cert.require(CERTIFICATE_VALUE).bytesValue()).equals(hash(bytes)),"certificate bytes");
        var request=Requests.getAttributes().uniqueIdentifier(id);
        var wanted=Map.of(CERTIFICATE_TYPE.code(),2,CERTIFICATE_LENGTH.code(),bytes.length,CRYPTOGRAPHIC_ALGORITHM.code(),algorithm,CRYPTOGRAPHIC_LENGTH.code(),bits,DIGITAL_SIGNATURE_ALGORITHM.code(),signature);
        var names=Map.of(CERTIFICATE_TYPE.code(),"Certificate Type",CERTIFICATE_LENGTH.code(),"Certificate Length",CRYPTOGRAPHIC_ALGORITHM.code(),"Cryptographic Algorithm",CRYPTOGRAPHIC_LENGTH.code(),"Cryptographic Length",DIGITAL_SIGNATURE_ALGORITHM.code(),"Digital Signature Algorithm");
        for(int tag:wanted.keySet())request.add(code<20?text(ATTRIBUTE_NAME,names.get(tag)):enumeration(ATTRIBUTE_REFERENCE,tag));
        var attrs=client.call(request.build()).requirePayload();Map<Integer,Integer>actual=new HashMap<>();
        if(code<20){for(var a:attrs.children())if(a.tag()==ATTRIBUTE.code()){
            String name=a.require(ATTRIBUTE_NAME).textValue();for(var entry:names.entrySet())if(entry.getValue().equals(name)){
                if(entry.getKey()==DIGITAL_SIGNATURE_ALGORITHM.code())require(a.require(ATTRIBUTE_INDEX).intValue()==0,"PGP signature index");
                actual.put(entry.getKey(),a.require(ATTRIBUTE_VALUE).intValue());
            }
        }}else for(var a:attrs.require(ATTRIBUTES).children())actual.put(a.tag(),a.intValue());
        require(actual.equals(wanted),"metadata "+actual+" expected "+wanted);
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]),fixtures=Path.of(args[5]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest),descriptions=Files.readAllLines(fixtures.resolve("metadata.tsv"));
        for(int code:new int[]{11,12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var client=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t";int count=0;
                if(create)for(String row:descriptions){String[]m=row.split("\t");String name=m[0];int algorithm=Integer.parseInt(m[1]),bits=Integer.parseInt(m[2]),signature=Integer.parseInt(m[3]);
                    for(String format:List.of("asc","bin")){
                        String file=name+"."+format;byte[]data=Files.readAllBytes(fixtures.resolve(file));
                        String id=client.register(ManagedObjects.certificate(Enums.CertificateType.PGP,data),Attributes.attribute("Cryptographic Algorithm",enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm)),Attributes.length(bits),Attributes.usage(),Attributes.attribute("Certificate Length",integer(CERTIFICATE_LENGTH,data.length)));
                        verify(client,code,id,data,algorithm,bits,signature);
                        if(code>=14){var exported=client.call(Requests.export().uniqueIdentifier(id).build()).requirePayload();client.destroy(id);client.call(Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true)).build());verify(client,code,id,data,algorithm,bits,signature);}
                        var unsupported=client.execute(Requests.validate().uniqueIdentifier(id).build());require(unsupported.status()==1&&Objects.equals(unsupported.reason(),8),"PGP trust capability");
                        rows.add(prefix+file+"\t"+id+"\t"+algorithm+"\t"+bits+"\t"+signature);count++;
                    }
                }else for(String row:saved)if(row.startsWith(prefix)){
                    String[]m=row.split("\t");verify(client,code,m[3],Files.readAllBytes(fixtures.resolve(m[2])),Integer.parseInt(m[4]),Integer.parseInt(m[5]),Integer.parseInt(m[6]));count++;
                }
                require(count==descriptions.size()*2,"complete fixture matrix");System.out.println("PASS released SDK PGP certificate "+version+" "+transport+" "+args[3]+" "+count+" cases");
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
