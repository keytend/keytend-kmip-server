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
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Versioned PGP blobs through the unchanged released SDK; JCE wrapping oracle. */
public final class ServerPgp {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static String hash(byte[]value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    static Ttlv attrs(int code,Ttlv...values){
        if(code>=20)return structure(ATTRIBUTES,values);
        List<Ttlv> result=new ArrayList<>();
        for(var v:values)result.add(structure(ATTRIBUTE,text(ATTRIBUTE_NAME,switch(Tag.fromCode(v.tag()).orElseThrow()){
            case CRYPTOGRAPHIC_USAGE_MASK->"Cryptographic Usage Mask";
            case CRYPTOGRAPHIC_PARAMETERS->"Cryptographic Parameters";
            case DIGITAL_SIGNATURE_ALGORITHM->"Digital Signature Algorithm";
            default->throw new IllegalArgumentException("attribute");
        }),v.retag(ATTRIBUTE_VALUE)));
        return structure(TEMPLATE_ATTRIBUTE,result.toArray(Ttlv[]::new));
    }
    static Ttlv object(int version,int format,byte[]data){return structure(PGP_KEY,integer(PGP_KEY_VERSION,version),
        structure(KEY_BLOCK,enumeration(KEY_FORMAT_TYPE,format),structure(KEY_VALUE,bytes(KEY_MATERIAL,data)),
            enumeration(CRYPTOGRAPHIC_ALGORITHM,4),integer(CRYPTOGRAPHIC_LENGTH,2048)));}
    static void verify(KmipClient c,String id,int pgp,String digest)throws Exception {
        var metadata=c.call(Requests.getAttributes().uniqueIdentifier(id).build()).requirePayload();
        if(c.version().code()>=20){
            var attributes=metadata.require(ATTRIBUTES);
            require(attributes.require(DIGITAL_SIGNATURE_ALGORITHM).type()==Ttlv.Type.ENUMERATION&&attributes.require(DIGITAL_SIGNATURE_ALGORITHM).intValue()==7,"signature metadata changed");
            require(attributes.require(CRYPTOGRAPHIC_USAGE_MASK).intValue()==0,"usage metadata changed");
        }else{
            int matches=0;
            for(var attribute:metadata.children())if(attribute.tag()==ATTRIBUTE.code()&&attribute.require(ATTRIBUTE_NAME).textValue().equals("Digital Signature Algorithm")){
                require(attribute.require(ATTRIBUTE_VALUE).intValue()==7&&attribute.require(ATTRIBUTE_INDEX).intValue()==0,"legacy signature metadata changed");matches++;
            }
            require(matches==1,"missing legacy signature metadata");
        }
        for(int format:new int[]{1,2}){
            var value=c.call(Requests.get().uniqueIdentifier(id).add(enumeration(KEY_FORMAT_TYPE,format)).build()).requirePayload().require(PGP_KEY);
            require(value.require(PGP_KEY_VERSION).type()==Ttlv.Type.INTEGER&&value.require(PGP_KEY_VERSION).intValue()==pgp,"PGP version changed");
            var block=value.require(KEY_BLOCK);
            require(block.require(KEY_FORMAT_TYPE).intValue()==format,"format conversion");
            require(block.require(CRYPTOGRAPHIC_ALGORITHM).intValue()==4&&block.require(CRYPTOGRAPHIC_LENGTH).intValue()==2048,"primary key metadata");
            require(hash(block.require(KEY_VALUE).require(KEY_MATERIAL).bytesValue()).equals(digest),"PGP bytes changed");
        }
    }
    static String register(KmipClient c,int code,Ttlv value)throws Exception{return c.call(Requests.register().add(enumeration(OBJECT_TYPE,9),attrs(code,integer(CRYPTOGRAPHIC_USAGE_MASK,0),enumeration(DIGITAL_SIGNATURE_ALGORITHM,7)),value).build()).requirePayload().require(UNIQUE_IDENTIFIER).textValue();}
    static String kek(KmipClient c,int code,byte[]key)throws Exception{
        var cp=structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(BLOCK_CIPHER_MODE,12));
        var object=structure(SYMMETRIC_KEY,structure(KEY_BLOCK,enumeration(KEY_FORMAT_TYPE,1),structure(KEY_VALUE,bytes(KEY_MATERIAL,key)),enumeration(CRYPTOGRAPHIC_ALGORITHM,3),integer(CRYPTOGRAPHIC_LENGTH,256)));
        String id=c.call(Requests.register().add(enumeration(OBJECT_TYPE,2),attrs(code,integer(CRYPTOGRAPHIC_USAGE_MASK,48),cp),object).build()).requirePayload().require(UNIQUE_IDENTIFIER).textValue();
        c.activate(id);return id;
    }
    public static void main(String[]args)throws Exception {
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]),fixtures=Path.of(args[5]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t";int cases=0;
                if(create){
                    byte[]key=new byte[32];Arrays.fill(key,(byte)0x72);String wrapping=kek(c,code,key);
                    for(String name:List.of("v3_public","v4_public","v4_private"))for(int format:new int[]{1,2}){
                        int pgp=name.startsWith("v3")?3:4;byte[]data=Files.readAllBytes(fixtures.resolve(name+".asc"));String digest=hash(data);
                        String id=register(c,code,object(pgp,format,data));verify(c,id,pgp,digest);
                        var spec=structure(KEY_WRAPPING_SPECIFICATION,enumeration(WRAPPING_METHOD,1),structure(ENCRYPTION_KEY_INFORMATION,text(UNIQUE_IDENTIFIER,wrapping)),enumeration(ENCODING_OPTION,1));
                        var wrapped=c.call(Requests.get().uniqueIdentifier(id).add(spec).build()).requirePayload().require(PGP_KEY);
                        var cipher=Cipher.getInstance("AES/KWP/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"));
                        require(Arrays.equals(cipher.doFinal(wrapped.require(KEY_BLOCK).require(KEY_VALUE).bytesValue()),data),"independent JCE unwrap");
                        String copy=register(c,code,wrapped);verify(c,copy,pgp,digest);
                        if(code>=14){var exported=c.call(Requests.export().uniqueIdentifier(id).build()).requirePayload();c.destroy(id);
                            c.call(Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true)).build());verify(c,id,pgp,digest);}
                        rows.add(prefix+pgp+"\t"+format+"\t"+id+"\t"+digest+"\t"+copy);cases++;
                    }
                }else for(String row:saved)if(row.startsWith(prefix)){
                    String[]v=row.split("\t");verify(c,v[4],Integer.parseInt(v[2]),v[5]);verify(c,v[6],Integer.parseInt(v[2]),v[5]);cases++;
                }
                System.out.println("PASS released SDK PGP "+version+" "+transport+" "+args[3]+" "+cases+" cases");
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
