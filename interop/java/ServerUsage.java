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
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Unrestricted is a versioned usage permission, never an override of other policy. */
public final class ServerUsage {
    static final int UNRESTRICTED=Enums.CryptographicUsageMask.UNRESTRICTED.code();
    static final byte[] KEY=HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c");
    static final byte[] DATA_VALUE="application data".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    static int observations;
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static Ttlv ok(KmipClient c,Request request)throws Exception{var r=c.call(request).requirePayload();observations++;return r;}
    static void denied(KmipClient c,Request request,int reason)throws Exception{var r=c.execute(request);require(r.status()==1&&Objects.equals(r.reason(),reason),"expected denial "+reason+" got "+r);observations++;}
    static Ttlv aes(){return structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(CRYPTOGRAPHIC_ALGORITHM,3),enumeration(BLOCK_CIPHER_MODE,1),enumeration(PADDING_METHOD,1));}
    static Ttlv hmac(){return structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(CRYPTOGRAPHIC_ALGORITHM,9));}
    static Ttlv usage(int total){return structure(USAGE_LIMITS,longInteger(USAGE_LIMITS_TOTAL,total),enumeration(USAGE_LIMITS_UNIT,2));}
    static String register(KmipClient c,boolean password,int mask,boolean limited)throws Exception{
        List<Ttlv> attrs=new ArrayList<>(List.of(integer(CRYPTOGRAPHIC_USAGE_MASK,mask)));
        if(limited)attrs.add(usage(password?2:3));
        if(!password)attrs.add(structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(BLOCK_CIPHER_MODE,13)));
        byte[] value=password?"password".getBytes(java.nio.charset.StandardCharsets.UTF_8):KEY;
        List<Ttlv> block=new ArrayList<>(List.of(enumeration(KEY_FORMAT_TYPE,1),integer(CRYPTOGRAPHIC_LENGTH,value.length*8),structure(KEY_VALUE,bytes(KEY_MATERIAL,value))));
        if(!password)block.add(enumeration(CRYPTOGRAPHIC_ALGORITHM,3));
        Ttlv object=password?structure(SECRET_DATA,enumeration(SECRET_DATA_TYPE,2),structure(KEY_BLOCK,block.toArray(Ttlv[]::new))):structure(SYMMETRIC_KEY,structure(KEY_BLOCK,block.toArray(Ttlv[]::new)));
        String id=ok(c,Requests.register().add(enumeration(OBJECT_TYPE,password?7:2),structure(ATTRIBUTES,attrs.toArray(Ttlv[]::new)),object).build()).require(UNIQUE_IDENTIFIER).textValue();
        ok(c,Requests.activate().uniqueIdentifier(id).build());return id;
    }
    static byte[] encrypt(KmipClient c,String id)throws Exception{
        var p=ok(c,Requests.encrypt().uniqueIdentifier(id).add(aes(),bytes(IV_COUNTER_NONCE,new byte[16]),bytes(DATA,DATA_VALUE)).build());
        require(id.equals(p.require(UNIQUE_IDENTIFIER).textValue()),"encryption identifier");return p.require(DATA).bytesValue();
    }
    static void destroy(KmipClient c,String id)throws Exception{
        ok(c,Requests.revoke().uniqueIdentifier(id).add(structure(REVOCATION_REASON,enumeration(REVOCATION_REASON_CODE,2))).build());
        ok(c,Requests.destroy().uniqueIdentifier(id).build());
    }
    static void verify(KmipClient c,int code,Path fixtures,Map<String,String> ids)throws Exception{
        String aesId=ids.get("aes");
        ok(c,Requests.check().uniqueIdentifier(aesId).add(integer(CRYPTOGRAPHIC_USAGE_MASK,4|8|16|32|128|256|512)).build());
        Cipher oracle=Cipher.getInstance("AES/CBC/NoPadding");oracle.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(KEY,"AES"),new IvParameterSpec(new byte[16]));
        byte[] ciphertext=encrypt(c,aesId);require(Arrays.equals(ciphertext,oracle.doFinal(DATA_VALUE)),"independent AES oracle");
        byte[] plain=ok(c,Requests.decrypt().uniqueIdentifier(aesId).add(aes(),bytes(IV_COUNTER_NONCE,new byte[16]),bytes(DATA,ciphertext)).build()).require(DATA).bytesValue();require(Arrays.equals(plain,DATA_VALUE),"decryption");
        Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(KEY,"HmacSHA256"));byte[] expected=mac.doFinal(DATA_VALUE);
        byte[] actual=ok(c,Requests.mac().uniqueIdentifier(aesId).add(hmac(),bytes(DATA,DATA_VALUE)).build()).require(MAC_DATA).bytesValue();require(Arrays.equals(actual,expected),"independent HMAC oracle");
        var valid=ok(c,Requests.macVerify().uniqueIdentifier(aesId).add(hmac(),bytes(DATA,DATA_VALUE),bytes(MAC_DATA,actual)).build());require(valid.require(VALIDITY_INDICATOR).intValue()==1,"MAC valid");
        byte[] wrong=actual.clone();wrong[0]^=1;
        require(ok(c,Requests.macVerify().uniqueIdentifier(aesId).add(hmac(),bytes(DATA,DATA_VALUE),bytes(MAC_DATA,wrong)).build()).require(VALIDITY_INDICATOR).intValue()==2,"MAC invalid");
        var initial=ok(c,Requests.mac().uniqueIdentifier(aesId).add(hmac(),bool(INIT_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(DATA_VALUE,0,7))).build());require(initial.child(MAC_DATA).isEmpty(),"nonfinal MAC");
        byte[] streamed=ok(c,Requests.mac().uniqueIdentifier(aesId).add(bytes(CORRELATION_VALUE,initial.require(CORRELATION_VALUE).bytesValue()),bool(FINAL_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(DATA_VALUE,7,DATA_VALUE.length))).build()).require(MAC_DATA).bytesValue();require(Arrays.equals(streamed,expected),"multipart HMAC");
        var mask=ok(c,Requests.getAttributes().uniqueIdentifier(aesId).add(enumeration(ATTRIBUTE_REFERENCE,CRYPTOGRAPHIC_USAGE_MASK.code())).build()).require(ATTRIBUTES).require(CRYPTOGRAPHIC_USAGE_MASK);require(mask.intValue()==UNRESTRICTED,"exact stored mask");
        var spec=structure(KEY_WRAPPING_SPECIFICATION,enumeration(WRAPPING_METHOD,1),enumeration(ENCODING_OPTION,1),structure(ENCRYPTION_KEY_INFORMATION,text(UNIQUE_IDENTIFIER,aesId),structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(BLOCK_CIPHER_MODE,13))));
        var wrapped=ok(c,Requests.get().uniqueIdentifier(aesId).add(spec).build()).require(SYMMETRIC_KEY);
        Cipher unwrap=Cipher.getInstance("AESWrap");unwrap.init(Cipher.DECRYPT_MODE,new SecretKeySpec(KEY,"AES"));require(Arrays.equals(unwrap.doFinal(wrapped.require(KEY_BLOCK).require(KEY_VALUE).bytesValue()),KEY),"JCA unwrap");
        String restored=ok(c,Requests.register().add(enumeration(OBJECT_TYPE,2),structure(ATTRIBUTES,integer(CRYPTOGRAPHIC_USAGE_MASK,0)),wrapped).build()).require(UNIQUE_IDENTIFIER).textValue();
        require(Arrays.equals(ok(c,Requests.get().uniqueIdentifier(restored).build()).require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue(),KEY),"server unwrap");
        ok(c,Requests.destroy().uniqueIdentifier(restored).build());
        Ttlv rsa=ServerCertificateVerify.parameters("RSA",false,code);byte[] signature=ok(c,Requests.sign().uniqueIdentifier(ids.get("private")).add(rsa,bytes(DATA,DATA_VALUE)).build()).require(SIGNATURE_DATA).bytesValue();
        var publicObject=ok(c,Requests.get().uniqueIdentifier(ids.get("public")).add(enumeration(KEY_FORMAT_TYPE,5)).build()).require(PUBLIC_KEY);
        PublicKey publicKey=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicObject.require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue()));
        Signature verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(publicKey);verifier.update(DATA_VALUE);require(verifier.verify(signature),"independent RSA oracle");
        require(ok(c,Requests.signatureVerify().uniqueIdentifier(ids.get("public")).add(rsa,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,signature)).build()).require(VALIDITY_INDICATOR).intValue()==1,"RSA verify");
        denied(c,Requests.sign().uniqueIdentifier(ids.get("public")).add(rsa,bytes(DATA,DATA_VALUE)).build(),8);
        byte[] ecSignature=ServerCertificateVerify.sign(ServerCertificateVerify.key(fixtures,"ec","EC"),"ECDSA",false,code);Ttlv ec=ServerCertificateVerify.parameters("ECDSA",false,code);
        require(ok(c,Requests.signatureVerify().uniqueIdentifier(ids.get("certificate")).add(ec,bytes(DATA,ServerCertificateVerify.DATA_VALUE),bytes(SIGNATURE_DATA,ecSignature)).build()).require(VALIDITY_INDICATOR).intValue()==1,"certificate verify");
        denied(c,Requests.signatureVerify().uniqueIdentifier(ids.get("purpose")).add(ec,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,ecSignature)).build(),0x29);
        denied(c,Requests.sign().uniqueIdentifier(ids.get("certificate")).add(ec,bytes(DATA,DATA_VALUE)).build(),8);
        ok(c,Requests.archive().uniqueIdentifier(aesId).build());denied(c,Requests.encrypt().uniqueIdentifier(aesId).add(aes(),bytes(IV_COUNTER_NONCE,new byte[16]),bytes(DATA,DATA_VALUE)).build(),13);ok(c,Requests.recover().uniqueIdentifier(aesId).build());
        String budget=register(c,false,UNRESTRICTED,true);ok(c,Requests.getUsageAllocation().uniqueIdentifier(budget).add(longInteger(USAGE_LIMITS_COUNT,1)).build());encrypt(c,budget);encrypt(c,budget);denied(c,Requests.encrypt().uniqueIdentifier(budget).add(aes(),bytes(IV_COUNTER_NONCE,new byte[16]),bytes(DATA,DATA_VALUE)).build(),12);destroy(c,budget);
        String password=register(c,true,UNRESTRICTED,true);ok(c,Requests.getUsageAllocation().uniqueIdentifier(password).add(longInteger(USAGE_LIMITS_COUNT,1)).build());
        Request derive=Requests.deriveKey().add(enumeration(OBJECT_TYPE,2),text(UNIQUE_IDENTIFIER,password),enumeration(DERIVATION_METHOD,1),structure(DERIVATION_PARAMETERS,structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(HASHING_ALGORITHM,6)),bytes(SALT,"12345678".getBytes(java.nio.charset.StandardCharsets.UTF_8)),integer(ITERATION_COUNT,2)),structure(ATTRIBUTES,enumeration(CRYPTOGRAPHIC_ALGORITHM,3),integer(CRYPTOGRAPHIC_LENGTH,128),integer(CRYPTOGRAPHIC_USAGE_MASK,0))).build();
        String derived=ok(c,derive).require(UNIQUE_IDENTIFIER).textValue();byte[] derivedValue=ok(c,Requests.get().uniqueIdentifier(derived).build()).require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue();
        var passwordSpec=new PBEKeySpec("password".toCharArray(),"12345678".getBytes(java.nio.charset.StandardCharsets.UTF_8),2,128);byte[] wanted=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(passwordSpec).getEncoded();passwordSpec.clearPassword();require(Arrays.equals(derivedValue,wanted),"independent PBKDF2 oracle");
        denied(c,derive,0x1a);ok(c,Requests.destroy().uniqueIdentifier(derived).build());destroy(c,password);
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]),fixtures=Path.of(args[5]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));List<String> rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            int start=observations;var v=ProtocolVersion.of(code/10,code%10);String prefix=code+"\t"+transport+"\t";Map<String,String> ids=new HashMap<>();
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,v)){
                if(create){
                    ids.put("aes",register(c,false,UNRESTRICTED,false));
                    var pair=ok(c,Requests.createKeyPair().add(structure(COMMON_ATTRIBUTES,enumeration(CRYPTOGRAPHIC_ALGORITHM,4),integer(CRYPTOGRAPHIC_LENGTH,2048),integer(CRYPTOGRAPHIC_USAGE_MASK,UNRESTRICTED))).build());
                    for(var entry:Map.of("private",PRIVATE_KEY_UNIQUE_IDENTIFIER,"public",PUBLIC_KEY_UNIQUE_IDENTIFIER).entrySet()){
                        String identifier=pair.require(entry.getValue()).textValue();ids.put(entry.getKey(),identifier);ok(c,Requests.activate().uniqueIdentifier(identifier).build());
                    }
                    ids.put("certificate",ServerCertificateVerify.register(c,code,fixtures,"ec",6,UNRESTRICTED));observations+=2;
                    ids.put("purpose",ServerCertificateVerify.register(c,code,fixtures,"enc",6,UNRESTRICTED));observations+=2;
                    for(var entry:ids.entrySet())rows.add(prefix+entry.getKey()+"\t"+entry.getValue());
                }else for(String row:saved)if(row.startsWith(prefix)){String[]col=row.split("\t");require(ids.put(col[2],col[3])==null,"duplicate manifest");}
                require(ids.size()==5,"manifest completeness");verify(c,code,fixtures,ids);
            }
            System.out.println("PASS\t"+code+"\t"+transport+"\t"+args[3]+"\t"+(observations-start));
        }
        if(create)Files.write(manifest,rows);
    }
}
