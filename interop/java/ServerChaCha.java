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
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Unchanged released SDK transport plus independent SunJCE cipher oracles. */
public final class ServerChaCha {
    static final byte[] KEY=new byte[32], INPUT=new byte[129], AAD=new byte[]{3,1,4,1,5,9};
    static {for(int i=0;i<KEY.length;i++)KEY[i]=(byte)i;for(int i=0;i<INPUT.length;i++)INPUT[i]=(byte)(i*7);}
    static int observations;
    static void require(boolean b,String message){if(!b)throw new AssertionError(message);}
    static Ttlv ok(KmipClient c,Request request)throws Exception{Ttlv p=c.call(request).requirePayload();observations++;return p;}
    static void denied(KmipClient c,Request request,int expected)throws Exception{var r=c.execute(request);require(r.status()==1&&Objects.equals(r.reason(),expected),"denial: "+r);observations++;}
    static Ttlv params(int algorithm,boolean random){
        List<Ttlv> fields=new ArrayList<>();
        fields.add(enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm));
        if(algorithm==30){fields.add(enumeration(BLOCK_CIPHER_MODE,18));fields.add(integer(TAG_LENGTH,16));}
        if(random)fields.add(bool(RANDOM_IV,true));return structure(CRYPTOGRAPHIC_PARAMETERS,fields.toArray(Ttlv[]::new));
    }
    static String register(KmipClient c,int algorithm)throws Exception{
        Ttlv object=structure(SYMMETRIC_KEY,structure(KEY_BLOCK,enumeration(KEY_FORMAT_TYPE,1),enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm),integer(CRYPTOGRAPHIC_LENGTH,256),structure(KEY_VALUE,bytes(KEY_MATERIAL,KEY))));
        String id=ok(c,Requests.register().template(Attributes.usage(Enums.CryptographicUsageMask.ENCRYPT,Enums.CryptographicUsageMask.DECRYPT),Attributes.attribute("Cryptographic Parameters",params(algorithm,false))).add(enumeration(OBJECT_TYPE,2),object).build()).require(UNIQUE_IDENTIFIER).textValue();
        ok(c,Requests.activate().uniqueIdentifier(id).build());return id;
    }
    static byte[] oracle(int algorithm,byte[] nonce,byte[] data)throws Exception{
        Cipher cipher=Cipher.getInstance(algorithm==30?"ChaCha20-Poly1305":"ChaCha20","SunJCE");
        if(algorithm==30){cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(KEY,"ChaCha20"),new IvParameterSpec(nonce));cipher.updateAAD(AAD);}
        else {byte[] ietf=nonce;if(nonce.length==8){ietf=new byte[12];System.arraycopy(nonce,0,ietf,4,8);}cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(KEY,"ChaCha20"),new ChaCha20ParameterSpec(ietf,0));}
        return cipher.doFinal(data);
    }
    static Request request(int op,String id,int algorithm,byte[] nonce,byte[] data,byte[] tag,byte[] token,boolean init,boolean last){
        var b=(op==31?Requests.encrypt():Requests.decrypt()).uniqueIdentifier(id);
        if(token==null){b.add(params(algorithm,false),bytes(IV_COUNTER_NONCE,nonce));if(algorithm==30){b.add(bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,AAD));if(tag!=null)b.add(bytes(AUTHENTICATED_ENCRYPTION_TAG,tag));}}
        else b.add(bytes(CORRELATION_VALUE,token));
        b.add(bytes(DATA,data));if(init)b.add(bool(INIT_INDICATOR,true));if(last)b.add(bool(FINAL_INDICATOR,true));return b.build();
    }
    static byte[] data(Ttlv p){return p.child(DATA).map(Ttlv::bytesValue).orElseGet(()->new byte[0]);}
    static byte[] concat(byte[] a,byte[] b){byte[] out=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,out,a.length,b.length);return out;}
    static void verify(KmipClient c,String id,int algorithm,int nonceLength)throws Exception{
        byte[] nonce=new byte[nonceLength];for(int i=0;i<nonce.length;i++)nonce[i]=(byte)(i+9);
        byte[] expected=oracle(algorithm,nonce,INPUT),tag=algorithm==30?Arrays.copyOfRange(expected,INPUT.length,expected.length):null;
        byte[] cipher=Arrays.copyOf(expected,INPUT.length);
        Ttlv encrypted=ok(c,request(31,id,algorithm,nonce,INPUT,null,null,false,false));require(Arrays.equals(data(encrypted),cipher),"JCA ciphertext");
        if(algorithm==30)require(Arrays.equals(encrypted.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue(),tag),"JCA tag");
        require(Arrays.equals(data(ok(c,request(32,id,algorithm,nonce,cipher,tag,null,false,false))),INPUT),"JCA decrypt");
        Ttlv first=ok(c,request(31,id,algorithm,nonce,Arrays.copyOfRange(INPUT,0,17),null,null,true,false));
        Ttlv last=ok(c,request(31,id,algorithm,null,Arrays.copyOfRange(INPUT,17,INPUT.length),null,first.require(CORRELATION_VALUE).bytesValue(),false,true));
        require(Arrays.equals(concat(data(first),data(last)),cipher),"stream JCA ciphertext");
        if(algorithm==30)require(Arrays.equals(last.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue(),tag),"stream JCA tag");
        first=ok(c,request(32,id,algorithm,nonce,Arrays.copyOfRange(cipher,0,17),tag,null,true,false));
        if(algorithm==30)require(data(first).length==0,"unchecked plaintext prefix");
        last=ok(c,request(32,id,algorithm,null,Arrays.copyOfRange(cipher,17,cipher.length),null,first.require(CORRELATION_VALUE).bytesValue(),false,true));
        require(Arrays.equals(concat(data(first),data(last)),INPUT),"stream plaintext");
        var generatedRequest=Requests.encrypt().uniqueIdentifier(id).add(params(algorithm,true),bytes(DATA,INPUT));
        if(algorithm==30)generatedRequest.add(bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,AAD));
        Ttlv generated=ok(c,generatedRequest.build());
        byte[] generatedNonce=generated.require(IV_COUNTER_NONCE).bytesValue();require(generatedNonce.length==12,"generated nonce length");
        byte[] generatedExpected=oracle(algorithm,generatedNonce,INPUT);require(Arrays.equals(data(generated),Arrays.copyOf(generatedExpected,INPUT.length)),"generated nonce JCA bytes");
        if(algorithm==30){
            require(Arrays.equals(generated.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue(),Arrays.copyOfRange(generatedExpected,INPUT.length,generatedExpected.length)),"generated tag");
            byte[] bad=tag.clone();bad[0]^=1;
            denied(c,request(32,id,algorithm,nonce,cipher,bad,null,false,false),10);
            String temporary=register(c,algorithm);
            try {
                first=ok(c,request(32,temporary,algorithm,nonce,Arrays.copyOfRange(cipher,0,17),bad,null,true,false));require(data(first).length==0,"invalid tag prefix");
                denied(c,request(32,temporary,algorithm,null,Arrays.copyOfRange(cipher,17,cipher.length),null,first.require(CORRELATION_VALUE).bytesValue(),false,true),10);
            } finally {
                ok(c,Requests.revoke().uniqueIdentifier(temporary).add(structure(REVOCATION_REASON,enumeration(REVOCATION_REASON_CODE,1))).build());
                ok(c,Requests.destroy().uniqueIdentifier(temporary).build());
            }
        }
    }
    public static void main(String[] args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String> saved=create?new ArrayList<>():Files.readAllLines(manifest);
        for(int code:new int[]{14,20,21,30})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);int start=observations;
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var client=new KmipClient(wire,version)){
                for(int algorithm:new int[]{28,30}){
                    String prefix=code+"\t"+transport+"\t"+algorithm+"\t",id;
                    if(create){id=register(client,algorithm);saved.add(prefix+id);}
                    else id=saved.stream().filter(row->row.startsWith(prefix)).findFirst().orElseThrow().substring(prefix.length());
                    if(algorithm==28)verify(client,id,algorithm,8);verify(client,id,algorithm,12);
                }
            }
            System.out.println("PASS\t"+code+"\t"+transport+"\t"+(observations-start));
        }
        if(create)Files.write(manifest,saved);
    }
}
