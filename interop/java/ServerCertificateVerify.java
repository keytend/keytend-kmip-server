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
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

/** Application signatures using the unchanged release and independent JCA keys. */
public final class ServerCertificateVerify {
    static final byte[] DATA_VALUE="independent JCA application signature".getBytes(StandardCharsets.UTF_8);
    static int results,continuations,denials;
    static void require(boolean value,String message){if(!value)throw new AssertionError(message);}
    static X509Certificate cert(Path directory,String name)throws Exception{
        return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(directory.resolve(name+".der"))));
    }
    static PrivateKey key(Path directory,String name,String family)throws Exception{
        return KeyFactory.getInstance(family).generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve(name+".pk8"))));
    }
    static Signature signature(String family,boolean pss,int code)throws Exception{
        Signature s=Signature.getInstance(pss?"RSASSA-PSS":"SHA256with"+family);
        if(pss)s.setParameter(new PSSParameterSpec("SHA-256","MGF1",code>=14?MGF1ParameterSpec.SHA256:MGF1ParameterSpec.SHA1,code>=14?32:20,1));
        return s;
    }
    static byte[] sign(PrivateKey key,String family,boolean pss,int code)throws Exception{
        Signature s=signature(family,pss,code);s.initSign(key);s.update(DATA_VALUE);return s.sign();
    }
    static void oracle(PublicKey key,String family,boolean pss,int code,byte[] data,byte[] sig,boolean expected)throws Exception{
        Signature s=signature(family,pss,code);s.initVerify(key);s.update(data);require(s.verify(sig)==expected,"JCA oracle");
    }
    static Ttlv parameters(String family,boolean pss,int code){
        List<Ttlv> p=new ArrayList<>();p.add(enumeration(CRYPTOGRAPHIC_ALGORITHM,family.equals("RSA")?4:family.equals("DSA")?5:6));
        p.add(enumeration(HASHING_ALGORITHM,6));
        if(family.equals("RSA")){
            p.add(enumeration(PADDING_METHOD,pss?10:8));
            if(pss&&code>=14){p.add(enumeration(MASK_GENERATOR,1));p.add(enumeration(MASK_GENERATOR_HASHING_ALGORITHM,6));p.add(integer(SALT_LENGTH,32));}
        }else if(family.equals("DSA"))p.add(enumeration(DIGITAL_SIGNATURE_ALGORITHM,11));
        return structure(CRYPTOGRAPHIC_PARAMETERS,p.toArray(Ttlv[]::new));
    }
    static void outcome(KmipClient c,String id,int expected,Ttlv...fields)throws Exception{
        var p=c.call(Requests.signatureVerify().uniqueIdentifier(id).add(fields).build()).requirePayload();
        require(id.equals(p.require(UNIQUE_IDENTIFIER).textValue()),"original certificate identifier");
        require(p.require(VALIDITY_INDICATOR).intValue()==expected,"signature validity: expected "+expected+" got "+p.require(VALIDITY_INDICATOR).intValue());results++;
    }
    static void deny(KmipClient c,String id,int reason,Ttlv...fields)throws Exception{
        var r=c.execute(Requests.signatureVerify().uniqueIdentifier(id).add(fields).build());
        require(r.status()==1&&Objects.equals(r.reason(),reason),"expected role denial "+reason+" got "+r);denials++;
    }
    static Ttlv attributes(int code,int algorithm,int bits,int length,int usage){
        Ttlv[] values={enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm),integer(CRYPTOGRAPHIC_LENGTH,bits),integer(CERTIFICATE_LENGTH,length),integer(CRYPTOGRAPHIC_USAGE_MASK,usage)};
        if(code>=20)return structure(ATTRIBUTES,values);
        String[] names={"Cryptographic Algorithm","Cryptographic Length","Certificate Length","Cryptographic Usage Mask"};
        List<Ttlv> attrs=new ArrayList<>();for(int i=0;i<values.length;i++)attrs.add(structure(ATTRIBUTE,text(ATTRIBUTE_NAME,names[i]),values[i].retag(ATTRIBUTE_VALUE)));
        return structure(TEMPLATE_ATTRIBUTE,attrs.toArray(Ttlv[]::new));
    }
    static String register(KmipClient c,int code,Path directory,String fixture,int purpose,int usage)throws Exception{
        byte[] der=Files.readAllBytes(directory.resolve(fixture+".der"));var key=cert(directory,fixture).getPublicKey();
        int algorithm=key instanceof RSAPublicKey?4:key instanceof DSAPublicKey?5:purpose;
        int bits=key instanceof RSAPublicKey k?k.getModulus().bitLength():key instanceof DSAPublicKey k?k.getParams().getP().bitLength():((ECPublicKey)key).getParams().getCurve().getField().getFieldSize();
        String id=c.call(Requests.register().add(enumeration(OBJECT_TYPE,1),attributes(code,algorithm,bits,der.length,usage),structure(CERTIFICATE,enumeration(CERTIFICATE_TYPE,1),bytes(CERTIFICATE_VALUE,der))).build()).uniqueIdentifier();
        c.activate(id);return id;
    }
    static final Set<String> clientFindings=new TreeSet<>();
    static void mechanism(KmipClient c,int code,Path directory,String id,String fixture,String family,boolean pss)throws Exception{
        var certificate=cert(directory,fixture);byte[] sig=sign(key(directory,fixture,family.equals("ECDSA")?"EC":family),family,pss,code);Ttlv cp=parameters(family,pss,code);
        oracle(certificate.getPublicKey(),family,pss,code,DATA_VALUE,sig,true);
        byte[] wrong=DATA_VALUE.clone();wrong[0]^=1;oracle(certificate.getPublicKey(),family,pss,code,wrong,sig,false);
        outcome(c,id,1,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,sig));
        outcome(c,id,2,cp,bytes(DATA,wrong),bytes(SIGNATURE_DATA,sig));
        if(code>=14)outcome(c,id,1,cp,bytes(DIGESTED_DATA,MessageDigest.getInstance("SHA-256").digest(DATA_VALUE)),bytes(SIGNATURE_DATA,sig));
        if(code>=13&&code<20){
            // The server omits Validity Indicator from a non-final multi-part response in every
            // edition (docs/crypto-operations.md#multipart-operations), as 2.x Table 338 allows ("No for multi-part"). The 1.3/1.4
            // tables mark it REQUIRED without that exception, and keytend-kmip enforces them, so
            // the client refuses the non-final response (CLIENT-MULTIPART-001); the continuation
            // is exercised from 2.0.
            try{c.call(Requests.signatureVerify().uniqueIdentifier(id).add(cp,bool(INIT_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(DATA_VALUE,0,7))).build());
                throw new AssertionError("Reevaluate CLIENT-MULTIPART-001: the non-final 1.x response was accepted");}
            catch(dev.keytend.kmip.client.ProtocolException expected){
                require(String.valueOf(expected.getMessage()).contains("ValidityIndicator"),"unexpected 1.x multi-part refusal: "+expected);clientFindings.add("CLIENT-MULTIPART-001");}
        }
        if(code>=20){
            var p=c.call(Requests.signatureVerify().uniqueIdentifier(id).add(cp,bool(INIT_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(DATA_VALUE,0,7))).build()).requirePayload();
            require(id.equals(p.require(UNIQUE_IDENTIFIER).textValue()),"initial identifier");require(p.child(VALIDITY_INDICATOR).isEmpty(),"nonfinal validity");continuations++;
            outcome(c,id,1,bytes(CORRELATION_VALUE,p.require(CORRELATION_VALUE).bytesValue()),bool(FINAL_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(DATA_VALUE,7,DATA_VALUE.length)),bytes(SIGNATURE_DATA,sig));
        }
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]),directory=Path.of(args[5]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String> rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            int start=results,continued=continuations,denied=denials;var v=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,v)){
                Map<String,String> ids=new HashMap<>();String prefix=code+"\t"+transport+"\t";
                // In 1.0-1.4 the server bounds the usage mask by the certificate's X.509 Key Usage
                // (1.4 Table 96): contentCommitment maps to Content Commitment and keyEncipherment to
                // Wrap/Unwrap Key, not Verify, so Register itself refuses those two certificates for
                // verification there (Invalid Field); from 2.0 they register and Signature Verify decides.
                List<String> fixtures=code>=20?List.of("rsa","ec","dsa","nonrep","enc","restricted","agreement"):List.of("rsa","ec","dsa","restricted","agreement");
                if(create&&code<20)for(String fixture:List.of("nonrep","enc")){
                    byte[] der=Files.readAllBytes(directory.resolve(fixture+".der"));var key=(ECPublicKey)cert(directory,fixture).getPublicKey();
                    var refused=c.execute(Requests.register().add(enumeration(OBJECT_TYPE,1),attributes(code,6,key.getParams().getCurve().getField().getFieldSize(),der.length,2),structure(CERTIFICATE,enumeration(CERTIFICATE_TYPE,1),bytes(CERTIFICATE_VALUE,der))).build());
                    require(!refused.successful()&&Objects.equals(refused.reason(),7),"Key Usage bound not applied at Register: "+fixture);denials++;
                }
                if(create)for(String fixture:fixtures){
                    String source=Set.of("restricted","agreement").contains(fixture)?"ec":fixture;
                    String id=register(c,code,directory,source,fixture.equals("agreement")?14:6,fixture.equals("restricted")?0:2);
                    ids.put(fixture,id);rows.add(prefix+fixture+"\t"+id);
                }else for(String row:saved)if(row.startsWith(prefix)){String[]col=row.split("\t");require(ids.put(col[2],col[3])==null,"duplicate manifest entry");}
                require(ids.size()==fixtures.size(),"manifest completeness");
                mechanism(c,code,directory,ids.get("rsa"),"rsa","RSA",false);
                mechanism(c,code,directory,ids.get("rsa"),"rsa","RSA",true);
                mechanism(c,code,directory,ids.get("ec"),"ec","ECDSA",false);
                mechanism(c,code,directory,ids.get("dsa"),"dsa","DSA",false);
                if(code>=20)mechanism(c,code,directory,ids.get("nonrep"),"nonrep","ECDSA",false);
                Ttlv cp=parameters("ECDSA",false,code);byte[] sig=sign(key(directory,"ec","EC"),"ECDSA",false,code);
                if(code>=20)deny(c,ids.get("enc"),0x29,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,sig));
                deny(c,ids.get("restricted"),code>=20?0x29:12,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,sig));
                deny(c,ids.get("agreement"),8,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,sig));
                byte[] other=sign(key(directory,"other","EC"),"ECDSA",false,code);oracle(cert(directory,"ec").getPublicKey(),"ECDSA",false,code,DATA_VALUE,other,false);
                outcome(c,ids.get("ec"),2,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,other));
                outcome(c,ids.get("ec"),2,cp,bytes(DATA,DATA_VALUE),bytes(SIGNATURE_DATA,new byte[]{1,2,3}));
                for(var entry:ids.entrySet()){
                    String source=Set.of("restricted","agreement").contains(entry.getKey())?"ec":entry.getKey();
                    var p=c.get(entry.getValue()).requirePayload();require(p.require(OBJECT_TYPE).intValue()==1,"certificate object type changed");
                    require(Arrays.equals(p.require(CERTIFICATE).require(CERTIFICATE_VALUE).bytesValue(),Files.readAllBytes(directory.resolve(source+".der"))),"certificate DER changed");
                }
            }
            System.out.println("PASS\t"+code+"\t"+transport+"\t"+args[3]+"\t"+(results-start)+"\t"+(continuations-continued)+"\t"+(denials-denied));
        }
        if(create)Files.write(manifest,rows);
    }
}
