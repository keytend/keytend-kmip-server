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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Published SDK wire execution; independent SunJCE HMAC and RFC 4493 CMAC values. */
public final class ServerMac {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static Ttlv cp(int algorithm){return structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm));}
    static Ttlv cmac(){return structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(CRYPTOGRAPHIC_ALGORITHM,3),enumeration(BLOCK_CIPHER_MODE,7));}
    static byte[] message(){byte[] data=new byte[521];for(int i=0;i<data.length;i++)data[i]=(byte)i;return data;}
    static byte[] hmac(int algorithm,byte[]key,byte[]data)throws Exception {
        String name=switch(algorithm){case 7->"HmacSHA1";case 8->"HmacSHA224";case 9->"HmacSHA256";case 10->"HmacSHA384";case 11->"HmacSHA512";case 12->"HmacMD5";default->"HmacSHA3-"+switch(algorithm){case 35->224;case 36->256;case 37->384;case 38->512;default->throw new AssertionError();};};
        var mac=Mac.getInstance(name,"SunJCE");mac.init(new SecretKeySpec(key,name));return mac.doFinal(data);
    }
    static Ttlv attrs(ProtocolVersion version,Ttlv...attributes){
        if(version.code()>=20)return structure(ATTRIBUTES,attributes);
        return structure(TEMPLATE_ATTRIBUTE,Arrays.stream(attributes).map(a->structure(ATTRIBUTE,text(ATTRIBUTE_NAME,a.tag()==CRYPTOGRAPHIC_PARAMETERS.code()?"Cryptographic Parameters":"Cryptographic Usage Mask"),a.retag(ATTRIBUTE_VALUE))).toArray(Ttlv[]::new));
    }
    static String register(KmipClient c,ProtocolVersion v,int algorithm,byte[]key,boolean stored)throws Exception {
        var fields=new ArrayList<Ttlv>();fields.add(integer(CRYPTOGRAPHIC_USAGE_MASK,0x180));if(stored)fields.add(cp(9));
        String id=c.call(Requests.register().add(enumeration(OBJECT_TYPE,2),attrs(v,fields.toArray(Ttlv[]::new)),structure(SYMMETRIC_KEY,structure(KEY_BLOCK,enumeration(KEY_FORMAT_TYPE,1),enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm),integer(CRYPTOGRAPHIC_LENGTH,key.length*8),structure(KEY_VALUE,bytes(KEY_MATERIAL,key))))).build()).requirePayload().require(UNIQUE_IDENTIFIER).textValue();
        c.activate(id);return id;
    }
    static byte[] mac(KmipClient c,String id,Ttlv parameters,byte[]data)throws Exception {
        var b=Requests.mac().uniqueIdentifier(id).add(bytes(DATA,data));if(parameters!=null)b.add(parameters);
        return c.call(b.build()).requirePayload().require(MAC_DATA).bytesValue();
    }
    static void stream(KmipClient c,String id,Ttlv parameters,byte[]data,byte[]expected)throws Exception {
        int mid=data.length/2;
        var started=c.call(Requests.mac().uniqueIdentifier(id).add(parameters,bool(INIT_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(data,0,mid))).build()).requirePayload();
        require(started.children(MAC_DATA).isEmpty(),"early MAC Data");
        var correlation=started.require(CORRELATION_VALUE);
        var altered=c.execute(Requests.mac().uniqueIdentifier(id).add(parameters.equals(cp(10))?cp(9):cp(10),correlation,bytes(DATA,new byte[]{1})).build());
        require(!altered.successful()&&altered.reason()==7,"changed stream mechanism accepted");
        var result=c.call(Requests.mac().uniqueIdentifier(id).add(correlation,bool(FINAL_INDICATOR,true),bytes(DATA,Arrays.copyOfRange(data,mid,data.length))).build()).requirePayload();
        require(Arrays.equals(result.require(MAC_DATA).bytesValue(),expected),"stream MAC differs");
        var verified=c.call(Requests.macVerify().uniqueIdentifier(id).add(parameters,bytes(DATA,data),bytes(MAC_DATA,expected)).build()).requirePayload();
        require(verified.require(VALIDITY_INDICATOR).intValue()==1,"valid MAC rejected");
        byte[]invalid=expected.clone();invalid[0]^=1;
        require(c.call(Requests.macVerify().uniqueIdentifier(id).add(parameters,bytes(DATA,data),bytes(MAC_DATA,invalid)).build()).requirePayload().require(VALIDITY_INDICATOR).intValue()==2,"invalid MAC accepted");
    }
    public static void main(String[]args)throws Exception {
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);boolean creating=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        byte[]aes=HexFormat.of().parseHex("2b7e151628aed2a6abf7158809cf4f3c"),data=message();
        byte[]cmacData=HexFormat.of().parseHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        String[]cmacExpected={"bb1d6929e95937287fa37d129b756746","070a16b46b4d4144f79bdd9dd04a287c","dfa66747de9ae63030ca32611497c827","51f0bebf7e3b9d92fc49741779363cfe"};int[]lengths={0,16,40,64};
        List<String>rows=new ArrayList<>(),saved=creating?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")) {
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,version)) {
                String prefix=code+"\t"+transport+"\t";int cases=0;
                if(creating){
                    String aesId=register(c,version,3,aes,true);
                    for(int algorithm:new int[]{7,8,9,10,11,12,35,36,37,38}) {
                        if(code<14&&algorithm>=35)continue;
                        byte[]key=new byte[algorithm%2==0?300:1];Arrays.fill(key,(byte)0xa5);
                        String id=register(c,version,algorithm,key,false);byte[]expected=hmac(algorithm,key,data),aesExpected=hmac(algorithm,aes,data);
                        require(Arrays.equals(mac(c,id,null,data),expected),"HMAC key result differs from SunJCE");
                        require(Arrays.equals(mac(c,aesId,cp(algorithm),data),aesExpected),"AES managed key HMAC differs from SunJCE");
                        // Change to a different mechanism during the trial chunk.
                        if(code>=13)stream(c,aesId,cp(algorithm),data,aesExpected);
                        rows.add(prefix+"HMAC\t"+algorithm+"\t"+id+"\t"+aesId+"\t"+HexFormat.of().formatHex(expected)+"\t"+HexFormat.of().formatHex(aesExpected));cases++;
                    }
                    for(int i=0;i<lengths.length;i++) {
                        byte[]input=Arrays.copyOf(cmacData,lengths[i]),expected=HexFormat.of().parseHex(cmacExpected[i]);
                        require(Arrays.equals(mac(c,aesId,cmac(),input),expected),"CMAC differs from RFC 4493");if(code>=13)stream(c,aesId,cmac(),input,expected);
                        rows.add(prefix+"CMAC\t"+lengths[i]+"\t"+aesId+"\t"+cmacExpected[i]);cases++;
                    }
                }else for(String row:saved)if(row.startsWith(prefix)) {
                    String[]v=row.split("\t");
                    if(v[2].equals("HMAC")) {
                        require(HexFormat.of().formatHex(mac(c,v[4],null,data)).equals(v[6]),"restored HMAC differs");
                        require(HexFormat.of().formatHex(mac(c,v[5],cp(Integer.parseInt(v[3])),data)).equals(v[7]),"restored AES HMAC differs");
                    }else require(HexFormat.of().formatHex(mac(c,v[4],cmac(),Arrays.copyOf(cmacData,Integer.parseInt(v[3])))).equals(v[5]),"restored CMAC differs");cases++;
                }
                System.out.println("PASS released SDK MAC "+version+" "+transport+" "+args[3]+" "+cases+" cases");
            }
        }
        if(creating)Files.write(manifest,rows);
    }
}
