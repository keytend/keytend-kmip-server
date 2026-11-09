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

/** External XOR shares with independently constructed material and SunJCE use. */
public final class ChaChaShares {
    static Request registration(int algorithm,int bits,int part,byte[] share) {
        Ttlv object=structure(SPLIT_KEY,integer(SPLIT_KEY_PARTS,3),integer(KEY_PART_IDENTIFIER,part),integer(SPLIT_KEY_THRESHOLD,3),enumeration(SPLIT_KEY_METHOD,1),
            structure(KEY_BLOCK,enumeration(KEY_FORMAT_TYPE,1),enumeration(CRYPTOGRAPHIC_ALGORITHM,algorithm),integer(CRYPTOGRAPHIC_LENGTH,bits),structure(KEY_VALUE,bytes(KEY_MATERIAL,share))));
        return Requests.register().template(Attributes.usage(Enums.CryptographicUsageMask.ENCRYPT,Enums.CryptographicUsageMask.DECRYPT)).add(enumeration(OBJECT_TYPE,5),object).build();
    }
    static byte[] material(Ttlv payload){return payload.require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue();}
    public static void main(String[] args)throws Exception {
        Path pki=Path.of(args[0]);var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        for(int code:new int[]{11,12,13,14,20,21,30})for(String transport:List.of("TLS","TTLV","JSON","XML")) {
            var version=ProtocolVersion.of(code/10,code%10);int start=ServerChaCha.observations,local=0;
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var client=new KmipClient(wire,version)) {
                for(int algorithm:new int[]{28,30}) {
                    if(code<14) {
                        try {client.execute(registration(algorithm,256,1,new byte[32]));throw new AssertionError("legacy request escaped SDK validation");}
                        catch(IllegalArgumentException expected){ServerChaCha.require(expected.getMessage().contains("requires KMIP 1.4"),"legacy preflight classification");local++;}
                        continue;
                    }
                    for(int bits:new int[]{128,240,264})ServerChaCha.denied(client,registration(algorithm,bits,1,new byte[32]),7);
                    for(int width:new int[]{30,31,33,34})ServerChaCha.denied(client,registration(algorithm,256,1,new byte[width]),7);
                    byte[][] shares={new byte[32],new byte[32],new byte[32]};
                    Arrays.fill(shares[0],(byte)0x5a);Arrays.fill(shares[1],(byte)0xa5);
                    for(int i=0;i<32;i++)shares[2][i]=(byte)(ServerChaCha.KEY[i]^0xff);
                    List<String> ids=new ArrayList<>();
                    for(int i=0;i<3;i++)ids.add(ServerChaCha.ok(client,registration(algorithm,256,i+1,shares[i])).require(UNIQUE_IDENTIFIER).textValue());
                    var join=Requests.joinSplitKey().template().add(enumeration(OBJECT_TYPE,2));
                    for(String id:ids)join.uniqueIdentifier(id);
                    String joined=ServerChaCha.ok(client,join.build()).require(UNIQUE_IDENTIFIER).textValue();
                    ServerChaCha.require(Arrays.equals(material(ServerChaCha.ok(client,Requests.get().uniqueIdentifier(joined).build())),ServerChaCha.KEY),"external XOR reconstruction");
                    ServerChaCha.ok(client,Requests.activate().uniqueIdentifier(joined).build());
                    if(algorithm==28)ServerChaCha.verify(client,joined,algorithm,8);
                    ServerChaCha.verify(client,joined,algorithm,12);
                }
            }
            System.out.println((code<14?"LOCAL":"PASS")+"\t"+code+"\t"+transport+"\t"+(code<14?local:ServerChaCha.observations-start));
        }
    }
}
