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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import dev.keytend.kmip.codec.*;
import java.net.URI;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Released generic request builders and independent Java scalar expected values. */
public final class ServerAdjust {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static Ttlv vendor(String name,Ttlv value){return structure(ATTRIBUTE,text(VENDOR_IDENTIFICATION,"x"),text(ATTRIBUTE_NAME,name),value.retag(ATTRIBUTE_VALUE));}
    static Ttlv reference(String name){return structure(ATTRIBUTE_REFERENCE,text(VENDOR_IDENTIFICATION,"x"),text(ATTRIBUTE_NAME,name));}
    static Request change(String id,String name,int kind,Ttlv amount){
        var b=Requests.adjustAttribute().uniqueIdentifier(id).add(reference(name),enumeration(ADJUSTMENT_TYPE,kind));
        if(amount!=null)b.add(amount.retag(ADJUSTMENT_VALUE));return b.build();
    }
    static Map<String,Ttlv> expected(){
        return Map.of("integer",integer(ATTRIBUTE_VALUE,7),"long",longInteger(ATTRIBUTE_VALUE,Long.MIN_VALUE+1),
            "big",bigInteger(ATTRIBUTE_VALUE,BigInteger.ONE.shiftLeft(255)),"flag",bool(ATTRIBUTE_VALUE,true),
            "interval",interval(ATTRIBUTE_VALUE,41),"date",dateTime(ATTRIBUTE_VALUE,Instant.ofEpochSecond(1700000001)),
            "extended",dateTimeExtended(ATTRIBUTE_VALUE,Instant.ofEpochSecond(1700000000,1000)),
            "absent",bigInteger(ATTRIBUTE_VALUE,BigInteger.ONE.shiftLeft(200).negate()));
    }
    static void verify(KmipClient client,String id,boolean extended)throws Exception{
        for(var e:expected().entrySet()){
            if(e.getKey().equals("extended")&&!extended)continue;
            var result=client.call(Requests.getAttributes().uniqueIdentifier(id).add(reference(e.getKey())).build()).requirePayload().require(ATTRIBUTES).require(ATTRIBUTE).require(ATTRIBUTE_VALUE);
            require(result.type()==e.getValue().type()&&result.value().equals(e.getValue().value()),"scalar mismatch "+e.getKey());
        }
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        var extendedProbe=dateTimeExtended(ATTRIBUTE_VALUE,Instant.ofEpochSecond(1700000000));
        for(int code:new int[]{20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var client=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t",id;boolean extended=true;
                if(create){
                    var attributes=new ArrayList<Ttlv>(List.of(
                        enumeration(CRYPTOGRAPHIC_ALGORITHM,3),integer(CRYPTOGRAPHIC_LENGTH,256),integer(CRYPTOGRAPHIC_USAGE_MASK,12),
                        vendor("integer",integer(ATTRIBUTE_VALUE,10)),vendor("long",longInteger(ATTRIBUTE_VALUE,Long.MIN_VALUE)),
                        vendor("big",bigInteger(ATTRIBUTE_VALUE,BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE))),vendor("flag",bool(ATTRIBUTE_VALUE,false)),
                        vendor("interval",interval(ATTRIBUTE_VALUE,40)),vendor("date",dateTime(ATTRIBUTE_VALUE,Instant.ofEpochSecond(1700000000)))));
                    if(extended)attributes.add(vendor("extended",extendedProbe));
                    id=client.call(Requests.create().add(enumeration(OBJECT_TYPE,2),structure(ATTRIBUTES,attributes)).build()).uniqueIdentifier();
                    client.call(change(id,"integer",2,integer(ADJUSTMENT_VALUE,3)));
                    client.call(change(id,"long",1,null));client.call(change(id,"big",1,null));client.call(change(id,"flag",3,null));
                    client.call(change(id,"interval",1,null));client.call(change(id,"date",1,null));if(extended)client.call(change(id,"extended",1,null));
                    client.call(change(id,"absent",2,bigInteger(ADJUSTMENT_VALUE,BigInteger.ONE.shiftLeft(200))));
                    var invalid=client.execute(change(id,"integer",1,bigInteger(ADJUSTMENT_VALUE,BigInteger.ONE.shiftLeft(70))));
                    require(invalid.status()==1&&Objects.equals(invalid.reason(),0x1b),"overflow accepted");
                    invalid=client.execute(Requests.adjustAttribute().uniqueIdentifier(id).attributeReference(CRYPTOGRAPHIC_USAGE_MASK).add(enumeration(ADJUSTMENT_TYPE,1),integer(ADJUSTMENT_VALUE,16)).build());
                    require(invalid.status()==1&&Objects.equals(invalid.reason(),0x1d),"client modified read-only mask");
                    rows.add(prefix+id);
                }else{id=saved.stream().filter(row->row.startsWith(prefix)).findFirst().orElseThrow().substring(prefix.length());}
                verify(client,id,extended);
                System.out.println("PASS released SDK Adjust Attribute "+version+" "+transport+" "+args[3]+" "+(extended?8:7)+" scalar values; DateTimeExtended "+(extended?"passed":"excluded"));
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
