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
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.transport.*;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Date predicates through unchanged released SDK builders and codecs. */
public final class ServerLocateDates {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static Ttlv date(Tag tag,long value){return Ttlv.of(tag.code(),Ttlv.Type.DATE_TIME,value);}
    static Ttlv attrs(int code,Ttlv...values){
        if(code>=20)return structure(ATTRIBUTES,values);
        return structure(TEMPLATE_ATTRIBUTE,Arrays.stream(values).map(ServerLocateDates::legacy).toArray(Ttlv[]::new));
    }
    static Ttlv legacy(Ttlv value){
        String name=switch(Tag.fromCode(value.tag()).orElseThrow()){
            case CRYPTOGRAPHIC_ALGORITHM->"Cryptographic Algorithm";
            case CRYPTOGRAPHIC_LENGTH->"Cryptographic Length";
            case CRYPTOGRAPHIC_USAGE_MASK->"Cryptographic Usage Mask";
            case OBJECT_GROUP->"Object Group";
            case ACTIVATION_DATE->"Activation Date";
            case DEACTIVATION_DATE->"Deactivation Date";
            default->throw new AssertionError("fixture attribute");
        };
        return structure(ATTRIBUTE,text(ATTRIBUTE_NAME,name),value.retag(ATTRIBUTE_VALUE));
    }
    static Request locate(int code,String group,Ttlv...dates){
        var values=new ArrayList<Ttlv>();values.add(text(OBJECT_GROUP,group));values.addAll(List.of(dates));
        var b=Requests.locate();
        if(code>=20)b.add(structure(ATTRIBUTES,values));else for(var value:values)b.add(legacy(value));
        return b.build();
    }
    static void check(KmipClient client,int code,String group,List<String>expected,Ttlv...dates)throws Exception{
        var result=client.call(locate(code,group,dates)).requirePayload();
        var actual=result.children().stream().filter(n->n.tag()==UNIQUE_IDENTIFIER.code()).map(Ttlv::textValue).toList();
        require(actual.equals(expected),"date query mismatch: "+actual+" expected "+expected);
        if(code>=13)require(result.require(LOCATED_ITEMS).intValue()==expected.size(),"located count mismatch");
    }
    public static void main(String[]args)throws Exception{
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        // keytend-kmip 0.9 encodes a DateTime outside the xsd:dateTime range it writes as hex in XML,
        // which Profiles 5.4.1.6.11 does not allow (hex is a JSON form only); the server refuses
        // such a request. Exclude the XML extremes while that holds, and fail if it changes.
        String xmlMax=new String(new XmlCodec().encode(date(ACTIVATION_DATE,Long.MAX_VALUE)),java.nio.charset.StandardCharsets.UTF_8);
        if(!xmlMax.contains("value=\"0x"))throw new AssertionError("Reevaluate the XML maximum timestamp exclusion: "+xmlMax);
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{11,12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var client=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t",group;long future;List<String>ids=new ArrayList<>();
                if(create){
                    group="java-locate-"+UUID.randomUUID();future=Instant.now().getEpochSecond()+1000000;
                    for(int index=0;index<4;index++){
                        var values=new ArrayList<Ttlv>(List.of(enumeration(CRYPTOGRAPHIC_ALGORITHM,3),integer(CRYPTOGRAPHIC_LENGTH,256),integer(CRYPTOGRAPHIC_USAGE_MASK,12),text(OBJECT_GROUP,group)));
                        if(index<3)values.add(date(ACTIVATION_DATE,future+index*100));
                        ids.add(client.call(Requests.create().add(enumeration(OBJECT_TYPE,2),attrs(code,values.toArray(Ttlv[]::new))).build()).uniqueIdentifier());
                    }
                    rows.add(prefix+group+"\t"+future+"\t"+String.join("\t",ids));
                }else{
                    var columns=saved.stream().filter(row->row.startsWith(prefix)).findFirst().orElseThrow().split("\t");
                    group=columns[2];future=Long.parseLong(columns[3]);ids.addAll(Arrays.asList(columns).subList(4,8));
                }
                check(client,code,group,List.of(ids.get(1)),date(ACTIVATION_DATE,future+100));
                check(client,code,group,List.of(ids.get(1),ids.get(0)),date(ACTIVATION_DATE,future),date(ACTIVATION_DATE,future+100));
                check(client,code,group,List.of(ids.get(1),ids.get(0)),date(ACTIVATION_DATE,future+100),date(ACTIVATION_DATE,future));
                check(client,code,group,List.of(ids.get(2),ids.get(1),ids.get(0)),date(ACTIVATION_DATE,future),date(ACTIVATION_DATE,future+200));
                int checks=4;
                if(!transport.equals("XML")){
                    check(client,code,group,List.of(ids.get(3)),date(ACTIVATION_DATE,Long.MAX_VALUE));
                    check(client,code,group,List.of(ids.get(3),ids.get(2)),date(ACTIVATION_DATE,future+200),date(ACTIVATION_DATE,Long.MAX_VALUE));
                    check(client,code,group,List.of(ids.get(3),ids.get(2),ids.get(1),ids.get(0)),date(ACTIVATION_DATE,Long.MIN_VALUE),date(ACTIVATION_DATE,Long.MAX_VALUE));checks+=3;
                }
                var invalid=client.execute(locate(code,group,date(ACTIVATION_DATE,future),date(ACTIVATION_DATE,future+1),date(ACTIVATION_DATE,future+2)));
                require(invalid.status()==1&&Objects.equals(invalid.reason(),7),"excess bounds accepted");checks++;
                System.out.println("PASS released SDK Locate dates "+version+" "+transport+" "+args[3]+" "+checks+" queries"+(transport.equals("XML")?"; full-range timestamps excluded CLIENT-LOCATE-001":""));
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
