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

/** Lossless vendor opaque types through the unchanged released SDK. */
public final class ServerOpaque {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static String hash(byte[]value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    static Ttlv object(int type,byte[]data){return structure(OPAQUE_OBJECT,enumeration(OPAQUE_DATA_TYPE,type),bytes(OPAQUE_DATA_VALUE,data));}
    static void verify(KmipClient c,int version,String id,int type,int length,String digest)throws Exception {
        var value=c.get(id).requirePayload().require(OPAQUE_OBJECT);
        require(value.require(OPAQUE_DATA_TYPE).type()==Ttlv.Type.ENUMERATION&&value.require(OPAQUE_DATA_TYPE).intValue()==type,"opaque type changed");
        byte[]data=value.require(OPAQUE_DATA_VALUE).bytesValue();require(data.length==length&&hash(data).equals(digest),"opaque value changed");
        if(version>=20){
            var attr=c.call(Requests.getAttributes().uniqueIdentifier(id).add(enumeration(ATTRIBUTE_REFERENCE,OPAQUE_DATA_TYPE.code())).build()).requirePayload().require(ATTRIBUTES).require(OPAQUE_DATA_TYPE);
            require(attr.type()==Ttlv.Type.ENUMERATION&&attr.intValue()==type,"mandatory intrinsic type differs");
        }
    }
    public static void main(String[]args)throws Exception {
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);boolean create=args[3].equals("create");
        var tls=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String>rows=new ArrayList<>(),saved=create?List.of():Files.readAllLines(manifest);
        for(int code:new int[]{11,12,13,14,20,21})for(String transport:List.of("TLS","TTLV","JSON","XML")){
            var version=ProtocolVersion.of(code/10,code%10);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),tls):new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),tls,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,version)){
                String prefix=code+"\t"+transport+"\t";int cases=0;
                if(create)for(int type:new int[]{0x80000000,0x80000001,0x80012345,0x8fffffff})for(int length:new int[]{0,65536}){
                    byte[]data=new byte[length];for(int i=0;i<length;i++)data[i]=(byte)i;
                    var attrs=structure(code>=20?ATTRIBUTES:TEMPLATE_ATTRIBUTE);
                    String id=c.call(Requests.register().add(enumeration(OBJECT_TYPE,8),attrs,object(type,data)).build()).requirePayload().require(UNIQUE_IDENTIFIER).textValue();
                    String digest=hash(data);verify(c,code,id,type,length,digest);
                    if(code>=20){
                        var rejected=c.execute(Requests.setAttribute().uniqueIdentifier(id).add(structure(NEW_ATTRIBUTE,enumeration(OPAQUE_DATA_TYPE,0x80000002))).build());
                        require(!rejected.successful()&&rejected.reason()==0x22,"opaque type was mutable");
                        var exported=c.call(Requests.export().uniqueIdentifier(id).build()).requirePayload();
                        c.destroy(id);c.call(Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true)).build());
                        verify(c,code,id,type,length,digest);
                    }
                    rows.add(prefix+Integer.toUnsignedString(type,16)+"\t"+length+"\t"+id+"\t"+digest);cases++;
                }else for(String row:saved)if(row.startsWith(prefix)){
                    String[]v=row.split("\t");verify(c,code,v[4],Integer.parseUnsignedInt(v[2],16),Integer.parseInt(v[3]),v[5]);cases++;
                }
                System.out.println("PASS released SDK opaque "+version+" "+transport+" "+args[3]+" "+cases+" cases");
            }
        }
        if(create)Files.write(manifest,rows);
    }
}
