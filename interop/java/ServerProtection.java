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

/** Live, unmodified release SDK protection-storage and factory interoperability. */
public final class ServerProtection {
    static void require(boolean ok,String message) { if(!ok)throw new AssertionError(message); }
    static Ttlv masks(Tag container,int... values) {
        return structure(container,Arrays.stream(values).mapToObj(n->integer(PROTECTION_STORAGE_MASK,n)).toArray(Ttlv[]::new));
    }
    static String identifier(Result result) { return result.requirePayload().require(UNIQUE_IDENTIFIER).textValue(); }
    static int metadata(KmipClient c,String id)throws Exception {
        var value=c.call(Requests.getAttributes().uniqueIdentifier(id).add(enumeration(ATTRIBUTE_REFERENCE,PROTECTION_STORAGE_MASK.code())).build())
            .requirePayload().require(ATTRIBUTES).require(PROTECTION_STORAGE_MASK);
        require(value.type()==Ttlv.Type.INTEGER,"mask has wrong wire type");return value.intValue();
    }
    static String digest(KmipClient c,String id)throws Exception {
        byte[] key=c.get(id).requirePayload().require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue();
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key)); }
        finally { Arrays.fill(key,(byte)0); }
    }
    static Request create(int... values) {
        return Requests.create().add(enumeration(OBJECT_TYPE,2),structure(ATTRIBUTES,enumeration(CRYPTOGRAPHIC_ALGORITHM,3),integer(CRYPTOGRAPHIC_LENGTH,128),integer(CRYPTOGRAPHIC_USAGE_MASK,12)),masks(PROTECTION_STORAGE_MASKS,values)).build();
    }
    static final Set<String> clientFindings=new TreeSet<>();
    public static void main(String[]args)throws Exception {
        Path pki=Path.of(args[0]),manifest=Path.of(args[4]);String phase=args[3];
        var context=Tls.context(pki.resolve("client.p12"),"changeit".toCharArray(),pki.resolve("ca.pem"));
        List<String> rows=new ArrayList<>();List<String> saved=phase.equals("create")?List.of():Files.readAllLines(manifest);
        for(int minor:new int[]{0,1})for(String transport:List.of("TLS","TTLV","JSON","XML")) {
            var version=ProtocolVersion.of(2,minor);
            KmipTransport wire=transport.equals("TLS")?new TlsTransport("localhost",Integer.parseInt(args[1]),context):
                new HttpsTransport(URI.create("https://localhost:"+args[2]+"/kmip"),context,HttpsTransport.Encoding.valueOf(transport));
            try(var c=new KmipClient(wire,version)) {
                var capabilities=c.call(Requests.query().add(enumeration(QUERY_FUNCTION,14)).build()).requirePayload().require(PROTECTION_STORAGE_MASKS).children();
                require(capabilities.size()==1 && capabilities.get(0).intValue()==1,"backend capability differs");
                String prefix="2."+minor+"\t"+transport+"\t";
                if(phase.equals("create")) {
                    var denied=c.execute(create(3));require(!denied.successful()&&denied.reason()==0x44,"partial mask accepted");
                    String software=identifier(c.call(create(2,1))),unrestricted=identifier(c.call(create(0)));
                    require(metadata(c,software)==1&&metadata(c,unrestricted)==0,"selection not retained");
                    String hash=digest(c,unrestricted);
                    var edit=c.execute(Requests.setAttribute().uniqueIdentifier(unrestricted).add(structure(NEW_ATTRIBUTE,integer(PROTECTION_STORAGE_MASK,2))).build());
                    require(!edit.successful()&&edit.reason()==0x22,"immutable storage was editable");
                    var split=c.call(Requests.createSplitKey().uniqueIdentifier(unrestricted).add(enumeration(OBJECT_TYPE,5),integer(SPLIT_KEY_PARTS,3),integer(SPLIT_KEY_THRESHOLD,2),enumeration(SPLIT_KEY_METHOD,4),structure(ATTRIBUTES),masks(PROTECTION_STORAGE_MASKS,1)).build()).requirePayload().children(UNIQUE_IDENTIFIER);
                    require(split.size()==3,"wrong part count");for(var part:split)require(metadata(c,part.textValue())==1,"share selection differs");
                    String joined=identifier(c.call(Requests.joinSplitKey().uniqueIdentifier(split.get(0).textValue()).uniqueIdentifier(split.get(2).textValue()).add(enumeration(OBJECT_TYPE,2),masks(PROTECTION_STORAGE_MASKS,0)).build()));
                    require(metadata(c,joined)==0&&digest(c,joined).equals(hash),"join changed storage or key bytes");
                    var pair=c.call(Requests.createKeyPair().add(masks(COMMON_PROTECTION_STORAGE_MASKS,0),masks(PRIVATE_PROTECTION_STORAGE_MASKS,1),masks(PUBLIC_PROTECTION_STORAGE_MASKS,0)).build()).requirePayload();
                    String privateId=pair.require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue(),publicId=pair.require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
                    require(metadata(c,privateId)==1&&metadata(c,publicId)==0,"pair role selection differs");
                    for(var role:List.of(COMMON_PROTECTION_STORAGE_MASKS,PRIVATE_PROTECTION_STORAGE_MASKS,PUBLIC_PROTECTION_STORAGE_MASKS)) {
                        var result=c.execute(Requests.createKeyPair().add(masks(role,2)).build());
                        require(!result.successful()&&result.reason()==(role==PUBLIC_PROTECTION_STORAGE_MASKS?0x49:0x48),"wrong role failure reason");
                    }
                    var exported=c.call(Requests.export().uniqueIdentifier(joined).build()).requirePayload();
                    c.destroy(joined);
                    // Protection Storage Masks is not a field of the KMIP 2.x Import request (2.0 Table 220,
                    // 2.1 Table 238); the server accepts it as an extension. keytend-kmip normalises the
                    // payload to the table and moves the unknown field into Attributes, where the server
                    // refuses it (CLIENT-PROTECTION-001). The server's Import storage checks are covered by
                    // tests/protection_storage.rs; this lane then restores without the extension field.
                    var incompatible=c.execute(Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true),masks(PROTECTION_STORAGE_MASKS,1)).build());
                    boolean extension=!(incompatible.reason()!=null&&incompatible.reason()==8&&"Attribute is not supported".equals(incompatible.message()));
                    if(extension)require(!incompatible.successful()&&incompatible.reason()==0x44,"Import rewrote readonly storage");
                    else clientFindings.add("CLIENT-PROTECTION-001");
                    var restore=extension?Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true),masks(PROTECTION_STORAGE_MASKS,1,0)).build()
                        :Requests.importObject().add(exported.children().toArray(Ttlv[]::new)).add(bool(REPLACE_EXISTING,true)).build();
                    c.call(restore);require(metadata(c,joined)==0&&digest(c,joined).equals(hash),"Import did not restore stored selection");
                    rows.add(prefix+software+"\t"+unrestricted+"\t"+joined+"\t"+privateId+"\t"+publicId+"\t"+hash);
                } else {
                    var row=saved.stream().filter(s->s.startsWith(prefix)).findFirst().orElseThrow().split("\t");
                    require(metadata(c,row[2])==1&&metadata(c,row[3])==0&&metadata(c,row[4])==0&&metadata(c,row[5])==1&&metadata(c,row[6])==0,"persisted masks differ");
                    require(digest(c,row[3]).equals(row[7])&&digest(c,row[4]).equals(row[7]),"persisted material differs");
                }
                System.err.println("PASS released Java SDK storage "+version+" "+transport+" "+phase+(clientFindings.isEmpty()?"":"; Import storage-extension check excluded "+String.join(",",new TreeSet<>(clientFindings))));
            }
        }
        if(phase.equals("create"))Files.write(manifest,rows);
    }
}
