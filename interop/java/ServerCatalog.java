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

import dev.keytend.kmip.model.ProtocolVersion;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Executes the unchanged, pinned Java catalog with owned Rust server fixture hooks. */
public final class ServerCatalog {
    static void control(CatalogFixture fixture,String socket,String action)throws IOException {
        try(SocketChannel channel=SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(UnixDomainSocketAddress.of(socket));
            ByteBuffer command=StandardCharsets.US_ASCII.encode(action+"\n");
            while(command.hasRemaining())channel.write(command);
            ByteBuffer response=ByteBuffer.allocate(4096);
            while(response.hasRemaining() && channel.read(response)>=0) {}
            response.flip();String value=StandardCharsets.UTF_8.decode(response).toString();
            if(!value.startsWith("OK "))throw new IOException("Owned fixture control failed");
            fixture.evidence.put("rust_fixture_action",action);
            fixture.evidence.put("rust_fixture_policy_sha256",value.substring(3).trim());
            @SuppressWarnings("unchecked") List<Map<String,String>> actions=(List<Map<String,String>>)fixture.evidence.computeIfAbsent("rust_fixture_actions",key->new ArrayList<Map<String,String>>());
            actions.add(Map.of("action",action,"policy_sha256",value.substring(3).trim()));
        }
    }
    public static void main(String[] args)throws Exception {
        Path root=Path.of(args[0]);String[] v=args[4].split("\\.");
        ProtocolVersion version=ProtocolVersion.of(Integer.parseInt(v[0]),Integer.parseInt(v[1]));
        try(CatalogFixture fixture=new CatalogFixture(root,"keytend-kmip-server",args[1],Integer.parseInt(args[2]),Path.of(args[3]),version,args[5],args[6],args[7],args[8])) {
            fixture.restart=()->control(fixture,args[9],"restart");
            fixture.serverIdentity=identity->{
                control(fixture,args[9],"identity:"+identity);
                CatalogTls.awaitIdentity(fixture,identity);
                fixture.evidence.put("rust_fixture_leaf_verified",identity);
            };
            fixture.grant=()->control(fixture,args[9],"grant:"+fixture.knownUid);
            fixture.revokeGrant=()->control(fixture,args[9],"revoke");
            fixture.listOnlyGrant=()->control(fixture,args[9],"list-only:"+fixture.knownUid);
            fixture.readOnlyRole=true;
            Map<String,Object> report=new CatalogLiveSuite(fixture).run();
            fixture.close();
            report.put("cleanup",Map.of("remaining_run_owned_ids",List.copyOf(fixture.owned)));
            report.put("server_fixture_adapter","Rust native listener, restart, TLS-chain rotation and exact-object Get/Locate grants with read-only operation ACL; real policy restarts");
            report.put("adapter_sha256",args[11]);
            Catalog.write(Path.of(args[10]),report);
            @SuppressWarnings("unchecked") List<Map<String,Object>> records=(List<Map<String,Object>>)report.get("records");
            Map<Object,Long> counts=new LinkedHashMap<>();
            for(var record:records)counts.merge(record.get("outcome"),1L,Long::sum);
            System.out.println(Catalog.json(counts));
        }
    }
}
