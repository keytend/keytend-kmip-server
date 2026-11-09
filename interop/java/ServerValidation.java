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
import java.nio.file.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

/** Supplemental real SDK Validate tests, independently checked with Java PKIX. */
public final class ServerValidation {
    static void require(boolean value,String message){if(!value)throw new AssertionError(message);}
    static X509Certificate certificate(Path path)throws Exception{
        try(var in=Files.newInputStream(path)){return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);}
    }
    static boolean pkix(X509Certificate root,X509Certificate inter,X509Certificate leaf,Instant at)throws Exception{
        var parameters=new PKIXParameters(Set.of(new TrustAnchor(root,null)));parameters.setRevocationEnabled(false);parameters.setDate(Date.from(at));
        var chain=CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf,inter));
        try{CertPathValidator.getInstance("PKIX").validate(chain,parameters);return true;}catch(CertPathValidatorException expected){return false;}
    }
    public static void main(String[]args)throws Exception{
        Path p=Path.of(args[0]);String[]v=args[2].split("\\.");var version=ProtocolVersion.of(Integer.parseInt(v[0]),Integer.parseInt(v[1]));
        var root=certificate(p.resolve("validation-root.der"));var inter=certificate(p.resolve("validation-intermediate.der"));var leaf=certificate(p.resolve("validation-leaf.der"));
        var rootNode=ManagedObjects.certificate(Enums.CertificateType.X_509,root.getEncoded());var interNode=ManagedObjects.certificate(Enums.CertificateType.X_509,inter.getEncoded());var leafNode=ManagedObjects.certificate(Enums.CertificateType.X_509,leaf.getEncoded());
        var tls=Tls.context(p.resolve("client.p12"),"changeit".toCharArray(),p.resolve("ca.pem"));
        try(var c=new KmipClient(new TlsTransport("localhost",Integer.parseInt(args[1]),tls),version)){
            Instant now=Instant.now();require(pkix(root,inter,leaf,now),"Java PKIX rejected independent fixture");
            var response=c.call(Requests.validate().add(rootNode,leafNode,interNode).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==1,"inline unordered chain invalid");
            String lid=c.register(leafNode),iid=c.register(interNode);
            try{
                response=c.call(Requests.validate().uniqueIdentifier(lid).add(text(UNIQUE_IDENTIFIER,iid)).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==1,"stored repeated UID chain invalid");
                response=c.call(Requests.validate().uniqueIdentifier(lid).add(interNode).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==1,"mixed chain invalid");
                Instant after=leaf.getNotAfter().toInstant().plusSeconds(1);require(!pkix(root,inter,leaf,after),"Java PKIX accepted expired leaf");
                response=c.call(Requests.validate().add(leafNode,interNode,dateTime(VALIDITY_DATE,after)).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==2,"expired chain accepted");
                var rogue=ManagedObjects.certificate(Enums.CertificateType.X_509,Files.readAllBytes(p.resolve("validation-rogue.der")));
                response=c.call(Requests.validate().add(leafNode,interNode,rogue).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==2,"extra unrelated certificate ignored");
                response=c.call(Requests.validate().add(rogue).build());require(response.requirePayload().require(VALIDITY_INDICATOR).intValue()==2,"request root became trusted");
                var bad=c.execute(Requests.validate().build());require(!bad.successful()&&bad.reason()==7,"empty Validate request accepted");
            }finally{c.destroy(lid);c.destroy(iid);}
        }
        System.out.println("PASS Java SDK "+version+": repeated UID, inline/mixed/unordered chain, explicit trust, expiry and Java PKIX oracle");
    }
}
