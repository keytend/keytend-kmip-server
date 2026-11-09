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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;

/** Unmodified SDK HTTP transport/codecs, with Java Cipher as a crypto oracle. */
public final class ServerHttps {
    static void require(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[]args)throws Exception{
        Path p=Path.of(args[0]);String[]v=args[2].split("\\.");
        var version=ProtocolVersion.of(Integer.parseInt(v[0]),Integer.parseInt(v[1]));
        var encoding=HttpsTransport.Encoding.valueOf(args[3]);
        var tls=Tls.context(p.resolve("client.p12"),"changeit".toCharArray(),p.resolve("ca.pem"));
        var endpoint=URI.create("https://localhost:"+args[1]+"/kmip");
        try(var c=new KmipClient(new HttpsTransport(endpoint,tls,encoding),version)){
            require(!c.query(Enums.QueryFunction.QUERY_OPERATIONS).requirePayload().children().isEmpty(),"empty Query response");
            String id=c.createSymmetricKey(Enums.CryptographicAlgorithm.AES,256,
                Enums.CryptographicUsageMask.ENCRYPT,Enums.CryptographicUsageMask.DECRYPT);
            byte[] key=c.get(id).requirePayload().require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue();
            require(key.length==32,"AES-256 key length");
            c.activate(id);
            try{
                byte[] message="KMIP HTTPS 雪 <&> \" escaped\t\n\r".getBytes(StandardCharsets.UTF_8);
                byte[] iv=new byte[16];Arrays.fill(iv,(byte)37);
                if(version.code()>=12){
                    var params=structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(BLOCK_CIPHER_MODE,1),enumeration(PADDING_METHOD,3));
                    var encrypted=c.call(Requests.encrypt().uniqueIdentifier(id).add(params,bytes(DATA,message),bytes(IV_COUNTER_NONCE,iv)).build()).requirePayload().require(DATA).bytesValue();
                    var cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
                    require(Arrays.equals(cipher.doFinal(message),encrypted),"independent Java CBC result differs");
                    var decrypted=c.call(Requests.decrypt().uniqueIdentifier(id).add(params,bytes(DATA,encrypted),bytes(IV_COUNTER_NONCE,iv)).build()).requirePayload().require(DATA).bytesValue();
                    require(Arrays.equals(message,decrypted),"decrypted bytes differ");
                }
                var missing=c.execute(Requests.get().uniqueIdentifier("https-missing-key").build());
                // 1.x Item Not Found; 2.x Object Not Found 0x37 (2.1 Table 222, docs/messages.md#unknown-identifiers).
                require(!missing.successful()&&missing.reason()==(version.code()>=20?0x37:1),"KMIP failure not returned over HTTP 200");
                try(var binary=new KmipClient(new TlsTransport("localhost",Integer.parseInt(args[4]),tls),version)){
                    byte[] other=binary.get(id).requirePayload().require(SYMMETRIC_KEY).require(KEY_BLOCK).require(KEY_VALUE).require(KEY_MATERIAL).bytesValue();
                    require(Arrays.equals(key,other),"binary and HTTPS listeners use different stores");Arrays.fill(other,(byte)0);
                }
            }finally{
                Arrays.fill(key,(byte)0);c.revoke(id,Enums.RevocationReasonCode.CESSATION_OF_OPERATION,"HTTPS fixture complete");c.destroy(id);
            }
        }
        System.out.println("PASS Java SDK "+version+" HTTPS "+encoding+": lifecycle, KMIP errors, shared binary store and independent Java CBC oracle where defined");
    }
}
