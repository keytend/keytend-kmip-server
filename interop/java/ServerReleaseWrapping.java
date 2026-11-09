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
import java.nio.file.Path;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Supplemental corrected wrapping fixture; original catalog outcomes remain unchanged. */
public final class ServerReleaseWrapping {
    static void require(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        var p=Path.of(args[0]);var tls=Tls.context(p.resolve("client.p12"),"changeit".toCharArray(),p.resolve("ca.pem"));
        List<Map<String,Object>> rows=new ArrayList<>();
        for(var version:List.of(ProtocolVersion.V1_1,ProtocolVersion.V1_2,ProtocolVersion.V1_3,ProtocolVersion.V1_4,ProtocolVersion.V2_0,ProtocolVersion.V2_1)){
            try(var client=new KmipClient(new TlsTransport("localhost",Integer.parseInt(args[1]),tls),version)){
                byte[] key=new byte[32],kek=new byte[16];Arrays.fill(key,(byte)0x39);Arrays.fill(kek,(byte)0x74);
                String kekId=client.register(ManagedObjects.rawSymmetricKey(kek,Enums.CryptographicAlgorithm.AES),Attributes.usage(Enums.CryptographicUsageMask.WRAP_KEY,Enums.CryptographicUsageMask.UNWRAP_KEY));
                String id=null;
                try{
                    client.activate(kekId);
                    id=client.register(ManagedObjects.rawSymmetricKey(key,Enums.CryptographicAlgorithm.AES),Attributes.usage(Enums.CryptographicUsageMask.ENCRYPT,Enums.CryptographicUsageMask.DECRYPT));
                    var cp=structure(CRYPTOGRAPHIC_PARAMETERS,enumeration(BLOCK_CIPHER_MODE,Enums.BlockCipherMode.NISTKEY_WRAP));
                    var spec=structure(KEY_WRAPPING_SPECIFICATION,enumeration(WRAPPING_METHOD,Enums.WrappingMethod.ENCRYPT),
                        structure(ENCRYPTION_KEY_INFORMATION,text(UNIQUE_IDENTIFIER,kekId),cp),enumeration(ENCODING_OPTION,Enums.EncodingOption.NO_ENCODING));
                    var get=Requests.get().uniqueIdentifier(id).add(spec).build();
                    var failure=client.execute(get);
                    require(!failure.successful()&&failure.payload().isEmpty(),"missing stored parameters were accepted or exposed a payload");
                    require(failure.reason()!=null&&failure.reason()==(version.legacyAttributes()?1:7),"incorrect versioned missing-parameters reason");
                    client.call(Requests.addAttribute().uniqueIdentifier(kekId).attribute(Attributes.attribute("Cryptographic Parameters",cp)).build());
                    var wrapped=client.call(get).requirePayload().require(SYMMETRIC_KEY).require(KEY_BLOCK);
                    require(wrapped.require(KEY_WRAPPING_DATA).require(ENCODING_OPTION).intValue()==1,"NoEncoding metadata missing");
                    var cipher=Cipher.getInstance("AESWrap");cipher.init(Cipher.UNWRAP_MODE,new SecretKeySpec(kek,"AES"));
                    byte[] unwrapped=cipher.unwrap(wrapped.require(KEY_VALUE).bytesValue(),"AES",Cipher.SECRET_KEY).getEncoded();
                    require(Arrays.equals(key,unwrapped),"independent JCE unwrap differs");Arrays.fill(unwrapped,(byte)0);
                    Map<String,Object> row=new LinkedHashMap<>();row.put("wire_version",version.toString());row.put("no_encoding_wrap_and_independent_unwrap",true);
                    row.put("missing_stored_parameters_reason",failure.reason());
                    if(version.legacyAttributes()){
                        row.put("normative_missing_parameters_reason",1);row.put("error_reason_conformant",failure.reason()==1);
                    }else row.put("error_reason_conformant","not_assessed_for_this_edition");
                    rows.add(row);
                }finally{
                    if(id!=null)client.destroy(id);
                    client.revoke(kekId,Enums.RevocationReasonCode.CESSATION_OF_OPERATION,"fixture complete");client.destroy(kekId);
                    Arrays.fill(key,(byte)0);Arrays.fill(kek,(byte)0);
                }
            }
        }
        Catalog.write(Path.of(args[2]),Map.of("scope","supplemental corrected SDK fixture; legacy Get error reasons verified separately; no full-spec qualification","versions",rows));
        System.out.println("PASS six-version NoEncoding wrapping with stored KEK parameters and independent JCE unwrap; versioned missing-parameters reasons verified");
    }
}
