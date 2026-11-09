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

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.transport.HttpsTransport;
import dev.keytend.kmip.transport.Tls;
import java.net.URI;
import java.nio.file.Path;

public class HttpsQuickstart {
  public static void main(String[] args) throws Exception {
    Path pki = Path.of(System.getenv("KMIP_PKI"));
    String cert = System.getenv().getOrDefault("KMIP_CLIENT", "client");  // the certificate in pki
    var tls = Tls.context(pki.resolve(cert + ".p12"), "changeit".toCharArray(),
        pki.resolve("ca.pem"));
    var https = new HttpsTransport(URI.create("https://localhost:5697/kmip"), tls,
        HttpsTransport.Encoding.JSON);
    try (var client = new KmipClient(https, ProtocolVersion.of(2, 1))) {
      String id = client.createSymmetricKey(Enums.CryptographicAlgorithm.AES, 256,
          Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT);
      System.out.println("created " + id + " over HTTPS JSON, KMIP "
          + client.version());
      client.destroy(id);
    }
  }
}
