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

import dev.keytend.kmip.kms.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class Quickstart {
  public static void main(String[] args) {
    Path pki = Path.of(System.getenv("KMIP_PKI"));
    String cert = System.getenv().getOrDefault("KMIP_CLIENT", "client");  // the certificate in pki
    KmsConfig config = KmsConfig.builder()
        .endpoints("localhost:5696")
        .clientIdentityPem(pki.resolve(cert + ".pem"), pki.resolve(cert + ".key"))
        .trustPem(pki.resolve("ca.pem"))
        .build();
    try (Kms kms = Kms.connect(config)) {
      KeyHandle kek = kms.keys().createAes(256).named("quickstart-kek")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .extractable(false)  // the server refuses to return the key's value
          .findOrCreate();
      byte[] aad = "record-42".getBytes(StandardCharsets.UTF_8);
      byte[] plaintext = "hello".getBytes(StandardCharsets.UTF_8);
      byte[] stored = kek.encrypt(CipherSpec.aesGcm(), plaintext, aad).toBytes();
      byte[] back = kek.decrypt(Ciphertext.fromBytes(stored), aad);
      System.out.println("KMIP " + kms.version() + ", key " + kek.id()
          + " round trip: " + new String(back, StandardCharsets.UTF_8));
    }
  }
}
