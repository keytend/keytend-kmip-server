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

public class Sign {
  public static void main(String[] args) {
    Path pki = Path.of(System.getenv("KMIP_PKI"));
    String cert = System.getenv().getOrDefault("KMIP_CLIENT", "client");  // the certificate in pki
    KmsConfig config = KmsConfig.builder()
        .endpoints("localhost:5696")
        .clientIdentityPem(pki.resolve(cert + ".pem"), pki.resolve(cert + ".key"))
        .trustPem(pki.resolve("ca.pem"))
        .build();
    try (Kms kms = Kms.connect(config)) {
      KeyPairHandle signer = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
          .named("quickstart-signer", "quickstart-signer-public")
          .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
          .findOrCreate();
      SignatureSpec ecdsa = SignatureSpec.ecdsa(Hash.SHA_256);
      byte[] message = "release manifest".getBytes(StandardCharsets.UTF_8);
      byte[] signature = signer.privateKey().sign(ecdsa, message);
      System.out.println("signed with " + signer.privateKey().id());
      var verifier = signer.publicKey();
      System.out.println("original: " + verifier.verify(ecdsa, message, signature));
      byte[] altered = "release manifest!".getBytes(StandardCharsets.UTF_8);
      System.out.println("altered:  " + verifier.verify(ecdsa, altered, signature));
    }
  }
}
