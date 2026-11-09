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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

func main() {
	log.SetFlags(0)                  // print errors without a timestamp
	pki := os.Getenv("KMIP_PKI")     // directory with ca.pem and the client certificates
	cert := os.Getenv("KMIP_CLIENT") // the client certificate: client, other or unlisted
	if cert == "" {
		cert = "client"
	}
	// Dial and Exec have no timeout of their own: give every call a deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := kmipclient.DialContext(ctx, "localhost:5696",
		kmipclient.WithRootCAFile(pki+"/ca.pem"),
		kmipclient.WithClientCertFiles(pki+"/"+cert+".pem", pki+"/"+cert+".key"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	created, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
	id := created.UniqueIdentifier
	if _, err := client.Activate(id).ExecContext(ctx); err != nil {
		log.Fatal(err)
	}
	got, err := client.Get(id).ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
	key, err := got.SymmetricKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("created %s: %d-byte AES key over KMIP %v\n", id, len(key), client.Version())

	// Encrypt and decrypt on the server with AES-GCM. The server picks the IV
	// and returns it with the ciphertext and tag; store all three.
	randomIV := true
	gcm := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeGCM, TagLength: 16, RandomIV: &randomIV}
	aad := []byte("order-42")
	sealed, err := client.Encrypt(id).WithCryptographicParameters(gcm).WithAAD(aad).Data([]byte("hello")).ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
	opened, err := client.Decrypt(id).WithCryptographicParameters(gcm).
		WithIvCounterNonce(sealed.IVCounterNonce).WithAAD(aad).
		WithAuthTag(sealed.AuthenticatedEncryptionTag).Data(sealed.Data).ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decrypted %q\n", opened.Data)

	// Retire the key: an Active key is revoked before it can be destroyed.
	if _, err := client.Revoke(id).
		WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).
		ExecContext(ctx); err != nil {
		log.Fatal(err)
	}
	if _, err := client.Destroy(id).ExecContext(ctx); err != nil {
		log.Fatal(err)
	}

	// ExecContext folds a KMIP failure into a plain error string. Batch returns the
	// result item instead, so the Result Reason can be checked; its error is
	// only for TLS, connection or encoding failures.
	res, err := client.Batch(ctx, &payloads.GetRequestPayload{UniqueIdentifier: id})
	if err != nil {
		log.Fatal(err)
	}
	if bi := res[0]; bi.ResultStatus != kmip.ResultStatusSuccess {
		fmt.Printf("Get after Destroy: %s: %s\n", ttlv.EnumStr(bi.ResultReason), bi.ResultMessage)
	}
}
