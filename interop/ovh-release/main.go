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

// Qualification profile on the tagged OVH kmip-go v0.9.2 release. The broader
// ../ovh adapter needs APIs that exist only after that release (Check, DeriveKey).
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}

func state(ctx context.Context, c *kmipclient.Client, id string) (kmip.State, int32) {
	attrs := must(c.GetAttributes(id, kmip.AttributeNameState, kmip.AttributeNameCryptographicLength).ExecContext(ctx))
	var s kmip.State
	var length int32
	for _, a := range attrs.Attribute {
		switch v := a.AttributeValue.(type) {
		case kmip.State:
			s = v
		case int32:
			length = v
		}
	}
	return s, length
}

func main() {
	info, _ := debug.ReadBuildInfo()
	for _, dep := range info.Deps {
		if dep.Path == "github.com/ovh/kmip-go" && dep.Version != "v0.9.2" {
			panic("not the tagged release: " + dep.Version)
		}
	}
	p, port := os.Getenv("KMIP_PKI"), os.Getenv("KMIP_PORT")
	versions := []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4}
	// NIST SP 800-38A F.1.5 ECB-AES256.Encrypt, first block.
	nistKey := must(hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
	nistPlain := must(hex.DecodeString("6bc1bee22e409f96e93d7e117393172a"))
	nistCipher := must(hex.DecodeString("f3eed1bdb5d2a03c064b5a7e3db181f8"))
	for _, v := range versions {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c := must(kmipclient.Dial("localhost:"+port, kmipclient.WithClientCertFiles(filepath.Join(p, "client.pem"), filepath.Join(p, "client.key")), kmipclient.WithRootCAFile(filepath.Join(p, "ca.pem")), kmipclient.EnforceVersion(v)))
		id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
		if s, n := state(ctx, c, id); s != kmip.StatePreActive || n != 256 {
			panic(fmt.Sprintf("created state %v length %d", s, n))
		}
		must(c.Activate(id).ExecContext(ctx))
		if s, _ := state(ctx, c, id); s != kmip.StateActive {
			panic("not Active")
		}
		key := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
		if len(key) != 32 || !bytes.Equal(key, must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())) {
			panic("repeated Get changed the material")
		}
		tested := "Create, typed PreActive/Active state and length, repeated exact 32-byte Get"
		if v.ProtocolVersionMinor >= 2 {
			nist := must(c.Register().SymmetricKey(kmip.CryptographicAlgorithmAES, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt, nistKey).ExecContext(ctx)).UniqueIdentifier
			must(c.Activate(nist).ExecContext(ctx))
			ecb := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeECB, PaddingMethod: kmip.PaddingMethodNone}
			if got := must(c.Encrypt(nist).WithCryptographicParameters(ecb).Data(nistPlain).ExecContext(ctx)).Data; !bytes.Equal(got, nistCipher) {
				panic("NIST SP 800-38A F.1.5 known answer differs")
			}
			block := must(aes.NewCipher(key))
			iv := []byte("0123456789abcdef")
			data := bytes.Repeat([]byte("database block 0"), 4)
			want := make([]byte, len(data))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, data)
			cbc := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeCBC, PaddingMethod: kmip.PaddingMethodNone}
			encrypted := must(c.Encrypt(id).WithCryptographicParameters(cbc).WithIvCounterNonce(iv).Data(data).ExecContext(ctx))
			if !bytes.Equal(encrypted.Data, want) {
				panic("CBC result differs from independent Go AES")
			}
			if got := must(c.Decrypt(id).WithCryptographicParameters(cbc).WithIvCounterNonce(iv).Data(want).ExecContext(ctx)).Data; !bytes.Equal(got, data) {
				panic("CBC decrypt mismatch")
			}
			must(c.Revoke(nist).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
			must(c.Destroy(nist).ExecContext(ctx))
			tested += ", NIST SP 800-38A F.1.5 ECB known answer, CBC against independent Go AES"
		}
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		if s, _ := state(ctx, c, id); s != kmip.StateDeactivated {
			panic("not Deactivated")
		}
		if v.ProtocolVersionMinor >= 2 {
			if _, err := c.Encrypt(id).Data(bytes.Repeat([]byte{1}, 16)).ExecContext(ctx); err == nil {
				panic("Encrypt with a revoked key succeeded")
			}
		}
		must(c.Destroy(id).ExecContext(ctx))
		if s, _ := state(ctx, c, id); s != kmip.StateDestroyed {
			panic("not Destroyed")
		}
		if _, err := c.Get(id).ExecContext(ctx); err == nil {
			panic("Get after Destroy returned material")
		}
		_ = c.Close()
		cancel()
		fmt.Printf("PASS OVH v0.9.2 %v: %s, Revoke to Deactivated, Destroy to Destroyed, refusal after Destroy\n", v, tested)
	}
	testNegatives(p, port, versions)
}
