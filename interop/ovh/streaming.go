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
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

// Keep the upstream SDK's payload codec and TLS transport. Independent Go
// primitives verify results rather than relying on a server round trip.
func testMultipart(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	if v.ProtocolVersionMinor < 3 {
		return
	}
	yes := true
	message := bytes.Repeat([]byte("uneven database envelope input!"), 47)
	chunks := [][]byte{message[:7], message[7:39], message[39:]}
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
	key := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
	must(c.Activate(id).ExecContext(ctx))
	iv := bytes.Repeat([]byte{9}, 16)
	cp := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeCTR, PaddingMethod: kmip.PaddingMethodNone}
	var token, output []byte
	for i, chunk := range chunks {
		req := &payloads.EncryptRequestPayload{UniqueIdentifier: id, Data: chunk}
		if i == 0 {
			req.InitIndicator = &yes
			req.CryptographicParameters = &cp
			req.IVCounterNonce = iv
		} else {
			req.CorrelationValue = token
		}
		if i == len(chunks)-1 {
			req.FinalIndicator = &yes
		}
		resp := must(c.Request(ctx, req)).(*payloads.EncryptResponsePayload)
		output = append(output, resp.Data...)
		if i == 0 {
			token = resp.CorrelationValue
			if len(token) != 32 {
				panic("missing multipart correlation")
			}
		}
	}
	block := must(aes.NewCipher(key))
	expected := make([]byte, len(message))
	cipher.NewCTR(block, iv).XORKeyStream(expected, message)
	if !bytes.Equal(output, expected) {
		panic("multipart CTR differs from Go")
	}
	hashcp := kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256}
	token = nil
	for i, chunk := range chunks {
		req := &payloads.HashRequestPayload{CryptographicParameters: hashcp, Data: chunk, CorrelationValue: token}
		if i == 0 {
			req.InitIndicator = &yes
		}
		if i == 2 {
			req.FinalIndicator = &yes
		}
		resp := must(c.Request(ctx, req)).(*payloads.HashResponsePayload)
		if i == 0 {
			token = resp.CorrelationValue
		}
		if i < 2 && len(resp.Data) != 0 {
			panic("early hash output")
		}
		digest := sha256.Sum256(message)
		if i == 2 && !bytes.Equal(resp.Data, digest[:]) {
			panic("multipart SHA256 differs from Go")
		}
	}
	hid := must(c.Create().SymmetricKey(kmip.CryptographicAlgorithmHMACSHA256, 256, kmip.CryptographicUsageMACGenerate|kmip.CryptographicUsageMACVerify).ExecContext(ctx)).UniqueIdentifier
	hkey := must(must(c.Get(hid).ExecContext(ctx)).SymmetricKey())
	must(c.Activate(hid).ExecContext(ctx))
	mac := hmac.New(sha256.New, hkey)
	_, _ = mac.Write(message)
	expected = mac.Sum(nil)
	token = nil
	for i, chunk := range chunks {
		req := &payloads.MACRequestPayload{UniqueIdentifier: hid, Data: chunk, CorrelationValue: token}
		if i == 0 {
			req.InitIndicator = &yes
		}
		if i == 2 {
			req.FinalIndicator = &yes
		}
		resp := must(c.Request(ctx, req)).(*payloads.MACResponsePayload)
		if i == 0 {
			token = resp.CorrelationValue
		}
		if i < 2 && len(resp.MACData) != 0 {
			panic("early MAC output")
		}
		if i == 2 && !bytes.Equal(resp.MACData, expected) {
			panic("multipart HMAC differs from Go")
		}
	}
	pair := must(c.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).ExecContext(ctx))
	private := must(must(c.Get(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx)).RsaPrivateKey())
	must(c.Activate(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx))
	must(c.Activate(pair.PublicKeyUniqueIdentifier).ExecContext(ctx))
	sigcp := kmip.CryptographicParameters{DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithm(5)}
	token = nil
	for i, chunk := range chunks {
		req := &payloads.SignRequestPayload{UniqueIdentifier: pair.PrivateKeyUniqueIdentifier, Data: chunk, CorrelationValue: token}
		if i == 0 {
			req.InitIndicator = &yes
			req.CryptographicParameters = &sigcp
		}
		if i == 2 {
			req.FinalIndicator = &yes
		}
		resp := must(c.Request(ctx, req)).(*payloads.SignResponsePayload)
		if i == 0 {
			token = resp.CorrelationValue
		}
		if i < 2 && len(resp.SignatureData) != 0 {
			panic("early signature output")
		}
		if i == 2 {
			digest := sha256.Sum256(message)
			if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], resp.SignatureData); err != nil {
				panic(err)
			}
		}
	}
	if v.ProtocolVersionMinor >= 4 {
		nonce := bytes.Repeat([]byte{4}, 12)
		aad := []byte("bound envelope context")
		aead := must(cipher.NewGCM(block))
		encrypted := aead.Seal(nil, nonce, message, aad)
		token = nil
		gcp := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeGCM, PaddingMethod: kmip.PaddingMethodNone}
		for i, chunk := range [][]byte{encrypted[:19], encrypted[19 : len(encrypted)-16]} {
			req := &payloads.DecryptRequestPayload{UniqueIdentifier: id, Data: chunk, CorrelationValue: token}
			if i == 0 {
				req.InitIndicator = &yes
				req.CryptographicParameters = &gcp
				req.IVCounterNonce = nonce
				req.AuthenticatedEncryptionAdditionalData = aad
				req.AuthenticatedEncryptionTag = encrypted[len(encrypted)-16:]
			} else {
				req.FinalIndicator = &yes
			}
			resp := must(c.Request(ctx, req)).(*payloads.DecryptResponsePayload)
			if i == 0 {
				token = resp.CorrelationValue
				if len(resp.Data) != 0 {
					panic("unauthenticated GCM prefix exposed")
				}
			} else if !bytes.Equal(resp.Data, message) {
				panic("multipart GCM differs from Go")
			}
		}
	}
	fmt.Printf("PASS OVH %v multipart: independent Go CTR, SHA256, HMAC, RSA signatures and authenticated GCM (1.4)\n", v)
}
