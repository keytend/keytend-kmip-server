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
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"os"
	"path/filepath"
	"time"
)

func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func main() {
	p := os.Getenv("KMIP_PKI")
	if os.Getenv("KMIP_HTTPS_ONLY") == "1" {
		testHTTPS(p, os.Getenv("KMIP_HTTPS_PORT"))
		return
	}
	port := os.Getenv("KMIP_PORT")
	if port == "" {
		port = "15696"
	}
	versions := []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4}
	testNegatives(p, port, versions)
	for _, v := range versions {
		c := must(kmipclient.Dial("localhost:"+port, kmipclient.WithClientCertFiles(filepath.Join(p, "client.pem"), filepath.Join(p, "client.key")), kmipclient.WithRootCAFile(filepath.Join(p, "ca.pem")), kmipclient.EnforceVersion(v)))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		q := must(c.Query().Operations().Objects().ServerInformation().ExecContext(ctx))
		if len(q.Operations) == 0 {
			panic("no operations")
		}
		testHashOperations(ctx, c, v)
		testMultipart(ctx, c, v)
		testAttributes(ctx, c, v)
		testMetadata(ctx, c, v)
		testECScalarDecode(ctx, c, v)
		testEC(ctx, c, v)
		testArchive(ctx, c, v)
		testWrapping(ctx, c, v)
		if v.ProtocolVersionMinor >= 4 {
			testTransfer(ctx, c, v)
		}
		testDerivation(ctx, c, v)
		testRekey(ctx, c, v)
		if v.ProtocolVersionMinor >= 1 {
			testRekeyPair(ctx, c, v)
		}
		initialCount := int64(999)
		limitedID := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
			WithAttribute(kmip.AttributeNameUsageLimits, kmip.UsageLimits{UsageLimitsTotal: 5, UsageLimitsCount: &initialCount, UsageLimitsUnit: kmip.UsageLimitsUnitObject}).ExecContext(ctx)).UniqueIdentifier
		must(c.Activate(limitedID).ExecContext(ctx))
		lease := must(c.ObtainLease(limitedID).ExecContext(ctx))
		if lease.LeaseTime <= 0 || lease.LeaseTime > 3600*time.Second || lease.LastChangeDate.IsZero() {
			panic("invalid lease response")
		}
		must(c.Check(limitedID).WithUsageLimitsCount(5).WithCryptographicUsageMask(kmip.CryptographicUsageEncrypt).WithLeaseTime(time.Second).ExecContext(ctx))
		must(c.GetUsageAllocation(limitedID, 2).ExecContext(ctx))
		readLimits := func() kmip.UsageLimits {
			attrs := must(c.GetAttributes(limitedID, kmip.AttributeNameUsageLimits).ExecContext(ctx))
			if len(attrs.Attribute) != 1 {
				panic("Usage Limits attribute missing")
			}
			switch limits := attrs.Attribute[0].AttributeValue.(type) {
			case kmip.UsageLimits:
				return limits
			case *kmip.UsageLimits:
				return *limits
			default:
				panic("SDK decoded an unexpected Usage Limits type")
			}
		}
		limits := readLimits()
		if limits.UsageLimitsTotal != 5 || limits.UsageLimitsCount == nil || *limits.UsageLimitsCount != 3 {
			panic("allocation did not decrement usage")
		}
		must(c.Check(limitedID).WithUsageLimitsCount(3).ExecContext(ctx))
		must(c.GetUsageAllocation(limitedID, 3).ExecContext(ctx))
		limits = readLimits()
		if limits.UsageLimitsCount == nil || *limits.UsageLimitsCount != 0 {
			panic("allocation was not permanent")
		}
		if _, err := c.GetUsageAllocation(limitedID, 1).ExecContext(ctx); err == nil {
			panic("exhausted key allocated again")
		}
		must(c.Revoke(limitedID).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(limitedID).ExecContext(ctx))
		for _, mode := range []kmip.BatchErrorContinuationOption{kmip.BatchErrorContinuationOptionUndo, kmip.BatchErrorContinuationOptionStop, kmip.BatchErrorContinuationOptionContinue} {
			id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
			key := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
			msg := kmip.NewRequestMessage(v,
				&payloads.ActivateRequestPayload{UniqueIdentifier: id},
				&payloads.GetRequestPayload{UniqueIdentifier: "nonexistent-ovh-batch-key"},
				&payloads.GetAttributesRequestPayload{UniqueIdentifier: id, AttributeName: []kmip.AttributeName{kmip.AttributeNameState}},
			)
			msg.Header.BatchErrorContinuationOption = mode
			// RoundTrip retains the SDK's codec/transport and permits the shorter
			// responses required by Stop and Undo; BatchOpt requires equal counts.
			resp := must(c.RoundTrip(ctx, &msg))
			expectedCount := 2
			if mode == kmip.BatchErrorContinuationOptionContinue {
				expectedCount = 3
			}
			if len(resp.BatchItem) != expectedCount || int(resp.Header.BatchCount) != expectedCount {
				panic("batch count mismatch")
			}
			for i, item := range resp.BatchItem {
				if !bytes.Equal(item.UniqueBatchItemID, msg.BatchItem[i].UniqueBatchItemID) {
					panic("batch ID mismatch")
				}
			}
			firstStatus := kmip.ResultStatusSuccess
			expectedState := kmip.StateActive
			if mode == kmip.BatchErrorContinuationOptionUndo {
				firstStatus = kmip.ResultStatusOperationUndone
				expectedState = kmip.StatePreActive
				if resp.BatchItem[0].ResponsePayload == nil {
					panic("required undone payload missing")
				}
			}
			if resp.BatchItem[0].ResultStatus != firstStatus || resp.BatchItem[1].ResultStatus != kmip.ResultStatusOperationFailed {
				panic("batch status mismatch")
			}
			if expectedCount == 3 && resp.BatchItem[2].ResultStatus != kmip.ResultStatusSuccess {
				panic("Continue did not continue")
			}
			state := must(c.GetAttributes(id, kmip.AttributeNameState).ExecContext(ctx))
			if len(state.Attribute) != 1 || state.Attribute[0].AttributeValue != expectedState {
				panic("batch state was not persisted correctly")
			}
			if !bytes.Equal(key, must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())) {
				panic("batch changed key material")
			}
			if expectedState == kmip.StateActive {
				must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
			}
			must(c.Destroy(id).ExecContext(ctx))
		}
		created := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).WithName(fmt.Sprintf("ovh-interop-%v", v)).ExecContext(ctx))
		id := created.UniqueIdentifier
		key := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
		if len(key) != 32 {
			panic("wrong length")
		}
		must(c.Activate(id).ExecContext(ctx))
		a := must(c.GetAttributes(id, kmip.AttributeNameState).ExecContext(ctx))
		if len(a.Attribute) == 0 {
			panic("no state")
		}
		found := must(c.Locate().WithName(fmt.Sprintf("ovh-interop-%v", v)).ExecContext(ctx))
		if len(found.UniqueIdentifier) == 0 {
			panic("not located")
		}
		if v.ProtocolVersionMinor >= 2 {
			testRSA(ctx, c, v)

			block := must(aes.NewCipher(key))
			for _, mode := range []kmip.BlockCipherMode{kmip.BlockCipherModeECB, kmip.BlockCipherModeCBC, kmip.BlockCipherModeCFB, kmip.BlockCipherModeOFB, kmip.BlockCipherModeCTR} {
				data := bytes.Repeat([]byte("0123456789abcdef"), 4)
				iv := []byte("0123456789abcdef")
				if mode == kmip.BlockCipherModeECB {
					iv = nil
				}
				if mode == kmip.BlockCipherModeCFB || mode == kmip.BlockCipherModeOFB || mode == kmip.BlockCipherModeCTR {
					data = data[:37]
				}
				want := make([]byte, len(data))
				switch mode {
				case kmip.BlockCipherModeECB:
					for offset := 0; offset < len(data); offset += aes.BlockSize {
						block.Encrypt(want[offset:offset+aes.BlockSize], data[offset:offset+aes.BlockSize])
					}
				case kmip.BlockCipherModeCBC:
					cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, data)
				case kmip.BlockCipherModeCFB:
					cipher.NewCFBEncrypter(block, iv).XORKeyStream(want, data)
				case kmip.BlockCipherModeOFB:
					cipher.NewOFB(block, iv).XORKeyStream(want, data)
				case kmip.BlockCipherModeCTR:
					cipher.NewCTR(block, iv).XORKeyStream(want, data)
				}
				cp := kmip.CryptographicParameters{BlockCipherMode: mode, PaddingMethod: kmip.PaddingMethodNone}
				encrypted := must(c.Encrypt(id).WithCryptographicParameters(cp).WithIvCounterNonce(iv).Data(data).ExecContext(ctx))
				if !bytes.Equal(encrypted.Data, want) || len(encrypted.IVCounterNonce) != 0 {
					panic("AES result differs from independent Go cipher")
				}
				decrypted := must(c.Decrypt(id).WithCryptographicParameters(cp).WithIvCounterNonce(iv).Data(encrypted.Data).ExecContext(ctx))
				if !bytes.Equal(decrypted.Data, data) {
					panic("AES decrypt mismatch")
				}
			}
			storedCP := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeECB}
			storedID := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).WithAttribute(kmip.AttributeNameCryptographicParameters, storedCP).ExecContext(ctx)).UniqueIdentifier
			must(c.Activate(storedID).ExecContext(ctx))
			storedKey := must(must(c.Get(storedID).ExecContext(ctx)).SymmetricKey())
			storedBlock := must(aes.NewCipher(storedKey))
			data := []byte("0123456789abcdef")
			want := make([]byte, 16)
			storedBlock.Encrypt(want, data)
			if !bytes.Equal(must(c.Encrypt(storedID).Data(data).ExecContext(ctx)).Data, want) {
				panic("stored parameters were not used")
			}
			must(c.Revoke(storedID).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
			must(c.Destroy(storedID).ExecContext(ctx))
			if v.ProtocolVersionMinor >= 4 {
				for tagLen := 12; tagLen <= 16; tagLen++ {
					random := true
					cp := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeGCM, RandomIV: &random, TagLength: int32(tagLen), IVLength: 96}
					aad := []byte("authenticated database context")
					encrypted := must(c.Encrypt(id).WithCryptographicParameters(cp).WithAAD(aad).Data(data).ExecContext(ctx))
					aead := must(cipher.NewGCMWithTagSize(block, tagLen))
					want := aead.Seal(nil, encrypted.IVCounterNonce, data, aad)
					combined := append(append([]byte{}, encrypted.Data...), encrypted.AuthenticatedEncryptionTag...)
					if !bytes.Equal(combined, want) {
						panic("GCM bytes differ from independent Go AEAD")
					}
					cp.RandomIV = nil
					plain := must(c.Decrypt(id).WithCryptographicParameters(cp).WithIvCounterNonce(encrypted.IVCounterNonce).WithAAD(aad).WithAuthTag(encrypted.AuthenticatedEncryptionTag).Data(encrypted.Data).ExecContext(ctx))
					if !bytes.Equal(plain.Data, data) {
						panic("GCM tag-length decrypt mismatch")
					}
				}
			}
			randomIV := true
			cp := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeGCM, RandomIV: &randomIV}
			if v.ProtocolVersionMinor < 4 {
				cp.BlockCipherMode = kmip.BlockCipherModeCBC
				cp.PaddingMethod = kmip.PaddingMethodPKCS5
			}
			encrypted := must(c.Encrypt(id).WithCryptographicParameters(cp).Data([]byte("database payload")).ExecContext(ctx))
			cp.RandomIV = nil
			plain := must(c.Decrypt(id).WithCryptographicParameters(cp).WithIvCounterNonce(encrypted.IVCounterNonce).WithAuthTag(encrypted.AuthenticatedEncryptionTag).Data(encrypted.Data).ExecContext(ctx))
			if !bytes.Equal(plain.Data, []byte("database payload")) {
				panic("decrypt mismatch")
			}
		}
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(id).ExecContext(ctx))
		if _, err := c.Get(id).ExecContext(ctx); err == nil {
			panic("Destroyed key returned")
		}
		c.Close()
		cancel()
		fmt.Printf("PASS OVH %v: discovery, lifecycle, Locate, attributes, usage allocation/exhaustion, leases, Check, batch Stop/Continue/Undo, AES modes and stored parameters (1.2+), independent Go GCM tag lengths (1.4)\n", v)
	}
}

// All ciphertexts and signatures are checked by Go crypto/rsa, independently
// of the Rust server's OpenSSL implementation and the KMIP codec.
func testRSA(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	pair := must(c.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign|kmip.CryptographicUsageDecrypt, kmip.CryptographicUsageVerify|kmip.CryptographicUsageEncrypt).ExecContext(ctx))
	privateID, publicID := pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier
	private := must(must(c.Get(privateID).ExecContext(ctx)).RsaPrivateKey())
	public := &private.PublicKey
	must(c.Activate(privateID).ExecContext(ctx))
	must(c.Activate(publicID).ExecContext(ctx))
	message := []byte("database envelope key and context")
	for _, algorithm := range []kmip.HashingAlgorithm{kmip.HashingAlgorithmSHA_1, kmip.HashingAlgorithmSHA_256, kmip.HashingAlgorithmSHA_384, kmip.HashingAlgorithmSHA_512} {
		cp := kmip.CryptographicParameters{PaddingMethod: kmip.PaddingMethodOAEP, HashingAlgorithm: algorithm}
		h := sha1.New()
		switch algorithm {
		case kmip.HashingAlgorithmSHA_256:
			h = sha256.New()
		case kmip.HashingAlgorithmSHA_384:
			h = sha512.New384()
		case kmip.HashingAlgorithmSHA_512:
			h = sha512.New()
		}
		// Before 1.4, the protocol cannot transmit a separate MGF hash; it is SHA-1.
		// For 1.4, choose matching hashes to use Go's high-level OAEP helper.
		if v.ProtocolVersionMinor >= 4 {
			cp.MaskGeneratorHashingAlgorithm = algorithm
			cp.PSource = []byte("database-a")
		}
		ciphertext := must(c.Encrypt(publicID).WithCryptographicParameters(cp).Data(message).ExecContext(ctx)).Data
		if v.ProtocolVersionMinor >= 4 || algorithm == kmip.HashingAlgorithmSHA_1 {
			plain := must(rsa.DecryptOAEP(h, rand.Reader, private, ciphertext, cp.PSource))
			if !bytes.Equal(plain, message) {
				panic("server OAEP differs from Go decryption")
			}
			independent := must(rsa.EncryptOAEP(h, rand.Reader, public, message, cp.PSource))
			plain = must(c.Decrypt(privateID).WithCryptographicParameters(cp).Data(independent).ExecContext(ctx)).Data
			if !bytes.Equal(plain, message) {
				panic("server cannot decrypt Go OAEP")
			}
		}
		plain := must(c.Decrypt(privateID).WithCryptographicParameters(cp).Data(ciphertext).ExecContext(ctx)).Data
		if !bytes.Equal(plain, message) {
			panic("OAEP roundtrip mismatch")
		}
		cp.HashingAlgorithm = kmip.HashingAlgorithmSHA_256
		if _, err := c.Decrypt(privateID).WithCryptographicParameters(cp).Data(make([]byte, 256)).ExecContext(ctx); err == nil {
			panic("corrupt OAEP accepted")
		}
	}
	digest := sha256.Sum256(message)
	// Combined Digital Signature Algorithm must select SHA-256 without a separate hash field.
	cp := kmip.CryptographicParameters{DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithm(5)}
	signature := must(c.Sign(privateID).WithCryptographicParameters(cp).Data(message).ExecContext(ctx)).SignatureData
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		panic(err)
	}
	if v.ProtocolVersionMinor >= 4 {
		for _, salt := range []int32{0, 32, 64, 222} {
			// Go's PSS options use zero to mean auto, not a zero-byte salt.
			cp = kmip.CryptographicParameters{PaddingMethod: kmip.PaddingMethodPSS, HashingAlgorithm: kmip.HashingAlgorithmSHA_256, MaskGeneratorHashingAlgorithm: kmip.HashingAlgorithmSHA_256, SaltLength: &salt}
			signature = must(c.Sign(privateID).WithCryptographicParameters(cp).DigestedData(digest[:]).ExecContext(ctx)).SignatureData
			opts := &rsa.PSSOptions{SaltLength: int(salt), Hash: crypto.SHA256}
			if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, opts); err != nil {
				panic(err)
			}
			// A raw-data request must verify a signature over exactly that digest.
			verified := must(c.SignatureVerify(publicID).WithCryptographicParameters(cp).Data(message).Signature(signature).ExecContext(ctx))
			if verified.ValidityIndicator != kmip.ValidityIndicatorValid {
				panic("PSS signature invalid")
			}
			if salt != 0 {
				independent := must(rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], opts))
				verified = must(c.SignatureVerify(publicID).WithCryptographicParameters(cp).DigestedData(digest[:]).Signature(independent).ExecContext(ctx))
				if verified.ValidityIndicator != kmip.ValidityIndicatorValid {
					panic("Go PSS signature invalid")
				}
			}
		}
		// Explicitly missing Salt Length must use the KMIP block-size default (64).
		cp.SaltLength = nil
		signature = must(c.Sign(privateID).WithCryptographicParameters(cp).Data(message).ExecContext(ctx)).SignatureData
		if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA256}); err != nil {
			panic(err)
		}
		// Also exercise the SDK's production crypto.Signer adapter with prehashed data.
		signer := must(c.Signer(ctx, privateID, publicID))
		signature = must(signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}))
		if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}); err != nil {
			panic(err)
		}
	}
	for _, id := range []string{privateID, publicID} {
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(id).ExecContext(ctx))
	}
	fmt.Printf("PASS OVH %v: RSA OAEP with independent Go cryptography, combined RSA signatures, PSS and crypto.Signer (1.4)\n", v)
}

func testAttributes(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
	custom := kmip.AttributeName("x-database-id")
	for i, value := range []string{"first", "second"} {
		r := must(c.AddAttribute(id, custom, value).ExecContext(ctx))
		if r.Attribute.AttributeIndex == nil || *r.Attribute.AttributeIndex != int32(i) || customAttributeValue(r.Attribute) != value {
			panic("invalid added custom attribute")
		}
	}
	must(c.AddAttribute(id, kmip.AttributeName("x-other"), int32(42)).ExecContext(ctx))
	deleted := must(c.DeleteAttribute(id, custom).ExecContext(ctx))
	if customAttributeValue(deleted.Attribute) != "first" {
		panic("deleted wrong attribute")
	}
	got := must(c.GetAttributes(id, custom).ExecContext(ctx))
	if len(got.Attribute) != 1 || got.Attribute[0].AttributeIndex == nil || *got.Attribute[0].AttributeIndex != 1 || customAttributeValue(got.Attribute[0]) != "second" {
		panic("surviving index changed")
	}
	must(c.ModifyAttribute(id, custom, "modified").WithIndex(1).ExecContext(ctx))
	if _, err := c.ModifyAttribute(id, custom, "absent-zero").ExecContext(ctx); err == nil {
		panic("modified absent index zero")
	}
	if _, err := c.AddAttribute(id, custom, "bad-index").WithIndex(0).ExecContext(ctx); err == nil {
		panic("Add accepted an index")
	}
	if _, err := c.AddAttribute(id, kmip.AttributeName("y-owned"), "forbidden").ExecContext(ctx); err == nil {
		panic("client created server attribute")
	}
	missing := must(c.GetAttributes(id, kmip.AttributeName("x-absent")).ExecContext(ctx))
	if len(missing.Attribute) != 0 {
		panic("missing attributes were returned")
	}
	list := must(c.GetAttributeList(id).ExecContext(ctx))
	count := 0
	for _, name := range list.AttributeName {
		if name == custom {
			count++
		}
	}
	if count != 1 {
		panic("list must contain each custom name once")
	}
	must(c.AddAttribute(id, custom, "reuse-zero").ExecContext(ctx))
	got = must(c.GetAttributes(id, custom).ExecContext(ctx))
	if len(got.Attribute) != 2 || *got.Attribute[0].AttributeIndex != 0 || *got.Attribute[1].AttributeIndex != 1 {
		panic("index reuse changed existing instance")
	}
	must(c.Destroy(id).ExecContext(ctx))
	fmt.Printf("PASS OVH %v: custom attribute values, stable indices, mutation, missing attributes, reserved prefix and index rejection\n", v)
}

func customAttributeValue(attribute kmip.Attribute) any {
	value, ok := attribute.AttributeValue.(ttlv.Value)
	if !ok || value.Tag != kmip.TagAttributeValue {
		panic("custom value was not decoded as the SDK TTLV value")
	}
	return value.Value
}

func testRekey(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	activation := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
	if v.ProtocolVersionMajor == 1 && v.ProtocolVersionMinor == 0 {
		// KMIP 1.0 replaces a past Activation Date with the request time; a
		// Process Start Date before that time is then refused (1.0 section 3.20).
		activation = time.Now().UTC().Truncate(time.Second)
	}
	process := activation.Add(time.Minute)
	protect := activation.Add(time.Hour)
	deactivation := activation.Add(2 * time.Hour)
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName(fmt.Sprintf("ovh-rekey-%v", v)).
		WithAttribute(kmip.AttributeNameActivationDate, activation).
		WithAttribute(kmip.AttributeNameProcessStartDate, process).
		WithAttribute(kmip.AttributeNameProtectStopDate, protect).
		WithAttribute(kmip.AttributeNameDeactivationDate, deactivation).ExecContext(ctx)).UniqueIdentifier
	original := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
	next := must(c.Rekey(id).WithOffset(time.Hour).ExecContext(ctx)).UniqueIdentifier
	replacement := must(must(c.Get(next).ExecContext(ctx)).SymmetricKey())
	if next == id || len(replacement) != 32 || bytes.Equal(replacement, original) || !bytes.Equal(original, must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())) {
		panic("Re-key did not preserve the old key and generate independent material")
	}
	read := func(id string, name kmip.AttributeName) any {
		attrs := must(c.GetAttributes(id, name).ExecContext(ctx)).Attribute
		if len(attrs) != 1 {
			panic("expected exactly one Re-key attribute")
		}
		return attrs[0].AttributeValue
	}
	link := func(id string) kmip.Link {
		switch x := read(id, kmip.AttributeNameLink).(type) {
		case kmip.Link:
			return x
		case *kmip.Link:
			return *x
		default:
			panic("SDK decoded an unexpected Link type")
		}
	}
	forward, reverse := link(id), link(next)
	if forward.LinkType != kmip.LinkTypeReplacementObjectLink || forward.LinkedObjectIdentifier != next || reverse.LinkType != kmip.LinkTypeReplacedObjectLink || reverse.LinkedObjectIdentifier != id {
		panic("Re-key history links are not reciprocal")
	}
	initialized := read(next, kmip.AttributeNameInitialDate).(time.Time)
	shifted := initialized.Add(time.Hour)
	for name, want := range map[kmip.AttributeName]time.Time{
		kmip.AttributeNameActivationDate:   shifted,
		kmip.AttributeNameProcessStartDate: shifted.Add(time.Minute),
		kmip.AttributeNameProtectStopDate:  shifted.Add(time.Hour),
		kmip.AttributeNameDeactivationDate: shifted.Add(2 * time.Hour),
	} {
		if !read(next, name).(time.Time).Equal(want) {
			panic("Re-key offset changed relative lifecycle dates")
		}
	}
	if read(next, kmip.AttributeNameState) != kmip.StatePreActive {
		panic("future replacement was activated prematurely")
	}
	if _, err := c.Rekey(id).ExecContext(ctx); err == nil {
		panic("source acquired a second replacement")
	}
	must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
	must(c.Destroy(id).ExecContext(ctx))
	must(c.Destroy(next).ExecContext(ctx))
	fmt.Printf("PASS OVH %v: Re-key reciprocal links, offset dates and retained original key\n", v)
}

func testRekeyPair(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	activation := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
	deactivation := activation.Add(2 * time.Hour)
	pair := must(c.CreateKeyPair().RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
		Common().WithAttribute(kmip.AttributeNameActivationDate, activation).
		WithAttribute(kmip.AttributeNameDeactivationDate, deactivation).
		WithAttribute(kmip.AttributeNameObjectGroup, "common-pair").
		PrivateKey().WithName(fmt.Sprintf("ovh-private-pair-%v", v)).
		PublicKey().WithName(fmt.Sprintf("ovh-public-pair-%v", v)).ExecContext(ctx))
	original := must(must(c.Get(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx)).RsaPrivateKey())
	next := must(c.RekeyKeyPair(pair.PrivateKeyUniqueIdentifier).WithOffset(time.Hour).
		PrivateKey().WithAttribute(kmip.AttributeNameObjectGroup, "private-pair").ExecContext(ctx))
	private := must(must(c.Get(next.PrivateKeyUniqueIdentifier).ExecContext(ctx)).RsaPrivateKey())
	public := must(must(c.Get(next.PublicKeyUniqueIdentifier).ExecContext(ctx)).RsaPublicKey())
	if private.N.Cmp(original.N) == 0 || private.N.Cmp(public.N) != 0 || private.E != public.E {
		panic("replacement RSA material is not a fresh matching pair")
	}
	before := must(must(c.Get(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx)).RsaPrivateKey())
	if original.N.Cmp(before.N) != 0 || original.D.Cmp(before.D) != 0 {
		panic("Re-key Key Pair changed original material")
	}
	one := func(id string, name kmip.AttributeName) any {
		attrs := must(c.GetAttributes(id, name).ExecContext(ctx)).Attribute
		if len(attrs) != 1 {
			panic("expected one key pair attribute")
		}
		return attrs[0].AttributeValue
	}
	checkLink := func(id string, kind kmip.LinkType, target string) {
		attrs := must(c.GetAttributes(id, kmip.AttributeNameLink).ExecContext(ctx)).Attribute
		found := 0
		for _, a := range attrs {
			var link kmip.Link
			switch value := a.AttributeValue.(type) {
			case kmip.Link:
				link = value
			case *kmip.Link:
				link = *value
			default:
				panic("unexpected SDK Link value")
			}
			if link.LinkType == kind {
				if link.LinkedObjectIdentifier != target {
					panic("pair history has wrong target")
				}
				found++
			}
		}
		if found != 1 {
			panic("pair history link absent or duplicated")
		}
	}
	checkLink(pair.PrivateKeyUniqueIdentifier, kmip.LinkTypeReplacementObjectLink, next.PrivateKeyUniqueIdentifier)
	checkLink(pair.PublicKeyUniqueIdentifier, kmip.LinkTypeReplacementObjectLink, next.PublicKeyUniqueIdentifier)
	checkLink(next.PrivateKeyUniqueIdentifier, kmip.LinkTypeReplacedObjectLink, pair.PrivateKeyUniqueIdentifier)
	checkLink(next.PublicKeyUniqueIdentifier, kmip.LinkTypeReplacedObjectLink, pair.PublicKeyUniqueIdentifier)
	checkLink(next.PrivateKeyUniqueIdentifier, kmip.LinkTypePublicKeyLink, next.PublicKeyUniqueIdentifier)
	checkLink(next.PublicKeyUniqueIdentifier, kmip.LinkTypePrivateKeyLink, next.PrivateKeyUniqueIdentifier)
	for _, id := range []string{next.PrivateKeyUniqueIdentifier, next.PublicKeyUniqueIdentifier} {
		initialized := one(id, kmip.AttributeNameInitialDate).(time.Time)
		if !one(id, kmip.AttributeNameActivationDate).(time.Time).Equal(initialized.Add(time.Hour)) || !one(id, kmip.AttributeNameDeactivationDate).(time.Time).Equal(initialized.Add(3*time.Hour)) {
			panic("pair Offset dates do not preserve the old interval")
		}
		if one(id, kmip.AttributeNameState) != kmip.StatePreActive {
			panic("future key pair activated prematurely")
		}
		must(c.Activate(id).ExecContext(ctx))
	}
	digest := sha256.Sum256([]byte("independent RSA pair replacement"))
	signature := must(rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		panic(err)
	}
	if err := rsa.VerifyPKCS1v15(&original.PublicKey, crypto.SHA256, digest[:], signature); err == nil {
		panic("replacement signature verified under old key")
	}
	if v.ProtocolVersionMinor >= 2 {
		signed := must(c.Sign(next.PrivateKeyUniqueIdentifier).WithCryptographicParameters(kmip.CryptographicParameters{PaddingMethod: kmip.PaddingMethodPKCS1V1_5, HashingAlgorithm: kmip.HashingAlgorithmSHA_256}).Data([]byte("server rekey pair proof")).ExecContext(ctx))
		hash := sha256.Sum256([]byte("server rekey pair proof"))
		if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, hash[:], signed.SignatureData); err != nil {
			panic(err)
		}
	}
	if _, err := c.RekeyKeyPair(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx); err == nil {
		panic("pair history forked")
	}
	for _, id := range []string{pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier, next.PrivateKeyUniqueIdentifier, next.PublicKeyUniqueIdentifier} {
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(id).ExecContext(ctx))
	}
	fmt.Printf("PASS OVH %v: Re-key Key Pair reciprocal history, dates and independent Go RSA signatures\n", v)
}

// Reference RFC3394/5649 implementation over Go AES, independent of OpenSSL.
func referenceKeyWrap(key, input []byte, padded, encrypt bool) []byte {
	block := must(aes.NewCipher(key))
	if encrypt {
		value := append([]byte(nil), input...)
		a := bytes.Repeat([]byte{0xa6}, 8)
		if padded {
			a = []byte{0xa6, 0x59, 0x59, 0xa6, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(a[4:], uint32(len(value)))
			for len(value)%8 != 0 {
				value = append(value, 0)
			}
			if len(value) == 8 {
				out := append(a, value...)
				block.Encrypt(out, out)
				return out
			}
		}
		n := len(value) / 8
		for j := 0; j < 6; j++ {
			for i := 1; i <= n; i++ {
				b := append(append([]byte(nil), a...), value[(i-1)*8:i*8]...)
				block.Encrypt(b, b)
				binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(b[:8])^uint64(n*j+i))
				copy(value[(i-1)*8:i*8], b[8:])
			}
		}
		return append(a, value...)
	}
	a := append([]byte(nil), input[:8]...)
	value := append([]byte(nil), input[8:]...)
	n := len(value) / 8
	if padded && n == 1 {
		b := append(a, value...)
		block.Decrypt(b, b)
		a = b[:8]
		value = b[8:]
	} else {
		for j := 5; j >= 0; j-- {
			for i := n; i >= 1; i-- {
				b := make([]byte, 16)
				binary.BigEndian.PutUint64(b, binary.BigEndian.Uint64(a)^uint64(n*j+i))
				copy(b[8:], value[(i-1)*8:i*8])
				block.Decrypt(b, b)
				copy(a, b[:8])
				copy(value[(i-1)*8:i*8], b[8:])
			}
		}
	}
	if padded {
		if !bytes.Equal(a[:4], []byte{0xa6, 0x59, 0x59, 0xa6}) {
			panic("invalid KWP integrity prefix")
		}
		length := int(binary.BigEndian.Uint32(a[4:]))
		if length <= len(value)-8 || length > len(value) {
			panic("invalid KWP length")
		}
		for _, b := range value[length:] {
			if b != 0 {
				panic("invalid KWP padding")
			}
		}
		return value[:length]
	}
	if !bytes.Equal(a, bytes.Repeat([]byte{0xa6}, 8)) {
		panic("invalid KW integrity value")
	}
	return value
}
func testWrapping(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	targetID := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
	target := must(must(c.Get(targetID).ExecContext(ctx)).SymmetricKey())
	option := kmip.EncodingOptionNoEncoding
	plain := append([]byte(nil), target...)
	if v.ProtocolVersionMinor == 0 {
		option = 0
		plain = append([]byte{0x42, 0, 0x45, 1, 0, 0, 0, 40, 0x42, 0, 0x43, 8, 0, 0, 0, 32}, target...)
	}
	for _, mode := range []kmip.BlockCipherMode{kmip.BlockCipherModeNISTKeyWrap, kmip.BlockCipherModeAESKeyWrapPadding} {
		cp := kmip.CryptographicParameters{BlockCipherMode: mode}
		keyID := must(c.Create().AES(128, kmip.CryptographicUsageMask(48)).WithAttribute(kmip.AttributeNameCryptographicParameters, cp).ExecContext(ctx)).UniqueIdentifier
		key := must(must(c.Get(keyID).ExecContext(ctx)).SymmetricKey())
		must(c.Activate(keyID).ExecContext(ctx))
		spec := kmip.KeyWrappingSpecification{WrappingMethod: kmip.WrappingMethodEncrypt, EncodingOption: option, EncryptionKeyInformation: &kmip.EncryptionKeyInformation{UniqueIdentifier: keyID}}
		result := must(c.Get(targetID).WithKeyWrapping(spec).ExecContext(ctx))
		object := result.Object.(*kmip.SymmetricKey)
		if object.KeyBlock.KeyValue.Wrapped == nil || object.KeyBlock.KeyWrappingData == nil {
			panic("server did not return a wrapped key")
		}
		ciphertext := *object.KeyBlock.KeyValue.Wrapped
		padded := mode == kmip.BlockCipherModeAESKeyWrapPadding
		if !bytes.Equal(referenceKeyWrap(key, ciphertext, padded, false), plain) {
			panic("independent Go unwrap differs from key value")
		}
		independent := referenceKeyWrap(key, plain, padded, true)
		if !bytes.Equal(independent, ciphertext) {
			panic("AES wrapping differs from independent Go implementation")
		}
		object.KeyBlock.KeyValue.Wrapped = &independent
		message := kmip.NewRequestMessage(v, &payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSymmetricKey, TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt}}}, Object: object})
		response := must(c.RoundTrip(ctx, &message))
		if response.BatchItem[0].ResultStatus != kmip.ResultStatusSuccess {
			panic("independently wrapped key was not registered")
		}
		imported := response.BatchItem[0].ResponsePayload.(*payloads.RegisterResponsePayload).UniqueIdentifier
		if !bytes.Equal(must(must(c.Get(imported).ExecContext(ctx)).SymmetricKey()), target) {
			panic("wrapped Register changed key bytes")
		}
		must(c.Destroy(imported).ExecContext(ctx))
		must(c.Revoke(keyID).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(keyID).ExecContext(ctx))
	}
	cp := kmip.CryptographicParameters{PaddingMethod: kmip.PaddingMethodOAEP, HashingAlgorithm: kmip.HashingAlgorithmSHA_256}
	mgf := crypto.SHA1
	var label []byte
	if v.ProtocolVersionMinor >= 4 {
		mgf = crypto.SHA256
		label = []byte("KMIP wrapped transfer")
		cp.MaskGenerator = kmip.MaskGeneratorMGF1
		cp.MaskGeneratorHashingAlgorithm = kmip.HashingAlgorithmSHA_256
		cp.PSource = label
	}
	pair := must(c.CreateKeyPair().RSA(2048, kmip.CryptographicUsageMask(32), kmip.CryptographicUsageMask(16)).Common().WithAttribute(kmip.AttributeNameCryptographicParameters, cp).ExecContext(ctx))
	secret := must(must(c.Get(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx)).RsaPrivateKey())
	must(c.Activate(pair.PrivateKeyUniqueIdentifier).ExecContext(ctx))
	must(c.Activate(pair.PublicKeyUniqueIdentifier).ExecContext(ctx))
	wrapped := must(c.Get(targetID).WithKeyWrapping(kmip.KeyWrappingSpecification{WrappingMethod: kmip.WrappingMethodEncrypt, EncodingOption: option, EncryptionKeyInformation: &kmip.EncryptionKeyInformation{UniqueIdentifier: pair.PublicKeyUniqueIdentifier}}).ExecContext(ctx)).Object.(*kmip.SymmetricKey)
	recovered := must(secret.Decrypt(rand.Reader, *wrapped.KeyBlock.KeyValue.Wrapped, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: mgf, Label: label}))
	if !bytes.Equal(recovered, plain) {
		panic("Go OAEP unwrapping differs from wrapped Key Value")
	}
	for _, id := range []string{pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier} {
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(id).ExecContext(ctx))
	}
	must(c.Destroy(targetID).ExecContext(ctx))
	fmt.Printf("PASS OVH %v: AES KW/KWP and RSA OAEP wrapped Get; independently wrapped Register with exact material\n", v)
}

func testTransfer(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	initial := int64(999)
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithAttribute(kmip.AttributeNameUsageLimits, kmip.UsageLimits{UsageLimitsTotal: 10, UsageLimitsCount: &initial, UsageLimitsUnit: kmip.UsageLimitsUnitObject}).ExecContext(ctx)).UniqueIdentifier
	key := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
	must(c.Activate(id).ExecContext(ctx))
	must(c.GetUsageAllocation(id, 3).ExecContext(ctx))
	exported := must(c.Export(id).ExecContext(ctx))
	importedID := "ovh-transfer-" + id
	attributes := append([]kmip.Attribute(nil), exported.Attribute...)
	for i := range attributes {
		if attributes[i].AttributeName == kmip.AttributeNameUniqueIdentifier {
			attributes[i].AttributeValue = importedID
		}
	}
	// The SDK's convenience Import builder currently omits its object argument.
	// Its public payload and RoundTrip API still provide independent wire coding.
	transfer := &payloads.ImportRequestPayload{UniqueIdentifier: importedID, Attribute: attributes, Object: exported.Object}
	importOnce := func() kmip.ResponseBatchItem {
		message := kmip.NewRequestMessage(v, transfer)
		return must(c.RoundTrip(ctx, &message)).BatchItem[0]
	}
	if item := importOnce(); item.ResultStatus != kmip.ResultStatusSuccess {
		panic(fmt.Sprintf("Import failed: %+v", item))
	}
	if !bytes.Equal(must(must(c.Get(importedID).ExecContext(ctx)).SymmetricKey()), key) {
		panic("Import changed material")
	}
	actual := must(c.Export(importedID).ExecContext(ctx))
	var foundCount bool
	for _, attribute := range actual.Attribute {
		if attribute.AttributeName == kmip.AttributeNameUsageLimits {
			value := attribute.AttributeValue.(kmip.UsageLimits)
			if value.UsageLimitsCount == nil || *value.UsageLimitsCount != 7 {
				panic("Import reset remaining count")
			}
			foundCount = true
		}
	}
	if !foundCount {
		panic("Import dropped Usage Limits")
	}
	if importOnce().ResultReason != kmip.ResultReasonObjectAlreadyExists {
		panic("Import collision accepted")
	}
	transfer.ReplaceExisting = true
	if importOnce().ResultStatus != kmip.ResultStatusSuccess {
		panic("Replace Existing failed")
	}
	must(c.Revoke(importedID).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
	must(c.Destroy(importedID).ExecContext(ctx))
	must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
	must(c.Destroy(id).ExecContext(ctx))
	fmt.Println("PASS OVH 1.4: Export and Import retain exact keys and usage counts; collisions rejected and owned replacement succeeds")
}

func testDerivation(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	cp := kmip.CryptographicParameters{BlockCipherMode: kmip.BlockCipherModeECB}
	base := must(c.Create().AES(256, kmip.CryptographicUsageMask(512)).WithAttribute(kmip.AttributeNameCryptographicParameters, cp).ExecContext(ctx)).UniqueIdentifier
	key := must(must(c.Get(base).ExecContext(ctx)).SymmetricKey())
	must(c.Activate(base).ExecContext(ctx))
	derive := func(ids []string, kind kmip.ObjectType, bits int32, method kmip.DerivationMethod, params kmip.DerivationParameters) string {
		attributes := []kmip.Attribute{{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: bits}, {AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt}}
		if kind == kmip.ObjectTypeSymmetricKey {
			attributes = append(attributes, kmip.Attribute{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES})
		}
		return must(c.DeriveKey().ObjectType(kind).WithUniqueIdentifiers(ids...).WithDerivationMethod(method).WithDerivationParameters(params).WithTemplateAttribute(kmip.TemplateAttribute{Attribute: attributes}).ExecContext(ctx)).UniqueIdentifier
	}
	check := func(id string, expected []byte) {
		result := must(c.Get(id).ExecContext(ctx))
		var actual []byte
		switch object := result.Object.(type) {
		case *kmip.SymmetricKey:
			actual = must(object.KeyBlock.GetBytes())
		case *kmip.SecretData:
			actual = must(object.Data())
		default:
			panic("Wrong derived type")
		}
		if !bytes.Equal(actual, expected) {
			panic("Derived material differs from independent Go cryptography")
		}
		must(c.Destroy(id).ExecContext(ctx))
	}
	digest := sha256.Sum256(key)
	id := derive([]string{base}, kmip.ObjectTypeSymmetricKey, 256, kmip.DerivationMethodHASH, kmip.DerivationParameters{CryptographicParameters: &kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256}})
	check(id, digest[:])
	input := []byte("0123456789abcdef0123456789abcdef")
	block := must(aes.NewCipher(key))
	expected := make([]byte, len(input))
	for offset := 0; offset < len(input); offset += 16 {
		block.Encrypt(expected[offset:offset+16], input[offset:offset+16])
	}
	id = derive([]string{base}, kmip.ObjectTypeSymmetricKey, 256, kmip.DerivationMethodENCRYPT, kmip.DerivationParameters{CryptographicParameters: &cp, DerivationData: input})
	check(id, expected)
	hmacID := must(c.Create().SymmetricKey(kmip.CryptographicAlgorithmHMACSHA256, 256, kmip.CryptographicUsageMask(512)).ExecContext(ctx)).UniqueIdentifier
	hmacKey := must(must(c.Get(hmacID).ExecContext(ctx)).SymmetricKey())
	must(c.Activate(hmacID).ExecContext(ctx))
	mac := func(data []byte) []byte { h := hmac.New(sha256.New, hmacKey); _, _ = h.Write(data); return h.Sum(nil) }
	id = derive([]string{hmacID}, kmip.ObjectTypeSymmetricKey, 256, kmip.DerivationMethodHMAC, kmip.DerivationParameters{DerivationData: input})
	check(id, mac(input))
	label := []byte("label\x00database-context")
	fixed := append(append([]byte{}, label...), 0, 0, 2, 0)
	for _, method := range []kmip.DerivationMethod{5, 6, 7} {
		var iteration []byte
		params := kmip.DerivationParameters{DerivationData: label}
		if method == 6 {
			iteration = make([]byte, 32)
			params.InitializationVector = append([]byte{}, iteration...)
		}
		if method == 7 {
			iteration = append([]byte{}, fixed...)
		}
		var output []byte
		for i := uint32(1); i <= 2; i++ {
			if method == 7 {
				iteration = mac(iteration)
			}
			counter := make([]byte, 4)
			binary.BigEndian.PutUint32(counter, i)
			data := append(append(append([]byte{}, iteration...), counter...), fixed...)
			value := mac(data)
			output = append(output, value...)
			if method == 6 {
				iteration = value
			}
		}
		id = derive([]string{hmacID}, kmip.ObjectTypeSecretData, 512, method, params)
		check(id, output)
	}
	password := []byte("independent password")
	value := &kmip.SecretData{SecretDataType: kmip.SecretDataTypePassword, KeyBlock: kmip.KeyBlock{KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &password}}}}}
	message := kmip.NewRequestMessage(v, &payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSecretData, TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageMask(512)}}}, Object: value})
	response := must(c.RoundTrip(ctx, &message))
	if response.BatchItem[0].ResultStatus != kmip.ResultStatusSuccess {
		panic("Password registration failed")
	}
	passwordID := response.BatchItem[0].ResponsePayload.(*payloads.RegisterResponsePayload).UniqueIdentifier
	must(c.Activate(passwordID).ExecContext(ctx))
	if actual := must(c.Get(passwordID).ExecContext(ctx)).Object.(*kmip.SecretData); actual.SecretDataType != kmip.SecretDataTypePassword {
		panic("Password type changed")
	}
	id = derive([]string{passwordID}, kmip.ObjectTypeSymmetricKey, 256, kmip.DerivationMethodPBKDF2, kmip.DerivationParameters{Salt: []byte("database salt"), IterationCount: 4096, CryptographicParameters: &kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256}})
	expected = must(pbkdf2.Key(sha256.New, string(password), []byte("database salt"), 4096, 32))
	check(id, expected)
	for _, id := range []string{base, hmacID, passwordID} {
		must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(c.Destroy(id).ExecContext(ctx))
	}
	fmt.Printf("PASS OVH %v: HASH, HMAC, AES and three NIST KDFs match Go cryptography; Password PBKDF2 matches Go PBKDF2\n", v)
}

func testMetadata(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
	read := func(id string, name kmip.AttributeName) any {
		r := must(c.GetAttributes(id, name).ExecContext(ctx))
		if len(r.Attribute) != 1 {
			panic("Mandatory attribute missing")
		}
		return r.Attribute[0].AttributeValue
	}
	if v.ProtocolVersionMinor >= 1 && !read(id, kmip.AttributeNameFresh).(bool) {
		panic("New object is not Fresh")
	}
	if v.ProtocolVersionMinor >= 2 && !read(id, kmip.AttributeNameOriginalCreationDate).(time.Time).Equal(read(id, kmip.AttributeNameInitialDate).(time.Time)) {
		panic("Generated origin date differs from initial date")
	}
	if v.ProtocolVersionMinor >= 3 && read(id, kmip.AttributeNameRandomNumberGenerator).(kmip.RNGParameters).RNGAlgorithm != kmip.RNGAlgorithmUnspecified {
		panic("RNG metadata is inaccurate")
	}
	must(c.Get(id).ExecContext(ctx))
	if v.ProtocolVersionMinor >= 1 && read(id, kmip.AttributeNameFresh).(bool) {
		panic("Retrieved object is still Fresh")
	}
	must(c.Destroy(id).ExecContext(ctx))
	if v.ProtocolVersionMinor >= 4 {
		id = must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).WithAttribute(kmip.AttributeNameSensitive, true).WithAttribute(kmip.AttributeNameExtractable, false).ExecContext(ctx)).UniqueIdentifier
		if !read(id, kmip.AttributeNameAlwaysSensitive).(bool) || !read(id, kmip.AttributeNameNeverExtractable).(bool) {
			panic("Initial extraction histories incorrect")
		}
		must(c.ModifyAttribute(id, kmip.AttributeNameSensitive, false).ExecContext(ctx))
		must(c.ModifyAttribute(id, kmip.AttributeNameExtractable, true).ExecContext(ctx))
		must(c.Get(id).ExecContext(ctx))
		must(c.ModifyAttribute(id, kmip.AttributeNameSensitive, true).ExecContext(ctx))
		must(c.ModifyAttribute(id, kmip.AttributeNameExtractable, false).ExecContext(ctx))
		if read(id, kmip.AttributeNameAlwaysSensitive).(bool) || read(id, kmip.AttributeNameNeverExtractable).(bool) {
			panic("Extraction history reverted")
		}
		must(c.Destroy(id).ExecContext(ctx))
	}
	fmt.Printf("PASS OVH %v: versioned Fresh, creation date, RNG and extraction histories\n", v)
}

func testArchive(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	id := must(c.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).ExecContext(ctx)).UniqueIdentifier
	original := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
	must(c.Archive(id).ExecContext(ctx))
	message := kmip.NewRequestMessage(v, &payloads.GetRequestPayload{UniqueIdentifier: id})
	item := must(c.RoundTrip(ctx, &message)).BatchItem[0]
	if item.ResultReason != kmip.ResultReasonObjectArchived {
		panic("Archived object was accessible")
	}
	online := must(c.Locate().WithStorageStatusMask(kmip.StorageStatusMask(1)).ExecContext(ctx))
	for _, value := range online.UniqueIdentifier {
		if value == id {
			panic("Archived object in online Locate")
		}
	}
	archived := must(c.Locate().WithStorageStatusMask(kmip.StorageStatusMask(2)).ExecContext(ctx))
	found := false
	for _, value := range archived.UniqueIdentifier {
		found = found || value == id
	}
	if !found {
		panic("Archived object not located")
	}
	must(c.Recover(id).ExecContext(ctx))
	restored := must(must(c.Get(id).ExecContext(ctx)).SymmetricKey())
	if !bytes.Equal(original, restored) {
		panic("Recovery changed key material")
	}
	r := must(c.GetAttributes(id).ExecContext(ctx))
	for _, a := range r.Attribute {
		if a.AttributeName == kmip.AttributeNameArchiveDate {
			panic("Recovery retained Archive Date")
		}
	}
	must(c.Destroy(id).ExecContext(ctx))
	fmt.Printf("PASS OVH %v: Archive denies Get, storage Locate selects archived objects, Recover preserves exact bytes\n", v)
}

func testEC(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	for _, curve := range []kmip.RecommendedCurve{kmip.RecommendedCurve(7), kmip.RecommendedCurve(10)} {
		pair := must(c.CreateKeyPair().ECDSA(curve, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).ExecContext(ctx))
		privateID, publicID := pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier
		private := getECPrivate(ctx, c, privateID)
		public := must(must(c.Get(publicID).ExecContext(ctx)).EcdsaPublicKey())
		if private.PublicKey.X.Cmp(public.X) != 0 || private.PublicKey.Y.Cmp(public.Y) != 0 {
			panic("EC pair mismatch")
		}
		must(c.Activate(privateID).ExecContext(ctx))
		must(c.Activate(publicID).ExecContext(ctx))
		if v.ProtocolVersionMinor >= 2 {
			cp := kmip.CryptographicParameters{HashingAlgorithm: kmip.HashingAlgorithmSHA_256}
			message := []byte("independent Go ECDSA verification")
			digest := sha256.Sum256(message)
			signature := must(c.Sign(privateID).WithCryptographicParameters(cp).Data(message).ExecContext(ctx)).SignatureData
			if !ecdsa.VerifyASN1(public, digest[:], signature) {
				panic("Invalid server ECDSA signature")
			}
			independent := must(ecdsa.SignASN1(rand.Reader, private, digest[:]))
			verified := must(c.SignatureVerify(publicID).WithCryptographicParameters(cp).Data(message).Signature(independent).ExecContext(ctx))
			if verified.ValidityIndicator != kmip.ValidityIndicatorValid {
				panic("Go ECDSA signature rejected")
			}
			if v.ProtocolVersionMinor >= 4 {
				signer := must(c.Signer(ctx, privateID, publicID))
				signature = must(signer.Sign(rand.Reader, digest[:], crypto.SHA256))
				if !ecdsa.VerifyASN1(public, digest[:], signature) {
					panic("EC crypto.Signer failed")
				}
			}
		}
		if v.ProtocolVersionMinor == 0 {
			for _, id := range []string{privateID, publicID} {
				must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
				must(c.Destroy(id).ExecContext(ctx))
			}
			continue
		}
		next := must(c.RekeyKeyPair(privateID).ExecContext(ctx))
		replacement := getECPrivate(ctx, c, next.PrivateKeyUniqueIdentifier)
		if private.D.Cmp(replacement.D) == 0 || private.Curve.Params().Name != replacement.Curve.Params().Name {
			panic("EC replacement failed")
		}
		for _, id := range []string{privateID, publicID, next.PrivateKeyUniqueIdentifier, next.PublicKeyUniqueIdentifier} {
			must(c.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
			must(c.Destroy(id).ExecContext(ctx))
		}
	}
	tested := "P256/P384 generation and formats"
	if v.ProtocolVersionMinor >= 1 {
		tested += ", pair replacement"
	}
	if v.ProtocolVersionMinor >= 2 {
		tested += ", independent ECDSA verification"
	}
	if v.ProtocolVersionMinor >= 4 {
		tested += ", crypto.Signer"
	}
	fmt.Printf("PASS OVH %v: %s\n", v, tested)
}
