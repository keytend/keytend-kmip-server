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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
)

func testHashOperations(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	if v.ProtocolVersionMinor < 2 {
		return
	}
	message := bytes.Repeat([]byte{0, 1, 127, 128, 255, 17, 3}, 1801)
	mechanisms := []struct {
		id   kmip.HashingAlgorithm
		make func() hash.Hash
	}{
		{4, sha1.New}, {5, sha256.New224}, {6, sha256.New}, {7, sha512.New384}, {8, sha512.New},
		{12, sha512.New512_224}, {13, sha512.New512_256},
		{14, func() hash.Hash { return sha3.New224() }},
		{15, func() hash.Hash { return sha3.New256() }},
		{16, func() hash.Hash { return sha3.New384() }},
		{17, func() hash.Hash { return sha3.New512() }},
	}
	for _, mechanism := range mechanisms {
		if mechanism.id >= 14 && v.ProtocolVersionMinor < 4 {
			continue
		}
		oracle := mechanism.make()
		_, _ = oracle.Write(message)
		expected := oracle.Sum(nil)
		cp := kmip.CryptographicParameters{HashingAlgorithm: mechanism.id}
		response := must(c.Request(ctx, &payloads.HashRequestPayload{
			CryptographicParameters: cp, Data: message,
		})).(*payloads.HashResponsePayload)
		if !bytes.Equal(response.Data, expected) || len(response.CorrelationValue) != 0 {
			panic(fmt.Sprintf("Hash %d differs from independent Go digest", mechanism.id))
		}
		if v.ProtocolVersionMinor < 3 {
			continue
		}
		yes := true
		var token []byte
		chunks := [][]byte{message[:1], message[1:137], message[137:8193], message[8193:]}
		for i, chunk := range chunks {
			request := &payloads.HashRequestPayload{
				CryptographicParameters: cp, Data: chunk, CorrelationValue: token,
			}
			if i == 0 {
				request.InitIndicator = &yes
			}
			if i == len(chunks)-1 {
				request.FinalIndicator = &yes
			}
			response := must(c.Request(ctx, request)).(*payloads.HashResponsePayload)
			if i == 0 {
				token = response.CorrelationValue
				if len(token) != 32 {
					panic("Hash stream lacks its bound correlation token")
				}
			}
			if i < len(chunks)-1 && len(response.Data) != 0 {
				panic("Hash stream exposed an intermediate digest")
			}
			if i == len(chunks)-1 && (!bytes.Equal(response.Data, expected) || len(response.CorrelationValue) != 0) {
				panic(fmt.Sprintf("Multipart Hash %d differs from independent Go digest", mechanism.id))
			}
		}
	}
	fmt.Printf("PASS OVH version %d.%d SHA Hash mechanisms with independent Go single/multipart oracles\n", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
}
