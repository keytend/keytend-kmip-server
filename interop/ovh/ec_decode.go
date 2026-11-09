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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"math/big"
	"strings"
)

// KMIP encodes D as a mathematical Big Integer. The pinned SDK passes
// D.Bytes() to Go's fixed-width ParseRawPrivateKey, losing leading zero octets.
// Compare the SDK's decoded integer with its independent PKCS#8 decoder for
// every key, including generated replacements. Never bias server generation.
func getECPrivate(ctx context.Context, c *kmipclient.Client, id string) *ecdsa.PrivateKey {
	transparent := must(c.Get(id).ExecContext(ctx))
	key := transparent.Object.(*kmip.PrivateKey)
	material := must(key.KeyBlock.GetMaterial())
	scalar := material.TransparentECPrivateKey
	if scalar == nil && material.TransparentECDSAPrivateKey != nil {
		scalar = (*kmip.TransparentECPrivateKey)(material.TransparentECDSAPrivateKey)
	}
	if scalar == nil {
		panic("missing transparent EC scalar")
	}
	decoded := must(must(c.Get(id).WithKeyFormat(kmip.KeyFormatTypePKCS_8).ExecContext(ctx)).EcdsaPrivateKey())
	if scalar.D.Cmp(decoded.D) != 0 {
		panic("transparent and PKCS8 scalar differ")
	}
	x, y := decoded.Curve.ScalarBaseMult(scalar.D.Bytes())
	if x.Cmp(decoded.X) != 0 || y.Cmp(decoded.Y) != 0 {
		panic("transparent scalar does not match public point")
	}
	return decoded
}

func testECScalarDecode(ctx context.Context, c *kmipclient.Client, v kmip.ProtocolVersion) {
	curve := elliptic.P256()
	d := big.NewInt(1)
	x, y := curve.ScalarBaseMult(d.Bytes())
	fixture := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	id := must(c.Register().WithKeyFormat(kmipclient.Transparent).EcdsaPrivateKey(fixture, kmip.CryptographicUsageSign).ExecContext(ctx)).UniqueIdentifier
	// This records a deterministic SDK defect, not a server/SDK qualification pass.
	raw := must(c.Get(id).ExecContext(ctx))
	_, err := raw.EcdsaPrivateKey()
	if err == nil || !strings.Contains(err.Error(), "invalid scalar length") {
		panic("pinned SDK scalar limitation changed; reassess adapter")
	}
	if getECPrivate(ctx, c, id).D.Cmp(d) != 0 {
		panic("small scalar changed")
	}
	must(c.Destroy(id).ExecContext(ctx))
	fmt.Printf("KNOWN SDK LIMITATION OVH %v: transparent small EC scalar rejected by SDK helper; decoded integer and PKCS8 exact scalar independently verified\n", v)
}
