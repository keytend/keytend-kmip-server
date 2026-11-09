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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

// selfSigned returns a certificate that no configured trust store contains.
func selfSigned(cn string, ca bool) (certPEM, keyPEM []byte) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der := must(x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key))
	keyDER := must(x509.MarshalPKCS8PrivateKey(key))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// refusedTLS requires a transport-layer refusal: a failed handshake or the
// server's TLS 1.3 post-handshake alert on the first request, never a KMIP reply.
func refusedTLS(label string, dial func() (*kmipclient.Client, error), want string) string {
	c, err := dial()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = c.Query().Operations().ExecContext(ctx)
		cancel()
		_ = c.Close()
	}
	if err == nil {
		panic(label + ": accepted")
	}
	if strings.Contains(err.Error(), "Operation ") && strings.Contains(err.Error(), "failed (status=") {
		panic(label + ": refused at the KMIP layer instead of TLS: " + err.Error())
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		panic(fmt.Sprintf("%s: unexpected error %v", label, err))
	}
	return err.Error()
}

func kmipReason(label string, err error, reason string) {
	if err == nil || !strings.Contains(err.Error(), "reason=\""+reason+"\"") {
		panic(fmt.Sprintf("%s: expected %s, got %v", label, reason, err))
	}
}

// testNegatives checks principal/operation ACLs on every version and trust,
// hostname and identity refusals once, each followed by a good fresh request.
func testNegatives(p, port string, versions []kmip.ProtocolVersion) {
	addr := "localhost:" + port
	ca := kmipclient.WithRootCAFile(filepath.Join(p, "ca.pem"))
	identity := func(name string) kmipclient.Option {
		return kmipclient.WithClientCertFiles(filepath.Join(p, name+".pem"), filepath.Join(p, name+".key"))
	}
	for _, v := range versions {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		owner := must(kmipclient.Dial(addr, identity("client"), ca, kmipclient.EnforceVersion(v)))
		id := must(owner.Create().AES(256, kmip.CryptographicUsageEncrypt).ExecContext(ctx)).UniqueIdentifier
		must(owner.Activate(id).ExecContext(ctx))
		other := must(kmipclient.Dial(addr, identity("other"), ca, kmipclient.EnforceVersion(v)))
		_, err := other.Get(id).ExecContext(ctx)
		kmipReason("other principal Get", err, "ItemNotFound")
		_, err = other.Create().AES(256, kmip.CryptographicUsageEncrypt).ExecContext(ctx)
		kmipReason("read-only principal Create", err, "PermissionDenied")
		unlisted := must(kmipclient.Dial(addr, identity("unlisted"), ca, kmipclient.EnforceVersion(v)))
		_, err = unlisted.Query().Operations().ExecContext(ctx)
		kmipReason("CA-valid unlisted certificate", err, "PermissionDenied")
		_, err = owner.Get("keytend-ovh-missing-object").ExecContext(ctx)
		kmipReason("missing object", err, "ItemNotFound")
		must(owner.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).ExecContext(ctx))
		must(owner.Destroy(id).ExecContext(ctx))
		if _, err = owner.Get(id).ExecContext(ctx); err == nil {
			panic("Get after Destroy returned material")
		}
		for _, c := range []*kmipclient.Client{owner, other, unlisted} {
			_ = c.Close()
		}
		cancel()
		fmt.Printf("PASS OVH %v: other principal Get ItemNotFound, read-only Create and unlisted certificate PermissionDenied, missing object ItemNotFound, refusal after Destroy\n", v)
	}
	v := versions[len(versions)-1]
	wrongCA, _ := selfSigned("ovh-wrong-ca", true)
	e1 := refusedTLS("wrong server CA", func() (*kmipclient.Client, error) {
		return kmipclient.Dial(addr, identity("client"), kmipclient.WithRootCAPem(wrongCA), kmipclient.EnforceVersion(v))
	}, "certificate signed by unknown authority")
	// The server certificate names localhost, 127.0.0.1 and keytend-kmip-server only.
	e2 := refusedTLS("wrong hostname", func() (*kmipclient.Client, error) {
		return kmipclient.Dial(addr, identity("client"), ca, kmipclient.WithServerName("wrong-kmip.example"), kmipclient.EnforceVersion(v))
	}, "not wrong-kmip.example")
	e3 := refusedTLS("missing client certificate", func() (*kmipclient.Client, error) {
		return kmipclient.Dial(addr, ca, kmipclient.EnforceVersion(v))
	}, "")
	certPEM, keyPEM := selfSigned("client", false)
	e4 := refusedTLS("untrusted client certificate", func() (*kmipclient.Client, error) {
		return kmipclient.Dial(addr, kmipclient.WithClientCertPEM(certPEM, keyPEM), ca, kmipclient.EnforceVersion(v))
	}, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fresh := must(kmipclient.Dial(addr, identity("client"), ca, kmipclient.EnforceVersion(v)))
	defer fresh.Close()
	id := must(fresh.Create().AES(256, kmip.CryptographicUsageEncrypt).ExecContext(ctx)).UniqueIdentifier
	first := must(fresh.Get(id).ExecContext(ctx)).Object.(*kmip.SymmetricKey)
	second := must(fresh.Get(id).ExecContext(ctx)).Object.(*kmip.SymmetricKey)
	if !bytes.Equal(must(first.KeyMaterial()), must(second.KeyMaterial())) {
		panic("repeated Get changed the material")
	}
	fmt.Printf("PASS OVH %v: wrong server CA (%s), wrong hostname (%s), missing (%s) and untrusted (%s) client certificates refused; fresh authorized request succeeds\n", v, e1, e2, e3, e4)
}
