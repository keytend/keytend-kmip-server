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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

type record struct {
	Minor     int
	Transport string
	PGP       int32
	Format    uint32
	ID        string
	Digest    string
}
type encoding struct {
	name, media string
	marshal     func(any) []byte
	unmarshal   func([]byte, any) error
}

func main() {
	pki, port, httpsPort := os.Getenv("KMIP_PKI"), os.Getenv("KMIP_PORT"), os.Getenv("KMIP_HTTPS_PORT")
	phase := os.Args[1]
	fixtures := os.Args[3]
	cert := must(tls.LoadX509KeyPair(filepath.Join(pki, "client.pem"), filepath.Join(pki, "client.key")))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(must(os.ReadFile(filepath.Join(pki, "ca.pem")))) {
		panic("no root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	encodings := []encoding{{"HTTPS-TTLV", "application/octet-stream", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV},
		{"HTTPS-JSON", "application/json", ttlv.MarshalJSON, ttlv.UnmarshalJSON}, {"HTTPS-XML", "text/xml", ttlv.MarshalXML, ttlv.UnmarshalXML}}
	if phase == "probe" {
		var results []map[string]any
		data := must(os.ReadFile(filepath.Join(fixtures, "v4_public.asc")))
		for minor := 2; minor <= 4; minor++ {
			for _, format := range encodings[1:] {
				object := &kmip.PGPKey{PGPKeyVersion: 4, KeyBlock: kmip.KeyBlock{KeyFormatType: kmip.KeyFormatTypeRaw,
					KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &data}}}, CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA, CryptographicLength: 2048}}
				operation := &payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypePGPKey, TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageMask(2)}, {AttributeName: kmip.AttributeNameDigitalSignatureAlgorithm, AttributeValue: kmip.DigitalSignatureAlgorithm(7)}}}, Object: object}
				message := kmip.NewRequestMessage(kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: int32(minor)}, operation)
				request := must(http.NewRequest("POST", "https://localhost:"+httpsPort+"/kmip", bytes.NewReader(format.marshal(&message))))
				request.Header.Set("Content-Type", format.media)
				request.Header.Set("Accept", format.media)
				response := must(httpClient.Do(request))
				body := must(io.ReadAll(io.LimitReader(response.Body, 65536)))
				must(struct{}{}, response.Body.Close())
				if response.StatusCode != 200 {
					panic("probe HTTP envelope")
				}
				var decoded kmip.ResponseMessage
				must(struct{}{}, format.unmarshal(body, &decoded))
				if len(decoded.BatchItem) != 1 || decoded.BatchItem[0].ResultStatus != kmip.ResultStatusOperationFailed || uint32(decoded.BatchItem[0].ResultReason) != 4 {
					panic("default-name probe did not reproduce the invalid wire name")
				}
				results = append(results, map[string]any{"version": fmt.Sprintf("1.%d", minor), "transport": format.name, "result_reason": 4, "client_outcome": "FAIL_CLIENT"})
			}
		}
		must(struct{}{}, json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "known_sdk_limitation", "emitted_name": ttlv.EnumName(kmip.TagDigitalSignatureAlgorithm, 7), "canonical_name": "SHA_512WithRSAEncryptionPKCS_1V1_5", "records": results}))
		return
	}
	// Explicit consumer configuration, before any concurrent SDK use. Retain
	// default-name probe results separately; the library itself is unchanged.
	if os.Getenv("KMIP_PGP_CANONICAL_SIGNATURE_NAMES") == "1" {
		ttlv.RegisterEnum(kmip.TagDigitalSignatureAlgorithm, map[kmip.DigitalSignatureAlgorithm]string{7: "SHA_512WithRSAEncryptionPKCS_1V1_5"})
	}
	var records []record
	if phase == "verify" {
		must(struct{}{}, json.Unmarshal(must(os.ReadFile(os.Args[2])), &records))
	} else if phase != "create" {
		panic("invalid phase")
	}
	var created []record
	for minor := 2; minor <= 4; minor++ {
		version := kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: int32(minor)}
		client := must(kmipclient.Dial("localhost:"+port, kmipclient.WithClientCertFiles(filepath.Join(pki, "client.pem"), filepath.Join(pki, "client.key")),
			kmipclient.WithRootCAFile(filepath.Join(pki, "ca.pem")), kmipclient.EnforceVersion(version)))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		for _, name := range []string{"TLS", "HTTPS-TTLV", "HTTPS-JSON", "HTTPS-XML"} {
			exchange := func(payload kmip.OperationPayload) kmip.ResponseBatchItem {
				message := kmip.NewRequestMessage(version, payload)
				if name == "TLS" {
					response := must(client.RoundTrip(ctx, &message))
					if len(response.BatchItem) != 1 {
						panic("invalid batch")
					}
					return response.BatchItem[0]
				}
				var format encoding
				for _, candidate := range encodings {
					if candidate.name == name {
						format = candidate
					}
				}
				request := must(http.NewRequestWithContext(ctx, "POST", "https://localhost:"+httpsPort+"/kmip", bytes.NewReader(format.marshal(&message))))
				request.Header.Set("Content-Type", format.media)
				request.Header.Set("Accept", format.media)
				response := must(httpClient.Do(request))
				body := must(io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1)))
				must(struct{}{}, response.Body.Close())
				if response.StatusCode != 200 || response.Header.Get("Content-Type") != format.media {
					panic("HTTP envelope")
				}
				var decoded kmip.ResponseMessage
				must(struct{}{}, format.unmarshal(body, &decoded))
				if len(decoded.BatchItem) != 1 {
					panic("invalid batch")
				}
				return decoded.BatchItem[0]
			}
			success := func(p kmip.OperationPayload) kmip.OperationPayload {
				r := exchange(p)
				if r.ResultStatus != kmip.ResultStatusSuccess {
					panic(fmt.Sprintf("operation failed: %v %v", r.ResultReason, r.ResultMessage))
				}
				return r.ResponsePayload
			}
			verify := func(r record) {
				attributes := success(&payloads.GetAttributesRequestPayload{UniqueIdentifier: r.ID, AttributeName: []kmip.AttributeName{kmip.AttributeNameDigitalSignatureAlgorithm}}).(*payloads.GetAttributesResponsePayload)
				if len(attributes.Attribute) != 1 || attributes.Attribute[0].AttributeValue != kmip.DigitalSignatureAlgorithm(7) {
					panic("typed signature attribute changed")
				}
				for _, format := range []kmip.KeyFormatType{kmip.KeyFormatTypeRaw, kmip.KeyFormatTypeOpaque} {
					response := success(&payloads.GetRequestPayload{UniqueIdentifier: r.ID, KeyFormatType: format}).(*payloads.GetResponsePayload)
					obj, ok := response.Object.(*kmip.PGPKey)
					if !ok || response.ObjectType != kmip.ObjectTypePGPKey || obj.PGPKeyVersion != r.PGP {
						panic("PGP container changed")
					}
					block := &obj.KeyBlock
					if block.KeyFormatType != format || block.CryptographicAlgorithm != kmip.CryptographicAlgorithmRSA || block.CryptographicLength != 2048 {
						panic("PGP metadata changed")
					}
					data := must(block.GetBytes())
					if fmt.Sprintf("%x", sha256.Sum256(data)) != r.Digest {
						panic("PGP material changed")
					}
				}
			}
			if phase == "create" {
				for _, fixtureName := range []string{"v3_public", "v4_public", "v4_private"} {
					pgp := int32(4)
					if fixtureName == "v3_public" {
						pgp = 3
					}
					data := must(os.ReadFile(filepath.Join(fixtures, fixtureName+".asc")))
					for _, format := range []kmip.KeyFormatType{kmip.KeyFormatTypeRaw, kmip.KeyFormatTypeOpaque} {
						obj := &kmip.PGPKey{PGPKeyVersion: pgp, KeyBlock: kmip.KeyBlock{KeyFormatType: format,
							KeyValue:               &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &data}}},
							CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA, CryptographicLength: 2048}}
						response := success(&payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypePGPKey, TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageMask(0)}, {AttributeName: kmip.AttributeNameDigitalSignatureAlgorithm, AttributeValue: kmip.DigitalSignatureAlgorithm(7)}}}, Object: obj}).(*payloads.RegisterResponsePayload)
						r := record{minor, name, pgp, uint32(format), response.UniqueIdentifier, fmt.Sprintf("%x", sha256.Sum256(data))}
						verify(r)
						created = append(created, r)
					}
				}
			} else {
				for _, r := range records {
					if r.Minor == minor && r.Transport == name {
						verify(r)
					}
				}
			}
			fmt.Fprintf(os.Stderr, "PASS typed OVH PGP 1.%d %s %s\n", minor, name, phase)
		}
		cancel()
		must(struct{}{}, client.Close())
	}
	if phase == "create" {
		must(struct{}{}, json.NewEncoder(os.Stdout).Encode(created))
	} else {
		fmt.Println(`{"status":"passed"}`)
	}
}
