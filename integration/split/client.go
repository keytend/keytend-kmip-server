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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
	Method    uint32
	Format    uint32
	ID        string
}
type encoding struct {
	name, media string
	marshal     func(any) []byte
	unmarshal   func([]byte, any) error
}

func main() {
	pki, port, httpsPort := os.Getenv("KMIP_PKI"), os.Getenv("KMIP_PORT"), os.Getenv("KMIP_HTTPS_PORT")
	phase := os.Args[1]
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
	var records []record
	if phase == "verify" {
		must(struct{}{}, json.Unmarshal(must(os.ReadFile(os.Args[2])), &records))
	} else if phase != "create" {
		panic("invalid phase")
	}
	var created []record
	for minor := 0; minor <= 4; minor++ {
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
			success := func(payload kmip.OperationPayload) kmip.OperationPayload {
				response := exchange(payload)
				must(struct{}{}, response.Err())
				return response.ResponsePayload
			}
			check := func(r record) {
				response := success(&payloads.GetRequestPayload{UniqueIdentifier: r.ID}).(*payloads.GetResponsePayload)
				split, ok := response.Object.(*kmip.SplitKey)
				if !ok {
					panic("wrong object")
				}
				expected := makeShare(r.Method, r.Format)
				if split.SplitKeyParts != expected.SplitKeyParts || split.KeyPartIdentifier != expected.KeyPartIdentifier || split.SplitKeyThreshold != expected.SplitKeyThreshold || split.SplitKeyMethod != expected.SplitKeyMethod || split.KeyBlock.KeyFormatType != expected.KeyBlock.KeyFormatType {
					panic("split metadata differs")
				}
				if (split.PrimeFieldSize == nil) != (expected.PrimeFieldSize == nil) || split.PrimeFieldSize != nil && split.PrimeFieldSize.Cmp(expected.PrimeFieldSize) != 0 {
					panic("prime differs")
				}
				if !bytes.Equal(must(split.KeyBlock.GetBytes()), must(expected.KeyBlock.GetBytes())) {
					panic("share bytes differ")
				}
			}
			if phase == "create" {
				for method := uint32(1); method <= 4; method++ {
					for _, format := range []uint32{1, 2} {
						response := exchange(&payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSplitKey, Object: makeShare(method, format)})
						if method == 4 && minor < 2 {
							if response.ResultStatus != kmip.ResultStatusOperationFailed {
								panic("old version accepted GF8")
							}
							continue
						}
						must(struct{}{}, response.Err())
						key := response.ResponsePayload.(*payloads.RegisterResponsePayload).UniqueIdentifier
						r := record{minor, name, method, format, key}
						check(r)
						success(&payloads.ArchiveRequestPayload{UniqueIdentifier: key})
						if response := exchange(&payloads.GetRequestPayload{UniqueIdentifier: key}); response.ResultReason != kmip.ResultReasonObjectArchived {
							panic("archived share exposed")
						}
						success(&payloads.RecoverRequestPayload{UniqueIdentifier: key})
						check(r)
						created = append(created, r)
						fmt.Fprintf(os.Stderr, "PASS OVH split create %s %s method=%d format=%d\n", version, name, method, format)
					}
				}
			} else {
				for _, r := range records {
					if r.Minor != minor || r.Transport != name {
						continue
					}
					check(r)
					success(&payloads.DestroyRequestPayload{UniqueIdentifier: r.ID})
					if response := exchange(&payloads.GetRequestPayload{UniqueIdentifier: r.ID}); response.ResultStatus != kmip.ResultStatusOperationFailed {
						panic("destroyed share exposed")
					}
					fmt.Fprintf(os.Stderr, "PASS OVH split restart %s %s method=%d format=%d\n", version, name, r.Method, r.Format)
				}
			}
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
func makeShare(method, format uint32) *kmip.SplitKey {
	material := must(hex.DecodeString("66c46a7754f94de420c7b1a7fff5ec56"))
	result := &kmip.SplitKey{SplitKeyParts: 3, KeyPartIdentifier: 2, SplitKeyThreshold: 2, SplitKeyMethod: kmip.SplitKeyMethod(method)}
	if method == 1 {
		result.SplitKeyThreshold = 3
	}
	if method == 3 {
		result.PrimeFieldSize = big.NewInt(257)
		material = []byte{0, 254}
	}
	result.KeyBlock = kmip.KeyBlock{KeyFormatType: kmip.KeyFormatType(format), KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &material}}}}
	return result
}
