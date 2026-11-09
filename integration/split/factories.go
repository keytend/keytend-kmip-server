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
	Joined    string
	Parts     []string
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
			success := func(payload kmip.OperationPayload) kmip.OperationPayload {
				response := exchange(payload)
				must(struct{}{}, response.Err())
				return response.ResponsePayload
			}

			keyBytes := []byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
			check := func(key string) {
				response := success(&payloads.GetRequestPayload{UniqueIdentifier: key}).(*payloads.GetResponsePayload)
				object, ok := response.Object.(*kmip.SymmetricKey)
				if !ok || !bytes.Equal(must(object.KeyBlock.GetBytes()), keyBytes) {
					panic("reconstructed key differs")
				}
			}
			join := func(parts []string, method uint32) string {
				fields := []ttlv.Value{{Tag: 0x420057, Value: ttlv.Enum(2)}}
				for i, key := range parts {
					if method != 1 && i == 1 {
						continue
					}
					fields = append(fields, ttlv.Value{Tag: 0x420094, Value: key})
				}
				response := success(kmip.NewUnknownPayload(kmip.Operation(41), fields...)).(*kmip.UnknownPayload)
				return factoryIDs(response, minor, false)[0]
			}
			if phase == "create" {
				for method := uint32(1); method <= 4; method++ {
					for _, format := range []uint32{1, 2} {
						source := success(&payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSymmetricKey, Object: &kmip.SymmetricKey{KeyBlock: kmip.KeyBlock{
							KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &keyBytes}}},
							CryptographicAlgorithm: kmip.CryptographicAlgorithmAES, CryptographicLength: 128,
						}}}).(*payloads.RegisterResponsePayload).UniqueIdentifier
						threshold := int32(2)
						if method == 1 {
							threshold = 3
						}
						attributes := ttlv.Struct{}
						split := success(kmip.NewUnknownPayload(kmip.Operation(40),
							ttlv.Value{Tag: 0x420057, Value: ttlv.Enum(5)}, ttlv.Value{Tag: 0x420094, Value: source},
							ttlv.Value{Tag: 0x42008b, Value: int32(3)}, ttlv.Value{Tag: 0x42008c, Value: threshold},
							ttlv.Value{Tag: 0x42008a, Value: ttlv.Enum(method)}, ttlv.Value{Tag: 0x420091, Value: attributes},
						)).(*kmip.UnknownPayload)
						parts := factoryIDs(split, minor, true)
						if len(parts) != 3 {
							panic("wrong number of shares")
						}
						var external []string
						for i, key := range parts {
							got := success(&payloads.GetRequestPayload{UniqueIdentifier: key, KeyFormatType: kmip.KeyFormatType(format)}).(*payloads.GetResponsePayload)
							share, ok := got.Object.(*kmip.SplitKey)
							if !ok || share.SplitKeyParts != 3 || share.KeyPartIdentifier != int32(i+1) || share.SplitKeyThreshold != threshold || uint32(share.SplitKeyMethod) != method || uint32(share.KeyBlock.KeyFormatType) != format {
								panic("share metadata differs")
							}
							external = append(external, success(&payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSplitKey, Object: share}).(*payloads.RegisterResponsePayload).UniqueIdentifier)
						}
						check(join(external, method))
						joined := join(parts, method)
						check(joined)
						success(&payloads.DestroyRequestPayload{UniqueIdentifier: source})
						created = append(created, record{minor, name, method, format, joined, parts})
						fmt.Fprintf(os.Stderr, "PASS OVH factories %s %s method=%d format=%d; local and externally registered quorum\n", version, name, method, format)
					}
				}
				vector := []string{"66C46A7754F94DE420C7B1A7FFF5EC56", "CF93D1E2A7E593CD5B8D6247F4E5D49C", "A855B891F61AD9217240D8EC061E37DA", "803DBAD55CDD329FAD19D99AE2C5A415"}
				var parts []string
				for i, value := range vector {
					raw := must(hex.DecodeString(value))
					share := &kmip.SplitKey{SplitKeyParts: 4, KeyPartIdentifier: int32(i + 1), SplitKeyThreshold: 2, SplitKeyMethod: kmip.SplitKeyMethod(4), KeyBlock: kmip.KeyBlock{
						KeyFormatType: kmip.KeyFormatTypeRaw, KeyValue: &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: kmip.KeyMaterial{Bytes: &raw}}}, CryptographicAlgorithm: kmip.CryptographicAlgorithmAES, CryptographicLength: 128,
					}}
					parts = append(parts, success(&payloads.RegisterRequestPayload{ObjectType: kmip.ObjectTypeSplitKey, Object: share}).(*payloads.RegisterResponsePayload).UniqueIdentifier)
				}
				result := success(&payloads.GetRequestPayload{UniqueIdentifier: join(parts, 4)}).(*payloads.GetResponsePayload)
				expected := must(hex.DecodeString("0102030405060708090A0B0C0D0E0F10"))
				if !bytes.Equal(must(result.Object.(*kmip.SymmetricKey).KeyBlock.GetBytes()), expected) {
					panic("OASIS vector differs")
				}
			} else {
				for _, r := range records {
					if r.Minor == minor && r.Transport == name {
						check(r.Joined)
						check(join(r.Parts, r.Method))
						fmt.Fprintf(os.Stderr, "PASS OVH factories restart %s %s method=%d format=%d\n", version, name, r.Method, r.Format)
					}
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

// The pinned SDK exposes these operations through its supported UnknownPayload
// extension API. Its native codec and transports remain unmodified.
func factoryIDs(payload *kmip.UnknownPayload, minor int, create bool) []string {
	var ids []string
	objectTypes := 0
	for _, field := range payload.Fields {
		switch field.Tag {
		case 0x420094:
			ids = append(ids, field.Value.(string))
		case 0x420057:
			objectTypes++
			want := ttlv.Enum(2)
			if create {
				want = 5
			}
			if field.Value != want {
				panic("wrong factory Object Type")
			}
		default:
			panic("unexpected factory response field")
		}
	}
	if (minor == 2 && objectTypes != 1) || (minor != 2 && objectTypes != 0) {
		panic("versioned factory Object Type presence")
	}
	if len(ids) == 0 || (!create && len(ids) != 1) {
		panic("factory response identifiers")
	}
	return ids
}
