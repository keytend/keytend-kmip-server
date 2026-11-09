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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// Independent SDK encoders/decoders over Go's authenticated HTTP/1.1 transport.
// This SDK implements 1.x; the Java SDK independently covers the 2.x editions.
func testHTTPS(pki, port string) {
	cert := must(tls.LoadX509KeyPair(filepath.Join(pki, "client.pem"), filepath.Join(pki, "client.key")))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(must(os.ReadFile(filepath.Join(pki, "ca.pem")))) {
		panic("missing test root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	type encoding struct {
		name, media string
		marshal     func(any) []byte
		unmarshal   func([]byte, any) error
	}
	formats := []encoding{{"TTLV", "application/octet-stream", ttlv.MarshalTTLV, ttlv.UnmarshalTTLV}, {"JSON", "application/json", ttlv.MarshalJSON, ttlv.UnmarshalJSON}, {"XML", "text/xml", ttlv.MarshalXML, ttlv.UnmarshalXML}}
	for _, v := range []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4} {
		for _, input := range formats {
			exchange := func(output encoding, payload kmip.OperationPayload) kmip.OperationPayload {
				message := kmip.NewRequestMessage(v, payload)
				req := must(http.NewRequest(http.MethodPost, "https://localhost:"+port+"/kmip", bytes.NewReader(input.marshal(&message))))
				req.Header.Set("Content-Type", input.media)
				req.Header.Set("Accept", output.media)
				req.Header.Set("Cache-Control", "no-cache")
				response := must(client.Do(req))
				body := must(io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1)))
				must(struct{}{}, response.Body.Close())
				if response.StatusCode != 200 || response.Header.Get("Content-Type") != output.media || response.Header.Get("Cache-Control") != "no-cache" || response.ContentLength != int64(len(body)) {
					panic("invalid HTTP response envelope")
				}
				var decoded kmip.ResponseMessage
				must(struct{}{}, output.unmarshal(body, &decoded))
				if len(decoded.BatchItem) != 1 || decoded.BatchItem[0].ResultStatus != kmip.ResultStatusSuccess {
					panic("unexpected KMIP batch failure")
				}
				return decoded.BatchItem[0].ResponsePayload
			}
			id := exchange(input, &payloads.CreateRequestPayload{ObjectType: kmip.ObjectTypeSymmetricKey, TemplateAttribute: kmip.TemplateAttribute{Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameCryptographicUsageMask, AttributeValue: kmip.CryptographicUsageEncrypt | kmip.CryptographicUsageDecrypt},
				{AttributeName: kmip.AttributeNameUsageLimits, AttributeValue: kmip.UsageLimits{UsageLimitsTotal: 1 << 60, UsageLimitsUnit: kmip.UsageLimitsUnitObject}},
			}}}).(*payloads.CreateResponsePayload).UniqueIdentifier
			var key []byte
			for _, output := range formats {
				got := must(exchange(output, &payloads.GetRequestPayload{UniqueIdentifier: id}).(*payloads.GetResponsePayload).SymmetricKey())
				if len(got) != 32 || key != nil && !bytes.Equal(key, got) {
					panic("cross-encoding key bytes differ")
				}
				key = got
				attrs := exchange(output, &payloads.GetAttributesRequestPayload{UniqueIdentifier: id, AttributeName: []kmip.AttributeName{kmip.AttributeNameUsageLimits}}).(*payloads.GetAttributesResponsePayload)
				if len(attrs.Attribute) != 1 {
					panic("missing long-integer fixture")
				}
				limits, ok := attrs.Attribute[0].AttributeValue.(kmip.UsageLimits)
				if !ok || limits.UsageLimitsTotal != 1<<60 {
					panic("64-bit integer precision lost")
				}
			}
			exchange(input, &payloads.DestroyRequestPayload{UniqueIdentifier: id})
			clear(key)
			fmt.Printf("PASS OVH SDK %s HTTPS %s: Create, Get, Destroy, all response encodings and exact 64-bit Usage Limits\n", v, input.name)
		}
	}
}
