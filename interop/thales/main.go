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
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
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
	port := os.Getenv("KMIP_PORT")
	if port == "" {
		port = "15696"
	}
	cert := must(tls.LoadX509KeyPair(filepath.Join(p, "client.pem"), filepath.Join(p, "client.key")))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(must(os.ReadFile(filepath.Join(p, "ca.pem")))) {
		panic("CA")
	}
	conn := must(tls.Dial("tcp", "localhost:"+port, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	send := func(op kmip14.Operation, payload any, out any) {
		msg := kmip.RequestMessage{RequestHeader: kmip.RequestHeader{ProtocolVersion: kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4}, BatchCount: 1}, BatchItem: []kmip.RequestBatchItem{{Operation: op, RequestPayload: payload}}}
		req := must(ttlv.Marshal(msg))
		if _, e := conn.Write(req); e != nil {
			panic(e)
		}
		raw := must(decoder.NextTTLV())
		var response kmip.ResponseMessage
		if e := decoder.DecodeValue(&response, raw); e != nil {
			panic(e)
		}
		if len(response.BatchItem) != 1 || response.BatchItem[0].ResultStatus != kmip14.ResultStatusSuccess {
			panic(fmt.Sprintf("operation %v: %+v", op, response))
		}
		encoded := must(ttlv.Marshal(response.BatchItem[0].ResponsePayload))
		if e := ttlv.Unmarshal(encoded, out); e != nil {
			panic(e)
		}
	}
	create := kmip.CreateRequestPayload{ObjectType: kmip14.ObjectTypeSymmetricKey}
	create.TemplateAttribute.Append(kmip14.TagCryptographicAlgorithm, kmip14.CryptographicAlgorithmAES)
	create.TemplateAttribute.Append(kmip14.TagCryptographicLength, 256)
	create.TemplateAttribute.Append(kmip14.TagCryptographicUsageMask, kmip14.CryptographicUsageMaskEncrypt|kmip14.CryptographicUsageMaskDecrypt)
	var created kmip.CreateResponsePayload
	send(kmip14.OperationCreate, &create, &created)
	var got kmip.GetResponsePayload
	send(kmip14.OperationGet, &kmip.GetRequestPayload{UniqueIdentifier: created.UniqueIdentifier}, &got)
	if got.SymmetricKey == nil {
		panic("missing symmetric key")
	}
	var destroyed kmip.DestroyResponsePayload
	send(kmip14.OperationDestroy, &kmip.DestroyRequestPayload{UniqueIdentifier: created.UniqueIdentifier}, &destroyed)
	fmt.Println("PASS Thales/Gemalto 1.4: independent codec Create, Get, Destroy")
}
