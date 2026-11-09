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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipclient/kmiphttp"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
func require(ok bool) {
	if !ok {
		panic("assertion failed")
	}
}
func main() {
	phase := os.Args[1]
	for _, minor := range []int32{3, 4} {
		version := kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: minor}
		for mode := 0; mode < 4; mode++ {
			options := []kmipclient.Option{
				kmipclient.WithClientCertFiles(filepath.Join("/pki", "client.pem"), filepath.Join("/pki", "client.key")),
				kmipclient.WithRootCAFile("/pki/ca.pem"), kmipclient.EnforceVersion(version),
			}
			port := os.Args[2]
			if mode > 0 {
				port = os.Args[3]
				format := []kmiphttp.WireFormat{kmiphttp.WireTTLV, kmiphttp.WireTTLV, kmiphttp.WireJSON, kmiphttp.WireXML}[mode]
				options = append(options, kmiphttp.WithTransport("/kmip", kmiphttp.WithWireFormat(format)))
			}
			client := must(kmipclient.Dial("localhost:"+port, options...))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			call := func(label string, max int32, expected kmip.ResultStatus, reason kmip.ResultReason) int {
				request := kmip.NewRequestMessage(version, &payloads.QueryRequestPayload{QueryFunction: []kmip.QueryFunction{1, 2}})
				request.Header.MaximumResponseSize = max
				request.BatchItem[0].UniqueBatchItemID = []byte{0x42}
				response := must(client.RoundTrip(ctx, &request))
				require(response.Header.ProtocolVersion == version && response.Header.BatchCount == 1 && len(response.BatchItem) == 1)
				item := response.BatchItem[0]
				require(item.Operation == kmip.OperationQuery && bytes.Equal(item.UniqueBatchItemID, []byte{0x42}))
				require(item.ResultStatus == expected && item.ResultReason == reason)
				// The real SDK parsed the response; only its public encoder
				// computes the TTLV equivalent. No server length math or codec.
				binary := ttlv.MarshalTTLV(response)
				var node ttlv.Value
				if err := ttlv.UnmarshalTTLV(binary, &node); err != nil {
					panic(err)
				}
				require(bytes.Equal(binary, ttlv.MarshalTTLV(&node)))
				if max > 0 {
					require(len(binary) <= int(max))
				}
				if expected == kmip.ResultStatusSuccess {
					query, ok := item.ResponsePayload.(*payloads.QueryResponsePayload)
					require(ok && len(query.Operations) > 0 && len(query.ObjectType) > 0)
				}
				fmt.Println(string(must(json.Marshal(map[string]any{
					"event": "item", "version": fmt.Sprintf("1.%d", minor), "mode": mode,
					"case": label, "max": max, "operation": int(item.Operation), "batch_id": "42",
					"status": int(item.ResultStatus), "reason": int(item.ResultReason),
					"sdk_encoded_binary_length": len(binary),
				}))))
				return len(binary)
			}
			if phase == "negative-control" {
				expected, reason := kmip.ResultStatusSuccess, kmip.ResultReason(0)
				if mode >= 2 {
					expected, reason = kmip.ResultStatusOperationFailed, kmip.ResultReasonResponseTooLarge
				}
				call("query-2048", 2048, expected, reason)
				call("health", 0, kmip.ResultStatusSuccess, 0)
			} else {
				require(phase == "exercise")
				length := call("query-2048", 2048, kmip.ResultStatusSuccess, 0)
				exact := call("exact", int32(length), kmip.ResultStatusSuccess, 0)
				require(exact == length)
				call("one-below", int32(length-1), kmip.ResultStatusOperationFailed, kmip.ResultReasonResponseTooLarge)
				call("query-256", 256, kmip.ResultStatusOperationFailed, kmip.ResultReasonResponseTooLarge)
				call("health", 2048, kmip.ResultStatusSuccess, 0)
			}
			cancel()
			require(client.Close() == nil)
			fmt.Println(string(must(json.Marshal(map[string]any{"event": "pass", "version": fmt.Sprintf("1.%d", minor), "mode": mode, "phase": phase}))))
		}
	}
}
