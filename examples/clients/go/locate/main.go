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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func main() {
	log.SetFlags(0)                  // print errors without a timestamp
	pki := os.Getenv("KMIP_PKI")     // directory with ca.pem and the client certificates
	cert := os.Getenv("KMIP_CLIENT") // the client certificate: client, other or unlisted
	if cert == "" {
		cert = "client"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := kmipclient.DialContext(ctx, "localhost:5696",
		kmipclient.WithRootCAFile(pki+"/ca.pem"),
		kmipclient.WithClientCertFiles(pki+"/"+cert+".pem", pki+"/"+cert+".key"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Find the key by its Name, or create it on the first run. Names are
	// unique per principal, so this finds the key an earlier run created.
	const name = "orders-kek"
	id, err := locate(ctx, client, name)
	if err != nil {
		log.Fatal(err)
	}
	action := "found"
	if id == "" {
		created, err := client.Create().
			AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
			WithName(name).ExecContext(ctx)
		if err != nil {
			// Another process may have created it since the Locate: the
			// server refuses a second object with the same Name.
			if id, _ = locate(ctx, client, name); id == "" {
				log.Fatal(err)
			}
		} else {
			id, action = created.UniqueIdentifier, "created"
		}
	}

	// A run that stopped between Create and Activate left the key Pre-Active.
	attrs, err := client.GetAttributes(id, kmip.AttributeNameState).ExecContext(ctx)
	if err != nil {
		log.Fatal(err)
	}
	state := attrs.Attribute[0].AttributeValue
	switch state {
	case kmip.StatePreActive:
		if _, err := client.Activate(id).ExecContext(ctx); err != nil {
			log.Fatal(err)
		}
	case kmip.StateActive:
	default:
		log.Fatalf("%s (%s) is %v: not using it", name, id, state)
	}
	fmt.Printf("%s %s: %s\n", action, name, id)
}

func locate(ctx context.Context, client *kmipclient.Client, name string) (string, error) {
	found, err := client.Locate().WithName(name).ExecContext(ctx)
	if err != nil || len(found.UniqueIdentifier) == 0 {
		return "", err
	}
	return found.UniqueIdentifier[0], nil
}
