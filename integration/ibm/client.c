/*
Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Public IBM libkmipclient API; no SDK codec or transport is replaced. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <kmipclient/kmipclient.h>

static void check(int rc, const char *stage) {
    if (rc != 0) { fprintf(stderr, "%s failed: %d\n", stage, rc); exit(1); }
}
static bool boolean_probe;
static bool order_option;
static struct kmip_node *call(struct kmip_connection *c,
        const struct kmip_version *v, enum kmip_operation op,
        struct kmip_node *payload, int expected_reason) {
    struct kmip_node *h = kmip_new_request_header(v, 0, NULL, NULL, false,
            NULL, 0, order_option, 1);
    struct kmip_node *b = kmip_new_request_batch_item(op, NULL, 0, payload);
    assert(h && b && payload);
    struct kmip_node *request = kmip_new_request_va(h, 1, b), *response = NULL;
    assert(request);
    check(kmip_connection_perform(c, request, &response, false), "SDK transport");
    struct kmip_node *rh = NULL, *rb = NULL, *result = NULL;
    check(kmip_get_response(response, &rh, 0, &rb), "SDK response");
    struct kmip_version got; int32_t count;
    check(kmip_get_response_header(rh, &got, NULL, NULL, NULL, &count), "SDK header");
    enum kmip_result_status status; enum kmip_result_reason reason;
    const char *message = NULL;
    check(kmip_get_response_batch_item(rb, NULL, NULL, NULL, &status, &reason,
            &message, NULL, NULL, &result), "SDK batch");
    if (got.major != v->major || got.minor != v->minor || count != 1) {
        fprintf(stderr, "response header %d.%d count=%d; expected %d.%d; status=%d reason=%d message=%s\n", got.major, got.minor, count, v->major, v->minor, status, reason, message ? message : "");
        kmip_node_dump(h, true);
        exit(1);
    }
    if (expected_reason) assert((int)status == 1 && (int)reason == expected_reason);
    else assert((int)status == 0 && result);
    kmip_node_free(rh); kmip_node_free(rb); kmip_node_free(response);
    kmip_node_free(request); kmip_node_free(b); kmip_node_free(h);
    kmip_node_free(payload);
    return result;
}
static struct kmip_node *id(const char *value) {
    struct kmip_node *n = kmip_new_unique_identifier(value, 0, 0); assert(n); return n;
}
static struct kmip_node *get_payload(const char *value) {
    struct kmip_node *u = id(value);
    struct kmip_node *p = kmip_new_get_request_payload(kmip_get_default_protocol_version(), u, 0, 0, 0, NULL);
    kmip_node_free(u); assert(p); return p;
}
static void key_bytes(const struct kmip_node *p, unsigned char out[32]) {
    struct kmip_node *obj = NULL, *block = NULL, *value = NULL, *material = NULL;
    enum kmip_object_type type; enum kmip_key_format_type format;
    enum kmip_crypto_algo algorithm; int32_t bits; uint32_t length;
    const unsigned char *bytes = NULL;
    check(kmip_get_get_response_payload(p, &type, NULL, &obj), "SDK Get payload");
    assert((int)type == 2);
    check(kmip_get_symmetric_key(obj, &block), "SDK Symmetric Key");
    check(kmip_get_key_block(block, &format, NULL, &value, &algorithm, &bits, NULL), "SDK Key Block");
    assert((int)format == 1 && (int)algorithm == 3 && bits == 256);
    check(kmip_get_key_value(value, &material, NULL, 0, NULL), "SDK Key Value");
    check(kmip_get_raw_key(material, &bytes, &length), "SDK Raw Key");
    assert(length == 32); memcpy(out, bytes, 32);
    kmip_node_free(material); kmip_node_free(value); kmip_node_free(block); kmip_node_free(obj);
}
/* Typed State through the public Get Attributes payload and attribute accessors. */
static int state_of(struct kmip_connection *c, const struct kmip_version *v, const char *uid) {
    struct kmip_node *u = id(uid), *ref = kmip_new_attribute_reference(KMIP_TAG_STATE, NULL, NULL);
    assert(ref);
    struct kmip_node *p = kmip_new_get_attributes_request_payload_va(v, u, 1, ref);
    kmip_node_free(u); kmip_node_free(ref); assert(p);
    struct kmip_node *r = call(c, v, 11, p, 0), *attr = NULL;
    unsigned int n = 0; enum kmip_state state;
    check(kmip_get_get_attributes_response_payload(r, NULL, &n, 0, &attr), "SDK Get Attributes");
    assert(n == 1 && attr);
    check(kmip_get_state(attr, &state), "SDK State");
    kmip_node_free(attr); kmip_node_free(r);
    return (int)state;
}
static EVP_PKEY *read_key(const char *path) {
    FILE *f = fopen(path, "r"); assert(f);
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); assert(key); return key;
}
static struct kmip_node *query_payload(void) {
    struct kmip_node *p = kmip_new_query_request_payload_va(1, 1); assert(p); return p;
}
/* A transport-layer refusal: kmip_connection_new or the first exchange fails.
   A KMIP response of any kind would mean the server or SDK accepted the peer. */
static int tls_refused(const char *label, struct kmip_conn_config *config, const struct kmip_version *v) {
    struct kmip_connection *c = NULL;
    int rc = kmip_connection_new(config, &c, false);
    if (rc == 0) {
        struct kmip_node *h = kmip_new_request_header(v, 0, NULL, NULL, false, NULL, 0, order_option, 1);
        struct kmip_node *payload = query_payload();
        struct kmip_node *b = kmip_new_request_batch_item(24, NULL, 0, payload);
        struct kmip_node *request = kmip_new_request_va(h, 1, b), *response = NULL;
        rc = kmip_connection_perform(c, request, &response, false);
        kmip_node_free(response); kmip_node_free(request); kmip_node_free(b);
        kmip_node_free(payload); kmip_node_free(h); kmip_connection_free(c);
    }
    if (rc == 0) { fprintf(stderr, "%s: accepted\n", label); exit(1); }
    return rc;
}
/* Principal/operation ACLs and trust/hostname/identity refusals over binary TLS
   and HTTPS, each followed by a successful fresh request (scripts/dev-pki.sh policy;
   wrong-ca.pem and untrusted.* are generated by scripts/test_ibm_client.py). */
static void negatives(struct kmip_conn_config base, const char *tls_port, const char *https_port) {
    struct kmip_version editions[] = {{1,4},{2,1}};
    EVP_PKEY *other = read_key("/pki/other.key"), *unlisted = read_key("/pki/unlisted.key"), *untrusted = read_key("/pki/untrusted.key");
    for (unsigned int i = 0; i < 2; i++) {
        struct kmip_version *v = &editions[i]; kmip_set_default_protocol_version(v);
        for (int mode = 0; mode < 2; mode++) {
            struct kmip_conn_config config = base, cfg;
            char endpoint[128], wrong[128];
            config.transport = mode == 0 ? KMIP_TRANSPORT_PLAIN_TLS : KMIP_TRANSPORT_HTTPS;
            config.encoding = KMIP_ENCODING_TTLV; order_option = false;
            assert(snprintf(endpoint, sizeof(endpoint), mode == 0 ? "localhost:%s" : "https://localhost:%s/kmip", mode == 0 ? tls_port : https_port) > 0);
            assert(snprintf(wrong, sizeof(wrong), mode == 0 ? "wrong-kmip.test:%s" : "https://wrong-kmip.test:%s/kmip", mode == 0 ? tls_port : https_port) > 0);
            config.server = endpoint;
            struct kmip_connection *c = NULL; check(kmip_connection_new(&config, &c, false), "SDK connect");
            struct kmip_node *a = kmip_new_cryptographic_algorithm(3), *l = kmip_new_cryptographic_length(256), *u = kmip_new_cryptographic_usage_mask(12);
            struct kmip_node *p = kmip_new_create_request_payload_va(v, 2, NULL, 3, a, l, u);
            kmip_node_free(a); kmip_node_free(l); kmip_node_free(u);
            struct kmip_node *r = call(c, v, 1, p, 0), *identifier = NULL;
            check(kmip_get_create_response_payload(r, NULL, &identifier, NULL, 0, NULL), "SDK Create");
            const char *text = NULL; check(kmip_get_unique_identifier(identifier, &text, NULL, NULL), "SDK identifier");
            char uid[1024]; assert(text && strlen(text) < sizeof(uid)); strcpy(uid, text);
            kmip_node_free(identifier); kmip_node_free(r);
            cfg = config; cfg.tls_client_key = other; cfg.tls_client_cert = "/pki/other.pem";
            struct kmip_connection *o = NULL; check(kmip_connection_new(&cfg, &o, false), "SDK connect other");
            /* Another owner's object is not found for this principal. */
            r = call(o, v, 10, get_payload(uid), v->major >= 2 ? 0x37 : 1); kmip_node_free(r);
            a = kmip_new_cryptographic_algorithm(3); l = kmip_new_cryptographic_length(256); u = kmip_new_cryptographic_usage_mask(12);
            p = kmip_new_create_request_payload_va(v, 2, NULL, 3, a, l, u);
            kmip_node_free(a); kmip_node_free(l); kmip_node_free(u);
            r = call(o, v, 1, p, 12); kmip_node_free(r);   /* read-only principal: Permission Denied */
            kmip_connection_free(o);
            cfg = config; cfg.tls_client_key = unlisted; cfg.tls_client_cert = "/pki/unlisted.pem";
            int e0 = 0;
            /* Both transports: one versioned Permission Denied answer, then close
               (HTTPS: HTTP 200 with the KMIP response and Connection: close). */
            check(kmip_connection_new(&cfg, &o, false), "SDK connect unlisted");
            r = call(o, v, 24, query_payload(), 12); kmip_node_free(r);
            kmip_connection_free(o);
            cfg = config; cfg.tls_ca = "/pki/wrong-ca.pem";
            int e1 = tls_refused("wrong server CA", &cfg, v);
            cfg = config; cfg.server = wrong;
            int e2 = tls_refused("wrong hostname", &cfg, v);
            cfg = config; cfg.tls_client_key = untrusted; cfg.tls_client_cert = "/pki/untrusted.pem";
            int e3 = tls_refused("untrusted client certificate", &cfg, v);
            cfg = config; cfg.tls_client_key = NULL;
            struct kmip_connection *none = NULL;
            int e4 = kmip_connection_new(&cfg, &none, false);
            assert(e4 != 0 && none == NULL);  /* the public API requires a client certificate */
            unsigned char first[32];
            r = call(c, v, 10, get_payload(uid), 0); key_bytes(r, first); kmip_node_free(r);
            OPENSSL_cleanse(first, sizeof(first));
            kmip_connection_free(c);
            printf("PASS IBM libkmipclient negatives %d.%d transport=%d: other principal Get not found, read-only Create Permission Denied, unlisted Query Permission Denied (%d); wrong server CA (%d), wrong hostname (%d), untrusted client certificate (%d) refused; missing client key rejected by the SDK API (%d); fresh request succeeds\n", v->major, v->minor, config.transport, e0, e1, e2, e3, e4); fflush(stdout);
        }
    }
    EVP_PKEY_free(other); EVP_PKEY_free(unlisted); EVP_PKEY_free(untrusted);
}
int main(int argc, char **argv) {
    assert(argc == 3);
    FILE *f = fopen("/pki/client.key", "r"); assert(f);
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); assert(key);
    struct kmip_conn_config config = {0};
    config.encoding = KMIP_ENCODING_TTLV;
    config.transport = KMIP_TRANSPORT_PLAIN_TLS;
    config.tls_client_key = key; config.tls_client_cert = "/pki/client.pem";
    config.tls_ca = "/pki/ca.pem"; config.tls_verify_peer = true; config.tls_verify_host = true;
    struct kmip_version editions[] = {{1,0},{1,1},{1,2},{1,3},{1,4},{2,0},{2,1}};
    boolean_probe = getenv("KEYTEND_IBM_BOOL_PROBE") != NULL;
    if (boolean_probe) {
        order_option = true;
        struct kmip_version v = {1,4}; kmip_set_default_protocol_version(&v);
        char endpoint[128]; assert(snprintf(endpoint,sizeof(endpoint),"localhost:%s",argv[1]) > 0); config.server = endpoint;
        struct kmip_connection *c = NULL; check(kmip_connection_new(&config,&c,false),"SDK probe connect");
        struct kmip_node *r = call(c,&v,24,kmip_new_query_request_payload_va(1,1),4);
        kmip_node_free(r); kmip_connection_free(c); EVP_PKEY_free(key);
        puts("KNOWN SDK LIMITATION: pinned IBM TTLV encoder writes Boolean True in host byte order on this little-endian test image; strict server rejects it. Single-item TTLV lifecycle uses public Batch Order Option False; JSON/XML use True.");
        return 0;
    }
    if (getenv("KEYTEND_IBM_NEGATIVES")) {
        negatives(config, argv[1], argv[2]);
        EVP_PKEY_free(key); return 0;
    }
    for (unsigned int i = 0; i < sizeof(editions)/sizeof(editions[0]); i++) {
        struct kmip_version *v = &editions[i]; kmip_set_default_protocol_version(v);
        for (int mode = 0; mode < 4; mode++) {
            config.transport = mode == 0 ? KMIP_TRANSPORT_PLAIN_TLS : KMIP_TRANSPORT_HTTPS;
            config.encoding = mode <= 1 ? KMIP_ENCODING_TTLV : mode == 2 ? KMIP_ENCODING_JSON : KMIP_ENCODING_XML;
            order_option = config.encoding != KMIP_ENCODING_TTLV;
            char endpoint[128];
            assert(snprintf(endpoint, sizeof(endpoint), mode == 0 ? "localhost:%s" : "https://localhost:%s/kmip", mode == 0 ? argv[1] : argv[2]) > 0);
            config.server = endpoint;
            struct kmip_connection *c = NULL; check(kmip_connection_new(&config, &c, false), "SDK connect");
            struct kmip_node *a = kmip_new_cryptographic_algorithm(3), *l = kmip_new_cryptographic_length(256), *u = kmip_new_cryptographic_usage_mask(12);
            assert(a && l && u);
            struct kmip_node *p = kmip_new_create_request_payload_va(v, 2, NULL, 3, a, l, u);
            kmip_node_free(a); kmip_node_free(l); kmip_node_free(u);
            struct kmip_node *r = call(c, v, 1, p, 0), *identifier = NULL;
            check(kmip_get_create_response_payload(r, NULL, &identifier, NULL, 0, NULL), "SDK Create");
            const char *text = NULL; check(kmip_get_unique_identifier(identifier, &text, NULL, NULL), "SDK identifier");
            char uid[1024]; assert(text && strlen(text) < sizeof(uid)); strcpy(uid, text);
            kmip_node_free(identifier); kmip_node_free(r);
            assert(state_of(c, v, uid) == 1);  /* Pre-Active */
            unsigned char first[32], second[32];
            r = call(c, v, 10, get_payload(uid), 0); key_bytes(r, first); kmip_node_free(r);
            r = call(c, v, 10, get_payload(uid), 0); key_bytes(r, second); kmip_node_free(r);
            assert(CRYPTO_memcmp(first, second, 32) == 0);
            /* Item Not Found in 1.x; Object Not Found (0x37) in the 2.x error tables. */
            r = call(c, v, 10, get_payload("ibm-missing-key"), v->major >= 2 ? 0x37 : 1); kmip_node_free(r);
            identifier = id(uid); p = kmip_new_activate_request_payload(identifier); kmip_node_free(identifier);
            r = call(c, v, 18, p, 0); kmip_node_free(r);
            assert(state_of(c, v, uid) == 2);  /* Active */
            identifier = id(uid); p = kmip_new_revoke_request_payload(identifier, 1, "fixture complete", 0); kmip_node_free(identifier);
            r = call(c, v, 19, p, 0); kmip_node_free(r);
            assert(state_of(c, v, uid) == 3);  /* Deactivated */
            identifier = id(uid); p = kmip_new_destroy_request_payload(identifier); kmip_node_free(identifier);
            r = call(c, v, 20, p, 0); kmip_node_free(r);
            assert(state_of(c, v, uid) == 5);  /* Destroyed */
            /* 1.x Get error tables: an object whose server keeps only attributes is Illegal Operation.
               2.x reports the caller's destroyed object as Object Destroyed (0x36,
               docs/interpretations.md#result-reasons). */
            r = call(c, v, 10, get_payload(uid), v->major >= 2 ? 0x36 : 0x0b); kmip_node_free(r);
            OPENSSL_cleanse(first, sizeof(first)); OPENSSL_cleanse(second, sizeof(second));
            kmip_connection_free(c);
            printf("PASS IBM libkmipclient %d.%d transport=%d encoding=%d: lifecycle, typed Pre-Active/Active/Deactivated/Destroyed state, exact bytes, missing/destroyed Get\n", v->major, v->minor, config.transport, config.encoding); fflush(stdout);
        }
    }
    EVP_PKEY_free(key); return 0;
}
