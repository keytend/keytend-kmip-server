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

/* Only the installed public IBM header is used. No private encoder symbols. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <kmipclient/kmipclient.h>

static struct kmip_conn_config config;
static struct kmip_version version;
static int mode;
static const char *phase;
static void check(int rc, const char *stage) {
    if (rc) { fprintf(stderr, "%s: SDK rc=%d\n", stage, rc); exit(1); }
}
static struct kmip_node *identifier(const char *id) {
    struct kmip_node *n = kmip_new_unique_identifier(id, 0, 0); assert(n); return n;
}
static struct kmip_node *query(void) {
    struct kmip_node *n = kmip_new_query_request_payload_va(2, 1, 2); assert(n); return n;
}
/* Ownership of payloads is consumed. Every exchange uses a fresh SDK connection. */
static int exchange(const char *label, int max, int option, int count,
        const int *ops, struct kmip_node **payloads, const int *statuses,
        const int *reasons, struct kmip_node **results, int expected_count,
        int allow_transport_failure, int debug) {
    struct kmip_node *h = kmip_new_request_header(&version, max, NULL, NULL,
            false, NULL, option, false, count);
    assert(h);
    struct kmip_node *limit = kmip_node_get_structure_element_by_tag(h, 0x420050, 0);
    assert((max == 0 && !limit) || (limit && kmip_node_get_integer(limit) == max));
    kmip_node_free(limit);
    struct kmip_node *items[3]; assert(count <= 3);
    for (int i = 0; i < count; i++) {
        unsigned char batch_id = (unsigned char)(i + 1);
        assert(payloads[i]);
        /* The unchanged SDK names this optional tag UniqueBatchItemId in
         * JSON/XML, while Profiles specify UniqueBatchItemID. Its public name
         * parameter adds metadata, not a tag override. Omit optional IDs only
         * for text lanes; exercise and assert exact IDs in both binary lanes.
         */
        items[i] = kmip_new_request_batch_item(ops[i], mode < 2 ? &batch_id : NULL,
                mode < 2 ? 1 : 0, payloads[i]);
        assert(items[i]);
    }
    struct kmip_node *request = kmip_new_request(h, count, items), *response = NULL;
    assert(request);
    struct kmip_connection *c = NULL;
    check(kmip_connection_new(&config, &c, debug), "connect");
    fprintf(stderr, "BEGIN %d.%d mode=%d phase=%s case=%s advertised_max=%d option=%d\n",
            version.major, version.minor, mode, phase, label, max, option);
    int rc = kmip_connection_perform(c, request, &response, debug);
    if (rc) {
        printf("{\"event\":\"transport_failure\",\"case\":\"%s\",\"max\":%d,\"sdk_rc\":%d}\n", label, max, rc);
        assert(allow_transport_failure);
    } else {
        assert(!allow_transport_failure);
        struct kmip_node *rh = NULL, *rb = NULL;
        check(kmip_get_response(response, &rh, 0, &rb), "response");
        struct kmip_version got; int32_t n;
        check(kmip_get_response_header(rh, &got, NULL, NULL, NULL, &n), "header");
        assert(got.major == version.major && got.minor == version.minor && n == expected_count);
        kmip_node_free(rh); kmip_node_free(rb);
        for (int i = 0; i < n; i++) {
            const unsigned char *id = NULL; uint32_t id_len = 0;
            enum kmip_operation op; enum kmip_result_status status;
            enum kmip_result_reason reason = 0;
            struct kmip_node *p = NULL;
            check(kmip_get_response(response, NULL, i, &rb), "response item");
            check(kmip_get_response_batch_item(rb, &op, &id, &id_len, &status,
                        &reason, NULL, NULL, NULL, &p), "typed item");
            printf("{\"event\":\"item\",\"case\":\"%s\",\"max\":%d,\"operation\":%d,\"batch_id\":%d,\"status\":%d,\"reason\":%d}\n",
                    label, max, op, id_len == 1 ? id[0] : -1, status, reason);
            assert((int)op == ops[i]);
            if (mode < 2) assert(id_len == 1 && id[0] == i + 1);
            else assert(id_len == 0 && id == NULL);
            assert((int)status == statuses[i]);
            if (reasons && reasons[i]) assert((int)reason == reasons[i]);
            if (results) results[i] = p; else kmip_node_free(p);
            kmip_node_free(rb);
        }
    }
    fflush(stdout);
    fprintf(stderr, "END case=%s sdk_rc=%d\n", label, rc);
    kmip_connection_free(c); kmip_node_free(response); kmip_node_free(request);
    for (int i = 0; i < count; i++) { kmip_node_free(items[i]); kmip_node_free(payloads[i]); }
    kmip_node_free(h);
    return rc;
}
static struct kmip_node *single(const char *label, int op, struct kmip_node *p, int reason) {
    int status = reason ? 1 : 0;
    struct kmip_node *r = NULL;
    exchange(label, 0, 0, 1, &op, &p, &status, &reason, &r, 1, 0, 0);
    return r;
}
static void query_case(const char *label, int max, int reason, int tiny, int debug) {
    int op = 24, status = reason ? 1 : 0;
    struct kmip_node *p = query(), *r = NULL;
    exchange(label, max, 0, 1, &op, &p, &status, &reason, &r, 1, tiny, debug);
    if (!reason && !tiny) {
        for (int function = 1; function <= 2; function++) {
            unsigned int count = 0; struct kmip_node *element = NULL;
            check(kmip_get_query_response_payload(r, function, &count, 0, &element), "Query typed payload");
            assert(count > 0 && element); kmip_node_free(element);
        }
    }
    kmip_node_free(r);
}
static void create(char uid[1024]) {
    struct kmip_node *a = kmip_new_cryptographic_algorithm(3);
    struct kmip_node *l = kmip_new_cryptographic_length(256);
    struct kmip_node *u = kmip_new_cryptographic_usage_mask(12);
    struct kmip_node *p = kmip_new_create_request_payload_va(&version, 2, NULL, 3, a, l, u);
    assert(a && l && u && p);
    kmip_node_free(a); kmip_node_free(l); kmip_node_free(u);
    struct kmip_node *r = single("create", 1, p, 0), *id = NULL;
    check(kmip_get_create_response_payload(r, NULL, &id, NULL, 0, NULL), "Create payload");
    const char *text; check(kmip_get_unique_identifier(id, &text, NULL, NULL), "identifier");
    assert(text && strlen(text) < 1024); strcpy(uid, text);
    kmip_node_free(id); kmip_node_free(r);
}
static void key_bytes(const char *uid, unsigned char out[32], int destroyed) {
    struct kmip_node *id = identifier(uid);
    struct kmip_node *p = kmip_new_get_request_payload(&version, id, 0, 0, 0, NULL);
    kmip_node_free(id);
    struct kmip_node *r = single("get-key", 10, p, destroyed ? (version.major >= 2 ? 0x36 : 0x0b) : 0);
    if (destroyed) { kmip_node_free(r); return; }
    struct kmip_node *obj = NULL, *block = NULL, *value = NULL, *material = NULL;
    enum kmip_object_type type; enum kmip_key_format_type format;
    enum kmip_crypto_algo algorithm; int32_t bits; uint32_t length;
    const unsigned char *bytes;
    check(kmip_get_get_response_payload(r, &type, NULL, &obj), "Get payload");
    check(kmip_get_symmetric_key(obj, &block), "Symmetric Key");
    check(kmip_get_key_block(block, &format, NULL, &value, &algorithm, &bits, NULL), "Key Block");
    assert((int)type == 2 && (int)format == 1 && (int)algorithm == 3 && bits == 256);
    check(kmip_get_key_value(value, &material, NULL, 0, NULL), "Key Value");
    check(kmip_get_raw_key(material, &bytes, &length), "Raw Key");
    assert(length == 32); memcpy(out, bytes, 32);
    kmip_node_free(material); kmip_node_free(value); kmip_node_free(block);
    kmip_node_free(obj); kmip_node_free(r);
}
static void state(const char *uid, int expected) {
    struct kmip_node *id = identifier(uid);
    struct kmip_node *ref = kmip_node_new_enumeration(0x42013b, NULL, 0x42008d);
    assert(ref);
    struct kmip_node *p = kmip_new_get_attributes_request_payload_va(&version, id, 1, ref);
    kmip_node_free(id); kmip_node_free(ref);
    struct kmip_node *r = single("state", 11, p, 0), *attr = NULL;
    unsigned int count;
    check(kmip_get_get_attributes_response_payload(r, NULL, &count, 0, &attr), "Get Attributes");
    assert(count == 1 && attr && kmip_node_get_tag(attr) == 0x42008d);
    assert((int)kmip_node_get_enumeration(attr) == expected);
    kmip_node_free(attr); kmip_node_free(r);
}
static void verify_pair(int option, const char *a, const char *b, const unsigned char ka[32], const unsigned char kb[32]) {
    state(a, option == 3 ? 1 : 2); state(b, option == 1 ? 5 : 1);
    unsigned char actual[32];
    key_bytes(a, actual, 0); assert(CRYPTO_memcmp(actual, ka, 32) == 0);
    key_bytes(b, actual, option == 1);
    if (option != 1) assert(CRYPTO_memcmp(actual, kb, 32) == 0);
    OPENSSL_cleanse(actual, sizeof(actual));
}
static void mutations(FILE *f) {
    for (int option = 1; option <= 3; option++) {
        char a[1024], b[1024]; unsigned char ka[32], kb[32];
        create(a); create(b); key_bytes(a, ka, 0); key_bytes(b, kb, 0);
        int ops[] = {18, 24, 20};
        struct kmip_node *id_a = identifier(a), *id_b = identifier(b);
        struct kmip_node *p[] = {kmip_new_activate_request_payload(id_a), query(), kmip_new_destroy_request_payload(id_b)};
        kmip_node_free(id_a); kmip_node_free(id_b);
        int statuses[] = {option == 3 ? 3 : 0, 1, 0};
        int reasons[] = {0, 2, 0};
        exchange("mutation", 600, option, 3, ops, p, statuses, reasons, NULL, option == 1 ? 3 : 2, 0, 0);
        verify_pair(option, a, b, ka, kb);
        assert(fprintf(f, "%d %s %s ", option, a, b) > 0);
        for (int i = 0; i < 32; i++) fprintf(f, "%02x", ka[i]);
        fputc(' ', f);
        for (int i = 0; i < 32; i++) fprintf(f, "%02x", kb[i]);
        fputc('\n', f);
        OPENSSL_cleanse(ka, sizeof(ka)); OPENSSL_cleanse(kb, sizeof(kb));
    }
}
static void verify(FILE *f) {
    int option, count = 0; char a[1024], b[1024], ha[65], hb[65];
    while (fscanf(f, "%d %1023s %1023s %64s %64s", &option, a, b, ha, hb) == 5) {
        unsigned char ka[32], kb[32];
        for (int i = 0; i < 32; i++) {
            unsigned int x, y; assert(sscanf(ha + i * 2, "%2x", &x) == 1);
            assert(sscanf(hb + i * 2, "%2x", &y) == 1); ka[i] = x; kb[i] = y;
        }
        verify_pair(option, a, b, ka, kb); count++;
        OPENSSL_cleanse(ka, sizeof(ka)); OPENSSL_cleanse(kb, sizeof(kb));
    }
    assert(count == 3);
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    assert(argc == 7);
    assert(sscanf(argv[3], "%d.%d", &version.major, &version.minor) == 2);
    mode = atoi(argv[4]); phase = argv[5];
    kmip_set_default_protocol_version(&version);
    FILE *f = fopen("/pki/client.key", "r"); assert(f);
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); assert(key);
    config.encoding = mode <= 1 ? KMIP_ENCODING_TTLV : mode == 2 ? KMIP_ENCODING_JSON : KMIP_ENCODING_XML;
    config.transport = mode == 0 ? KMIP_TRANSPORT_PLAIN_TLS : KMIP_TRANSPORT_HTTPS;
    config.tls_client_key = key; config.tls_client_cert = "/pki/client.pem";
    config.tls_ca = "/pki/ca.pem"; config.tls_verify_peer = true; config.tls_verify_host = true;
    char endpoint[128];
    assert(snprintf(endpoint, sizeof(endpoint), mode == 0 ? "localhost:%s" : "https://localhost:%s/kmip", mode == 0 ? argv[1] : argv[2]) > 0);
    config.server = endpoint;
    if (!strcmp(phase, "negative-control")) {
        query_case("query-2048", 2048, mode >= 2 ? 2 : 0, 0, 1);
        query_case("health", 0, 0, 0, 0);
    } else if (!strcmp(phase, "exercise")) {
        query_case("query-2048", 2048, 0, 0, 1);
        query_case("query-256", 256, 2, 0, 0);
        query_case("health-after-256", 2048, 0, 0, 0);
        query_case("tiny-1", 1, 0, 1, 1);
        query_case("health-after-tiny", 2048, 0, 0, 0);
        if (mode < 2) {
            f = fopen(argv[6], "w"); assert(f); mutations(f); assert(fclose(f) == 0);
        } else {
            puts("{\"event\":\"unsupported\",\"case\":\"text-mutation-batch\",\"reason\":\"SDK tag UniqueBatchItemId differs from canonical UniqueBatchItemID; multi-item server requests require IDs\"}");
        }
    } else {
        assert(!strcmp(phase, "verify")); f = fopen(argv[6], "r"); assert(f);
        verify(f); fclose(f);
    }
    EVP_PKEY_free(key);
    printf("{\"event\":\"pass\",\"version\":\"%d.%d\",\"mode\":%d,\"phase\":\"%s\"}\n", version.major, version.minor, mode, phase);
    return 0;
}
