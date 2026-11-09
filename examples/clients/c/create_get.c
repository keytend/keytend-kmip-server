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

/* Create and fetch an AES-256 key with libkmip over mutual TLS. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_io.h"

/* Error paths return without freeing ctx and bio, for brevity; free them in
   long-running code. */
static int fail(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    return 1;
}

int main(void) {
    const char *pki = getenv("KMIP_PKI");             /* directory of the test certificates */
    const char *name = getenv("KMIP_CLIENT");         /* client, other or unlisted */
    if (name == NULL || *name == '\0') name = "client";
    char ca[4096], cert[4096], keyfile[4096];
    if (pki == NULL) return fail("KMIP_PKI");
    snprintf(ca, sizeof ca, "%s/ca.pem", pki);
    snprintf(cert, sizeof cert, "%s/%s.pem", pki, name);
    snprintf(keyfile, sizeof keyfile, "%s/%s.key", pki, name);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL
        || SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1
        || SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1                 /* server CA */
        || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1                /* client certificate */
        || SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1)
        return fail("TLS setup");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl = NULL;
    if (bio != NULL) BIO_get_ssl(bio, &ssl);
    if (ssl == NULL || SSL_set1_host(ssl, "localhost") != 1)                 /* check the name */
        return fail("TLS setup");
    BIO_set_conn_hostname(bio, "localhost:5696");
    if (BIO_do_connect(bio) != 1 || BIO_do_handshake(bio) != 1)
        return fail("TLS connection");

    /* libkmip's calls block: bound every later read and write to 10 seconds.
       A read that runs out returns KMIP_IO_FAILURE (-13). */
    struct timeval limit = {.tv_sec = 10};
    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0
        || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit) != 0
        || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit) != 0)
        return fail("socket timeouts");

    KMIP k = {0};
    kmip_init(&k, NULL, 0, KMIP_1_4);
    enum cryptographic_algorithm alg = KMIP_CRYPTOALG_AES;
    int32 bits = 256, usage = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    Attribute a[3];
    for (int i = 0; i < 3; i++) kmip_init_attribute(&a[i]);
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;  a[0].value = &alg;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;     a[1].value = &bits;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK; a[2].value = &usage;
    TemplateAttribute ta = {.attributes = a, .attribute_count = 3};

    char *id = NULL, *key = NULL;
    int id_len = 0, key_len = 0;
    /* KMIP_OK, a negative libkmip error, or the failed KMIP Result Status */
    int result = kmip_bio_create_symmetric_key_with_context(&k, bio, &ta, &id, &id_len);
    if (result == KMIP_OK)
        result = kmip_bio_get_symmetric_key_with_context(&k, bio, id, id_len, &key, &key_len);
    if (result == KMIP_OK)  /* a new key is Pre-Active, so Destroy needs no Revoke */
        result = kmip_bio_destroy_symmetric_key_with_context(&k, bio, id, id_len);
    if (result != KMIP_OK) {
        /* Create and Get record the Result Reason and Message; Destroy does not. */
        fprintf(stderr, "KMIP request failed: status %d, ", result);
        kmip_print_result_reason_enum(stderr, kmip_last_reason());
        fprintf(stderr, ": %s\n", kmip_last_message());
        return 1;
    }
    printf("created, fetched and destroyed %.*s: %d-byte AES key\n", id_len, id, key_len);

    OPENSSL_cleanse(key, (size_t)key_len);
    free(key);
    free(id);
    kmip_destroy(&k);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
