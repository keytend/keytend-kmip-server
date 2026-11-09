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

/* Independent libkmip BIO client test; validates chain and hostname. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include "kmip.h"
#include "kmip_bio.h"
static void path(char *out,size_t n,const char *p,const char *file){assert(snprintf(out,n,"%s/%s",p,file)>0);}
int main(void){
 const char *p=getenv("KMIP_PKI"),*port=getenv("KMIP_PORT");assert(p);if(!port)port="15696";
 SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());assert(ctx);SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
 char f[4096];path(f,sizeof(f),p,"ca.pem");assert(SSL_CTX_load_verify_locations(ctx,f,NULL)==1);
 path(f,sizeof(f),p,"client.pem");assert(SSL_CTX_use_certificate_chain_file(ctx,f)==1);
 path(f,sizeof(f),p,"client.key");assert(SSL_CTX_use_PrivateKey_file(ctx,f,SSL_FILETYPE_PEM)==1);
 BIO *bio=BIO_new_ssl_connect(ctx);assert(bio);SSL *ssl=NULL;BIO_get_ssl(bio,&ssl);assert(SSL_set1_host(ssl,"localhost")==1);
 BIO_set_conn_hostname(bio,"localhost");BIO_set_conn_port(bio,port);assert(BIO_do_connect(bio)==1);assert(BIO_do_handshake(bio)==1);assert(SSL_get_verify_result(ssl)==X509_V_OK);
 for(int minor=0;minor<=4;minor++){
 KMIP k={0};kmip_init(&k,NULL,0,(enum kmip_version)minor);
 Attribute a[3];for(int i=0;i<3;i++)kmip_init_attribute(&a[i]);
 enum cryptographic_algorithm alg=KMIP_CRYPTOALG_AES;int32 bits=256,usage=KMIP_CRYPTOMASK_ENCRYPT|KMIP_CRYPTOMASK_DECRYPT;
 a[0].type=KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;a[0].value=&alg;a[1].type=KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;a[1].value=&bits;a[2].type=KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;a[2].value=&usage;
 TemplateAttribute ta={0};ta.attributes=a;ta.attribute_count=3;char *id=NULL,*key=NULL;int id_len=0,key_len=0;
 int r=kmip_bio_create_symmetric_key_with_context(&k,bio,&ta,&id,&id_len);
 if(r!=KMIP_OK){fprintf(stderr,"create: %d %s\n",r,kmip_last_message());return 1;}
 assert(kmip_bio_get_symmetric_key_with_context(&k,bio,id,id_len,&key,&key_len)==KMIP_OK);assert(key_len==32);
 assert(kmip_bio_destroy_symmetric_key_with_context(&k,bio,id,id_len)==KMIP_OK);
 OPENSSL_cleanse(key,(size_t)key_len);free(key);free(id);kmip_destroy(&k);
 printf("PASS libkmip 1.%d: Create, Get, Destroy\n",minor);
 }
 BIO_free_all(bio);SSL_CTX_free(ctx);return 0;
}
