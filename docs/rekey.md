<!--
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
-->

# Re-key and Re-key Key Pair

Part of the [feature reference](README.md#feature-reference).

Re-key (all editions) replaces a symmetric key with new material under a new
identifier; Re-key Key Pair (1.1 and later) does the same for an RSA, EC or
post-quantum key pair. The source objects keep their material and state.

## What the replacement gets

- The material is freshly generated, of the source's algorithm and length unless
  the request overrides them. Re-key supports AES and HMAC keys (and 3DES and
  ChaCha20 where enabled); Re-key Key Pair supports RSA 2048/3072/4096, the
  EC curves `--ec-curves` offers and, in the 3.0 draft, ML-KEM, ML-DSA and
  SLH-DSA. RSA pairs keep their PKCS#1 or PKCS#8/SPKI format.
- Attributes are copied from the source, with requested values applied. For
  pairs, common and key-specific values combine as in Create Key Pair:
  multi-instance attributes are merged, key-specific single values win.
- Names move from the source to the replacement. Requested Names follow the
  normal uniqueness rules; two pair members cannot share a Name, so give each
  key its own.
- The source gets a Replacement Object Link and the replacement a
  Replaced Object Link (in the 3.0 draft, the typed link attributes). The new
  pair members link to each other.
- The replacement gets new Initial and Last Change Dates, Digest, Unique
  Identifier and Original Creation Date, a full Usage Limits budget, and none
  of the source's compromise, revocation, destroy or lease metadata. The source's used
  budget is unchanged.

## Dates and Offset

- Without an Offset, the Activation, Process Start, Protect Stop and Deactivation
  Dates are copied, and the state is recomputed from them: an active source
  normally gives an active replacement.
- With an Offset, the replacement's Activation Date is its Initial Date plus
  the Offset, and the other dates shift by the same amount relative to the old
  Activation Date. A source without an Activation Date but with other dates
  cannot be offset (Illegal Operation).
- Offset together with explicit lifecycle dates is refused.

## Rules

- A source can be re-keyed only once: a key that has already been re-keyed
  is refused, even if its Replacement Object Link was deleted. A replacement can
  itself be re-keyed, extending the chain.
- Both keys of a pair must belong to the caller, link to
  each other and match mathematically. In 1.x–2.1 the request names the
  private key (or uses the ID Placeholder); in the 3.0 draft either member.
- Source changes, the new objects, Names, links and the audit
  record commit together; any failure leaves neither a half pair nor a
  record that the source was re-keyed.
- At most four key-pair generations per batch, counting Create
  Key Pair and Re-key Key Pair together.

## Not supported

Re-key of templates, of protection storage selections beyond Software, and
of algorithms other than those listed above.

The Usage Limits rows of the specification tables disagree between editions;
see [interpretations](interpretations.md#other-readings).
