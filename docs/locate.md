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

# Locate

Part of the [feature reference](README.md#feature-reference).

Locate returns the identifiers of the caller's objects, and of objects
granted to it ([authorization](authorization.md)), that match every filter in
the request.

## Results

- Newest object first (descending creation time).
- Maximum Items and Offset Items page through the results. Offset Items above
  100,000 is refused; a response holds at most 1,000 identifiers.
- A single result sets the ID Placeholder for the next batch item; several
  results clear it.

## Filters

| Filter | Editions | Match |
| --- | --- | --- |
| Object Type, State, Cryptographic Algorithm, Cryptographic Length, Unique Identifier, Short Unique Identifier, Fresh, Sensitive, Extractable and their histories | where defined | equal |
| Cryptographic Usage Mask | all | every bit given must be set |
| Name, Object Group, Application Specific Information, Alternative Name | where defined | any instance equal; an Alternative Name filter may give only the value, only the type, or neither (presence) |
| Cryptographic Parameters, Cryptographic Domain Parameters, Digest, Revocation Reason, Key Value Location, Random Number Generator | where defined | the fields given must match within one instance |
| Contact Information | all | equal text |
| Description, Comment | 1.4+ | equal text |
| Key Format Type | 2.0+ | equal |
| Usage Limits | all | Total and Count are lower bounds; Unit is equal |
| Lease Time | all | interval |
| Dates (Initial, Activation, Deactivation, Process Start, Protect Stop, Compromise, Compromise Occurrence, Destroy, Archive, Last Change, Original Creation) | where defined | see [dates](#date-filters) |
| Link (1.x–2.x), typed links and Group Link (3.0 draft) | where defined | whole structure: link type and target |
| Certificate type, length, identifier, subject and issuer attributes; Digital Signature Algorithm | where defined | equal |
| Opaque Data Type, Protection Storage Mask, Split Key fields, Protection Level, Protection Period, Quantum Safe | where defined | equal |
| Key Value Present | 1.2+ | equal (only objects registered without material carry it) |
| Operation Policy Name | 1.x | `default` matches every object; any other name matches nothing |
| Custom (`x-`) and vendor attributes | all | equal value and type; Attribute Index is ignored |

- A filter on an attribute the edition does not define is Invalid Field. A
  field of the wrong type is Invalid Field. Any attribute not listed here is
  refused with Feature Not Supported.
- There are no wildcards or regular expressions.
- A `y-` filter is valid and matches nothing: the server sets no such
  attribute.

### Date filters

- One value matches exactly. Two values of the same date attribute form an
  inclusive range, in either order.
- A missing date compares as the largest possible date, so a range ending at
  that maximum includes objects without the date. For example, "active at
  time T" is Activation Date ≤ T and Deactivation Date ≥ T, with the upper
  bound of the second range at the maximum.
- More than two values of one date attribute, or a value that is not a
  Date-Time, is Invalid Field.
- Vendor date attributes keep their type: a Date-Time filter does not match a
  Date-Time Extended value.

### Storage status

The Storage Status Mask selects on-line (the default), archived and, from
2.0, destroyed objects; zero selects none. In 1.x, which has no destroyed bit,
an on-line Locate skips destroyed objects unless the filters select the
Destroyed or Destroyed Compromised state or a Destroy Date. An object that is
both archived and destroyed needs both bits.

### Object Group Member (1.1+)

With an Object Group filter:

- Group Member Fresh returns only fresh members (never served by Get),
  oldest first in 1.x so a prepared pool is handed out in creation order,
  newest first from 2.0. No object is generated on demand.
- Group Member Default returns one member, rotating through the group in
  creation order. The position is kept in memory per principal and group, so
  a restart begins again with the oldest member. Offset Items is refused.

Without an Object Group filter the field is Invalid Field.
