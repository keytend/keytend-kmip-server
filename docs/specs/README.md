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

# Specification data

Machine-readable records that the project's test tools read and check
against the pinned KMIP documents. They are test evidence, not user
documentation, and nothing in a deployment reads them. The pages that use
them are [project status](../status.md) and [testing](../testing.md).

| Files | What they record |
| --- | --- |
| `sources.json`, `errata.json`, `profiles.json`, `operations.json`, `registry.json` | The pinned KMIP documents and their errata, profiles, operations, tags and enumerations |
| `requirement-matrix.json`, `requirements-index.json` | The clause-level requirements of the pinned documents and their status |
| `oasis-*.json`, `additional-traces.json` | The OASIS Profiles XML test traces (1.3–3.0) and their replay results |
| `legacy-*.json` | The KMIP 1.1 and 1.2 Test Cases and their replay |
| `tls-profile-inventory.json`, `tls-external-references.json` | The TLS requirements of the KMIP authentication suites ([TLS profiles](../tls-profiles.md)) |
