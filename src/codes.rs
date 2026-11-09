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

//! Frequently used OASIS enumeration values, kept distinct from TTLV tag numbers.
pub mod hash {
    pub const SHA256: u32 = 0x00000006;
    pub const SHA384: u32 = 0x00000007;
    pub const SHA512: u32 = 0x00000008;
}
pub mod block_mode {
    pub const CBC: u32 = 1;
    pub const ECB: u32 = 2;
    pub const CFB: u32 = 4;
    pub const OFB: u32 = 5;
    pub const CTR: u32 = 6;
    pub const GCM: u32 = 9;
}
pub mod padding {
    pub const NONE: u32 = 1;
    pub const PKCS5: u32 = 3;
}
