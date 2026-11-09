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

//! Response forms of the text encodings (docs/interpretations.md, tag and
//! enumeration names in JSON responses). Profiles 2.1 sections 5.4.1 (XML) and 5.5.1
//! (JSON) let several elements be written in more than one form; each such
//! element has one setting here. Requests are always read in every form the
//! Profiles allow. Whatever the setting, a tag or enumeration value without a
//! name in the response's own edition (extensions, vendor and unknown values,
//! Reserved slots, messages without a known version) is written in hex, and a
//! value a JSON Number cannot carry exactly is written in hex.

/// A tag (5.4.1.3/5.4.1.6, 5.5.1.3) or an XML enumeration (5.4.1.6.7): the
/// normalized name or hex. For XML tags `name` selects the specific element
/// form (`<ObjectType .../>`) and `hex` the general `<TTLV tag="0x..."/>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum NameForm {
    Name,
    Hex,
}
/// A JSON enumeration value (5.5.1.6.7): CamelCase text, hex string or Number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EnumerationForm {
    Name,
    Hex,
    Number,
}
/// A mask (5.4.1.6.4, 5.5.1.6.4): the Integer form (JSON Number, XML
/// xsd:int decimal), one 32-bit hex component, or component names with any
/// unnamed bits as one hex component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum MaskForm {
    Number,
    Hex,
    Names,
}
/// A JSON Integer, Long Integer, Big Integer, Interval or Date-Time Extended
/// (5.5.1.6.3, .5, .6, .12, .13): a Number or a fixed-width hex string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum NumberForm {
    Number,
    Hex,
}
/// A JSON Boolean (5.5.1.6.8): `true`/`false` or an 8-byte hex string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum BooleanForm {
    Boolean,
    Hex,
}
/// A JSON Date-Time (5.5.1.6.11): a 64-bit hex string or the time-zoned
/// XML Schema dateTime text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum DateTimeForm {
    Hex,
    Text,
}
/// Starting values that individual settings override.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Preset {
    /// The defaults: JSON tags by name with hex enumerations (some clients
    /// reject normative enumeration names), JSON Numbers, hex Date-Times; XML
    /// general elements, hex enumerations and mask names.
    #[default]
    Compatible,
    /// Names and Numbers wherever the Profiles allow them, text Date-Times.
    Readable,
    /// Hex wherever the Profiles allow it.
    Hex,
}
/// One setting per element whose response form the Profiles leave open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextEncoding {
    pub json_tags: NameForm,
    pub json_enumerations: EnumerationForm,
    pub json_masks: MaskForm,
    pub json_integers: NumberForm,
    pub json_long_integers: NumberForm,
    pub json_big_integers: NumberForm,
    pub json_intervals: NumberForm,
    pub json_date_time_extended: NumberForm,
    pub json_booleans: BooleanForm,
    pub json_date_times: DateTimeForm,
    pub xml_tags: NameForm,
    pub xml_enumerations: NameForm,
    pub xml_masks: MaskForm,
}
impl Default for TextEncoding {
    fn default() -> Self {
        Self::preset(Preset::Compatible)
    }
}
impl TextEncoding {
    pub const fn preset(preset: Preset) -> Self {
        match preset {
            Preset::Compatible => Self {
                json_tags: NameForm::Name,
                json_enumerations: EnumerationForm::Hex,
                json_masks: MaskForm::Number,
                json_integers: NumberForm::Number,
                json_long_integers: NumberForm::Number,
                json_big_integers: NumberForm::Hex,
                json_intervals: NumberForm::Number,
                json_date_time_extended: NumberForm::Number,
                json_booleans: BooleanForm::Boolean,
                json_date_times: DateTimeForm::Hex,
                xml_tags: NameForm::Hex,
                xml_enumerations: NameForm::Hex,
                xml_masks: MaskForm::Names,
            },
            Preset::Readable => Self {
                json_tags: NameForm::Name,
                json_enumerations: EnumerationForm::Name,
                json_masks: MaskForm::Names,
                json_integers: NumberForm::Number,
                json_long_integers: NumberForm::Number,
                json_big_integers: NumberForm::Number,
                json_intervals: NumberForm::Number,
                json_date_time_extended: NumberForm::Number,
                json_booleans: BooleanForm::Boolean,
                json_date_times: DateTimeForm::Text,
                xml_tags: NameForm::Name,
                xml_enumerations: NameForm::Name,
                xml_masks: MaskForm::Names,
            },
            Preset::Hex => Self {
                json_tags: NameForm::Hex,
                json_enumerations: EnumerationForm::Hex,
                json_masks: MaskForm::Hex,
                json_integers: NumberForm::Hex,
                json_long_integers: NumberForm::Hex,
                json_big_integers: NumberForm::Hex,
                json_intervals: NumberForm::Hex,
                json_date_time_extended: NumberForm::Hex,
                json_booleans: BooleanForm::Hex,
                json_date_times: DateTimeForm::Hex,
                xml_tags: NameForm::Hex,
                xml_enumerations: NameForm::Hex,
                xml_masks: MaskForm::Hex,
            },
        }
    }
}
/// Server options: `--text-encoding` picks a preset and each element option
/// overrides it. clap validates every value at startup.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct TextEncodingArgs {
    /// Starting response forms of the JSON and XML encodings: `compatible`
    /// (default), `readable` or `hex`. The element options below override it.
    #[arg(long, env = "KMIP_TEXT_ENCODING", value_enum, default_value_t = Preset::Compatible)]
    pub text_encoding: Preset,
    /// JSON tags (Profiles 5.5.1.3): `name` or `hex`.
    #[arg(long, env = "KMIP_JSON_TAGS", value_enum)]
    pub json_tags: Option<NameForm>,
    /// JSON enumeration values (5.5.1.6.7): `name`, `hex` or `number`.
    #[arg(long, env = "KMIP_JSON_ENUMERATIONS", value_enum)]
    pub json_enumerations: Option<EnumerationForm>,
    /// JSON masks (5.5.1.6.4): `number`, `hex` or `names` ('|'-separated).
    #[arg(long, env = "KMIP_JSON_MASKS", value_enum)]
    pub json_masks: Option<MaskForm>,
    /// JSON Integers (5.5.1.6.3): `number` or `hex`.
    #[arg(long, env = "KMIP_JSON_INTEGERS", value_enum)]
    pub json_integers: Option<NumberForm>,
    /// JSON Long Integers (5.5.1.6.5): `number` or `hex`; hex at or above 2^52.
    #[arg(long, env = "KMIP_JSON_LONG_INTEGERS", value_enum)]
    pub json_long_integers: Option<NumberForm>,
    /// JSON Big Integers (5.5.1.6.6): `number` or `hex`; Numbers only for
    /// eight-byte values below 2^52 in magnitude.
    #[arg(long, env = "KMIP_JSON_BIG_INTEGERS", value_enum)]
    pub json_big_integers: Option<NumberForm>,
    /// JSON Intervals (5.5.1.6.12): `number` or `hex`.
    #[arg(long, env = "KMIP_JSON_INTERVALS", value_enum)]
    pub json_intervals: Option<NumberForm>,
    /// JSON Date-Time Extended (5.5.1.6.13): `number` or `hex`; hex at or above 2^52.
    #[arg(long, env = "KMIP_JSON_DATE_TIME_EXTENDED", value_enum)]
    pub json_date_time_extended: Option<NumberForm>,
    /// JSON Booleans (5.5.1.6.8): `boolean` or `hex`.
    #[arg(long, env = "KMIP_JSON_BOOLEANS", value_enum)]
    pub json_booleans: Option<BooleanForm>,
    /// JSON Date-Times (5.5.1.6.11): `hex` or `text` (XML Schema dateTime).
    #[arg(long, env = "KMIP_JSON_DATE_TIMES", value_enum)]
    pub json_date_times: Option<DateTimeForm>,
    /// XML tags (5.4.1.6): `name` (specific elements) or `hex` (`<TTLV tag=...>`).
    #[arg(long, env = "KMIP_XML_TAGS", value_enum)]
    pub xml_tags: Option<NameForm>,
    /// XML enumeration values (5.4.1.6.7): `name` or `hex`.
    #[arg(long, env = "KMIP_XML_ENUMERATIONS", value_enum)]
    pub xml_enumerations: Option<NameForm>,
    /// XML masks (5.4.1.6.4): `names`, `hex` or `number` (xsd:int).
    #[arg(long, env = "KMIP_XML_MASKS", value_enum)]
    pub xml_masks: Option<MaskForm>,
}
impl TextEncodingArgs {
    /// The preset with every given element option applied.
    pub fn resolve(&self) -> TextEncoding {
        let base = TextEncoding::preset(self.text_encoding);
        TextEncoding {
            json_tags: self.json_tags.unwrap_or(base.json_tags),
            json_enumerations: self.json_enumerations.unwrap_or(base.json_enumerations),
            json_masks: self.json_masks.unwrap_or(base.json_masks),
            json_integers: self.json_integers.unwrap_or(base.json_integers),
            json_long_integers: self.json_long_integers.unwrap_or(base.json_long_integers),
            json_big_integers: self.json_big_integers.unwrap_or(base.json_big_integers),
            json_intervals: self.json_intervals.unwrap_or(base.json_intervals),
            json_date_time_extended: self
                .json_date_time_extended
                .unwrap_or(base.json_date_time_extended),
            json_booleans: self.json_booleans.unwrap_or(base.json_booleans),
            json_date_times: self.json_date_times.unwrap_or(base.json_date_times),
            xml_tags: self.xml_tags.unwrap_or(base.xml_tags),
            xml_enumerations: self.xml_enumerations.unwrap_or(base.xml_enumerations),
            xml_masks: self.xml_masks.unwrap_or(base.xml_masks),
        }
    }
}
