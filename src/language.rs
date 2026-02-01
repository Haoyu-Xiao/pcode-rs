use std::ffi::c_uint;
use std::io::BufReader;
use std::{fs::File, path::Path};

use anyhow::Result;
use quick_xml::de;
use serde::{Deserialize, Serialize};

use crate::bindings::{context_set_variable_default, create_context};
use crate::context::Context;
use crate::processor::ProcessorSpec;

const ARCH_SPEC_DIR: &str = concat!(env!("OUT_DIR"), "/processors");

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct LanguageDefinitions {
    language: Vec<LanguageSpec>,
}

impl IntoIterator for LanguageDefinitions {
    type Item = LanguageSpec;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.language.into_iter()
    }
}

impl LanguageDefinitions {
    pub fn get_context(&self, language_id: &str) -> Option<Context> {
        self.language
            .iter()
            .find(|ldef| ldef.id.to_lowercase() == language_id.to_lowercase())
            .map(|ldef| ldef.create_context())
    }
}

impl LanguageDefinitions {
    pub fn load() -> Result<Self> {
        let arch_spec_dir: &Path = ARCH_SPEC_DIR.as_ref();
        // list directory
        let lspec_paths = arch_spec_dir
            .read_dir()?
            .filter_map(|entry| {
                let path = entry.ok()?.path().join("data/languages");
                if path.is_dir() {
                    Some(path)
                } else {
                    None
                }
            })
            .filter_map(|path| {
                let ldef_iter = path.read_dir().ok()?.filter_map(|entry| {
                    let path = entry.ok()?.path();
                    if path.extension()?.to_str()? == "ldefs" {
                        Some(path)
                    } else {
                        None
                    }
                });
                Some(ldef_iter)
            })
            .flatten()
            .collect::<Vec<_>>();

        lspec_paths.into_iter().try_fold(
            LanguageDefinitions::default(),
            |mut language_definitions, path| {
                let ldef: LanguageDefinitions = Self::load_one(&path)?;
                // eprintln!(
                //     "Loaded {} language definition from: {:?}",
                //     ldef.language.len(),
                //     path
                // );
                language_definitions.language.extend(ldef.language);
                Ok(language_definitions)
            },
        )
    }

    pub fn load_one(path: impl AsRef<Path>) -> Result<LanguageDefinitions> {
        let data_dir = path
            .as_ref()
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let file = File::open(path)?;
        let buf_reader = BufReader::new(file); // Buffering is important for performance

        let mut ldefs: LanguageDefinitions = de::from_reader(buf_reader)?;
        ldefs.language.iter_mut().for_each(|ldef| {
            ldef.data_dir = data_dir.clone();
        });
        Ok(ldefs)
    }
}

/// Language Specification
/// Reference: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/data/languages/language_definitions.rxg
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LanguageSpec {
    #[serde(default, rename = "@hidden")]
    pub hidden: bool, // a language marked as hidden will only be available within a development environment
    #[serde(default, rename = "@deprecated")]
    pub deprecated: bool,
    #[serde(rename = "@processor")]
    pub processor: String,
    #[serde(rename = "@endian")]
    pub endian: Endian,
    #[serde(default, rename = "@instructionEndian")]
    pub instructionEndian: Option<Endian>,
    #[serde(rename = "@size")]
    pub size: u32,
    #[serde(rename = "@variant")]
    pub variant: String,
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@slafile")]
    pub slafile: String,
    #[serde(rename = "@processorspec")]
    pub processorspec: String,
    #[serde(default, rename = "@manualindexfile")]
    pub manualindexfile: Option<String>,
    #[serde(rename = "@id")]
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub truncate_space: Option<TruncateSpace>,
    pub compiler: Vec<CompilerSpec>, // one or more, first compiler spec is the default
    #[serde(default)]
    pub external_name: Vec<ExternalName>, // zero or more
    #[serde(default)]
    pub data_dir: String, // directory where the language data files are located
}

impl LanguageSpec {
    pub fn load_processor_spec(&self) -> Result<ProcessorSpec> {
        let data_dir: &Path = self.data_dir.as_ref();
        ProcessorSpec::load(data_dir.join(&self.processorspec))
    }

    pub fn create_context(&self) -> Context {
        let data_dir: &Path = self.data_dir.as_ref();
        let slafile_path = data_dir.join(&self.slafile);
        let sleigh_spec = format!("<sleigh>{}</sleigh>", slafile_path.display());
        use std::ffi::{c_uint, CString};

        let sleigh_spec_cstr = CString::new(sleigh_spec).expect("Failed to create CString");
        let mut context_internal = unsafe { create_context(sleigh_spec_cstr.as_ptr()) };
        if context_internal.is_null() {
            panic!("Failed to create context");
        }
        let mut context = Context::new(context_internal);

        if let Ok(processor_spec) = self.load_processor_spec() {
            if let Some(context_data) = processor_spec.context_data {
                context_data.context_set.iter().for_each(|set| {
                    set.set.iter().for_each(|set_data| {
                        let name = CString::new(set_data.name.clone()).unwrap();
                        let val = c_uint::from(set_data.val.parse::<u32>().unwrap());
                        unsafe {
                            context_set_variable_default(context.internal, name.as_ptr(), val);
                        }
                    });
                });
            }
        }
        context
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TruncateSpace {
    #[serde(rename = "@space")]
    pub space: String,
    #[serde(rename = "@size")]
    pub size: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompilerSpec {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@spec")]
    pub spec: String,
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalName {
    #[serde(rename = "@tool")]
    pub tool: String,
    #[serde(rename = "@name")]
    pub name: String,
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::*;

    #[test]
    fn test_parse_lspec() {
        let s = "<compiler name=\"golang\" spec=\"x86-64-golang.cspec\" id=\"golang\"/>";
        let result: CompilerSpec = de::from_str(s).unwrap();
        assert_eq!(result.name, "golang");
        assert_eq!(result.spec, "x86-64-golang.cspec");
        assert_eq!(result.id, "golang");

        let arch_spec_dir: &Path = ARCH_SPEC_DIR.as_ref();
        let ldef_path = arch_spec_dir.join("x86/data/languages/x86.ldefs");
        let result = LanguageDefinitions::load_one(ldef_path);
        assert!(
            result.is_ok(),
            "Failed to parse language specification: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_parse_lspec_all() {
        let language_definitions = LanguageDefinitions::load();
        assert!(
            language_definitions.is_ok(),
            "Failed to load language definitions: {:?}",
            language_definitions.err()
        );

        let language_definitions = language_definitions.unwrap();
        assert!(
            !language_definitions.language.is_empty(),
            "No language definitions found"
        );

        assert!(language_definitions.language.len() > 0);
    }
}
