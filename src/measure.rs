//! SEV-SNP launch digest, computed the way COCONUT-SVSM's `igvmmeasure` does
//! (<https://github.com/coconut-svsm/svsm/tree/main/tools/igvmmeasure>, `igvm_measure.rs` and
//! `page_info.rs`): each page extends the digest with a 0x70-byte PAGE_INFO structure that holds
//! the current digest, the SHA-384 of the page contents (zero for pages without measured
//! contents), the page type and the guest physical address.
//!
//! One deliberate difference: igvmmeasure measures every SNP VP context in the file, while this
//! port measures only those whose compatibility mask selects the `sev-snp` platform. The two
//! agree for files with a single SEV-SNP platform, which includes every fixture.

use serde::Serialize;
use sha2::{Digest, Sha384};

use crate::image::{Directive, Image};

const PAGE: usize = 4096;

/// SNP page types in PAGE_INFO.
const NORMAL: u8 = 1;
const VMSA: u8 = 2;
const ZERO: u8 = 3;
const UNMEASURED: u8 = 4;
const SECRETS: u8 = 5;
const CPUID: u8 = 6;

/// IGVM page data types.
const DATA_NORMAL: u16 = 0;
const DATA_SECRETS: u16 = 1;
const DATA_CPUID: u16 = 2;
const DATA_CPUID_XF: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnpMeasurement {
    /// Zero-filled pages measured as SNP ZERO pages (`igvmmeasure --native-zero`).
    pub native_zero: String,
    /// Zero-filled pages measured as normal pages of zeroes (`igvmmeasure` default).
    pub zero_as_normal: String,
    /// VMSAs in the file. A hypervisor that adds a VMSA for each further vCPU measures those
    /// too, which gives a different value.
    pub vmsa_count: usize,
    /// Zero-filled `sev-snp` pages; when 0 the two conventions give the same value.
    pub zero_pages: usize,
    /// `sev-snp` pages flagged shared. `igvmmeasure` measures them as normal pages, while the
    /// IGVM definition says shared pages are not part of the launch measurement.
    pub shared_pages: usize,
    /// The launch digest declared in the file's SNP ID block, if any.
    pub id_block_launch_digest: Option<String>,
}

/// Launch measurements of one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileMeasurements {
    /// Per platform (`sev-snp`, `tdx`, `vbs`): the digest from the `igvm` crate's `measurement`
    /// module, maintained with the IGVM definitions. SEV-SNP: zero-filled pages measured as
    /// pages of zeroes, shared pages skipped, every page of a parameter area unmeasured.
    pub igvm: std::collections::BTreeMap<String, Result<String, String>>,
    /// SEV-SNP digests computed as COCONUT-SVSM igvmmeasure does.
    pub igvmmeasure: Option<SnpMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchMeasurement {
    pub before: FileMeasurements,
    pub after: FileMeasurements,
}

pub(crate) fn measurements(bytes: &[u8], image: &Image) -> FileMeasurements {
    FileMeasurements {
        igvm: image
            .measurements
            .iter()
            .map(|(name, result)| (name.to_string(), result.clone()))
            .collect(),
        igvmmeasure: snp(bytes, image),
    }
}

struct Chain([u8; 48]);

impl Chain {
    fn extend(&mut self, page_type: u8, contents: &[u8; 48], gpa: u64) {
        let mut info = [0u8; 0x70];
        info[..48].copy_from_slice(&self.0);
        info[48..96].copy_from_slice(contents);
        info[96..98].copy_from_slice(&0x70_u16.to_le_bytes());
        info[98] = page_type;
        // IMI page, reserved and VMPL1-3 permissions are zero.
        info[104..112].copy_from_slice(&gpa.to_le_bytes());
        self.0 = Sha384::digest(info).into();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn snp(bytes: &[u8], image: &Image) -> Option<SnpMeasurement> {
    let (&snp, _) = image
        .platforms
        .iter()
        .find(|(_, name)| **name == "sev-snp")?;
    let mut native = Chain([0; 48]);
    let mut normal = Chain([0; 48]);
    let zero_contents: [u8; 48] = Sha384::digest([0u8; PAGE]).into();
    let mut result = SnpMeasurement {
        native_zero: String::new(),
        zero_as_normal: String::new(),
        vmsa_count: 0,
        zero_pages: 0,
        shared_pages: 0,
        id_block_launch_digest: None,
    };
    fn both(chains: [&mut Chain; 2], page_type: u8, contents: &[u8; 48], gpa: u64) {
        for chain in chains {
            chain.extend(page_type, contents, gpa);
        }
    }
    let page = |offset: u32| &bytes[offset as usize..offset as usize + PAGE];
    for directive in &image.directives {
        match *directive {
            Directive::Page {
                gpa,
                mask,
                offset,
                data_type,
                unmeasured,
                shared,
            } if mask & snp != 0 => {
                result.shared_pages += usize::from(shared);
                match data_type {
                    DATA_NORMAL if unmeasured => {
                        both([&mut native, &mut normal], UNMEASURED, &[0; 48], gpa)
                    }
                    DATA_NORMAL if offset == 0 => {
                        result.zero_pages += 1;
                        native.extend(ZERO, &[0; 48], gpa);
                        normal.extend(NORMAL, &zero_contents, gpa);
                    }
                    DATA_NORMAL => both(
                        [&mut native, &mut normal],
                        NORMAL,
                        &Sha384::digest(page(offset)).into(),
                        gpa,
                    ),
                    DATA_SECRETS => both([&mut native, &mut normal], SECRETS, &[0; 48], gpa),
                    DATA_CPUID | DATA_CPUID_XF => {
                        both([&mut native, &mut normal], CPUID, &[0; 48], gpa)
                    }
                    _ => {}
                }
            }
            Directive::ParameterInsert { gpa, mask } if mask & snp != 0 => {
                both([&mut native, &mut normal], UNMEASURED, &[0; 48], gpa);
            }
            Directive::SnpVpContext { gpa, mask, offset } if mask & snp != 0 => {
                result.vmsa_count += 1;
                both(
                    [&mut native, &mut normal],
                    VMSA,
                    &Sha384::digest(page(offset)).into(),
                    gpa,
                );
            }
            Directive::SnpIdBlock {
                mask,
                launch_digest,
            } if mask & snp != 0 => {
                result.id_block_launch_digest = Some(hex(&launch_digest));
            }
            _ => {}
        }
    }
    result.native_zero = hex(&native.0);
    result.zero_as_normal = hex(&normal.0);
    Some(result)
}
