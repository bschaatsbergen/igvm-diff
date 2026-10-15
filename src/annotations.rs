use serde_json::Value;

const EFER_REFERENCE: &str = "AMD APM vol. 2, rev. 3.45, §3.1.7, pp. 57–59 (PDF pages 120–122), EFER: https://docs.amd.com/v/u/en-US/24593_3.45_APM_Vol2_PUB";
const SEV_REFERENCE: &str = "AMD APM vol. 2, rev. 3.45, Table B-4, p. 777 (PDF page 840), SEV_FEATURES: https://docs.amd.com/v/u/en-US/24593_3.45_APM_Vol2_PUB";

const EFER_BITS: &[(u32, &str)] = &[
    (0, "system-call extensions (SCE)"),
    (8, "long mode enable (LME)"),
    (10, "long mode active (LMA)"),
    (11, "no-execute (NXE)"),
    (12, "SVM (SVME)"),
    (13, "long mode segment limits (LMSLE)"),
    (14, "fast FXSAVE/FXRSTOR (FFXSR)"),
    (15, "translation cache extension (TCE)"),
    (17, "MCOMMIT"),
    (18, "interruptible WBINVD/WBNOINVD (INTWB)"),
    (20, "upper address ignore (UAIE)"),
    (21, "automatic IBRS (AIBRSE)"),
    (24, "enhanced TLB invalidation (EnhancedTlbi)"),
];

const SEV_BITS: &[(u32, &str)] = &[
    (0, "SNP active (SNPActive)"),
    (1, "vTOM"),
    (2, "#VC reflection (ReflectVC)"),
    (3, "restricted injection (RestrictedInjection)"),
    (4, "alternate injection (AlternateInjection)"),
    (5, "debug-register virtualization (DebugVirtualization)"),
    (6, "host IBS prevention (PreventHostIBS)"),
    (7, "BTB isolation (BTBIsolation)"),
    (8, "VMPL supervisor shadow stack (VmplSSS)"),
    (9, "secure TSC (SecureTSC)"),
    (10, "VMGEXIT parameter (VmgexitParameter)"),
    (11, "PMC virtualization (PmcVirtualization)"),
    (12, "IBS virtualization (IbsVirtualization)"),
    (13, "guest intercept control (GuestInterceptCtl)"),
    (14, "VMSA register protection (VmsaRegProt)"),
    (15, "SMT protection (SmtProtection)"),
    (16, "secure AVIC (SecureAvic)"),
    (21, "IBPB on entry (IbpbOnEntry)"),
];

#[derive(Debug)]
pub(crate) struct Annotation {
    pub text: String,
    pub reference: &'static str,
}

pub(crate) fn explain(field: &str, before: &Value, after: &Value) -> Option<Annotation> {
    let (bits, reference) = match field {
        "efer" => (EFER_BITS, EFER_REFERENCE),
        "sev_features" => (SEV_BITS, SEV_REFERENCE),
        _ => return None,
    };
    let parse = |value: &Value| u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok();
    let before = parse(before)?;
    let after = parse(after)?;
    let changed = before ^ after;
    if changed == 0 {
        return None;
    }
    let mut notes = Vec::new();
    let mut known = 0;
    for &(bit, name) in bits {
        let mask = 1_u64 << bit;
        known |= mask;
        if changed & mask != 0 {
            let state = if (field == "efer" && matches!(bit, 8 | 10))
                || (field == "sev_features" && bit == 0)
            {
                if after & mask != 0 { "set" } else { "cleared" }
            } else if after & mask != 0 {
                "enabled"
            } else {
                "disabled"
            };
            notes.push(format!("{name} {state}"));
        }
    }
    for (mask, state) in [
        (after & !before & !known, "set"),
        (before & !after & !known, "cleared"),
    ] {
        if mask != 0 {
            notes.push(format!("undecoded bits {state}: {mask:#x}"));
        }
    }
    Some(Annotation {
        text: notes.join(", "),
        reference,
    })
}
