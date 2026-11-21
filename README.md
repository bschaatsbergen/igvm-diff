# igvm-diff

A Rust CLI and library for comparing IGVM files. It shows changes to memory pages, boot configuration, and initial CPU state between builds.

It is meant for confidential computing operators who receive IGVM builds from a cloud or firmware vendor. Before approving a new build in a remote attestation policy, an operator can see whether the launch measurement changes and which firmware modules and payloads are behind the change.

```sh
cargo run -- diff A.igvm B.igvm
cargo run -- diff A.igvm B.igvm --verbose
cargo run -- diff A.igvm B.igvm --format json
cargo run -- diff A.igvm B.igvm --platform sev-snp
```

The default output is a short review summary: attestation impact, computed launch measurements, the next step, the changed configuration, firmware modules by boot phase, and where the changed pages are. `--verbose` lists every module and page range, adds explanations, and ends with every record change. `--format json` gives the full report as JSON.

Vendor files often define several platforms; GCE's SVSM image, for example, defines both `sev-snp` and `tdx`. `--platform` restricts the report to the platform you run; an unknown platform is an error.

`compare` is an alias for `diff`. Exit codes are `0` for identical files, `1` for differences, and `2` for invalid or unsupported input. Errors go to stderr.

## Examples

The fixtures include a small pair that differs in one 4 KiB page:

```sh
cargo run -- diff tests/fixtures/before.igvm tests/fixtures/after.igvm
```

Compare two COCONUT-SVSM community builds:

```sh
cargo run -- diff \
  tests/fixtures/coconut-svsm/coconut-fedora-9065337.igvm \
  tests/fixtures/coconut-svsm/coconut-fedora-10828816.igvm
```

Compare two Google Compute Engine SVSM releases published in `gs://gce_tcb_integrity/ovmf_x64_csm/svsm/`. The fixtures use the first eight hex digits of each object name; `tests/fixtures/gce-svsm/manifest.json` maps them back to the full object names. This pair changes only SEV-SNP pages above `0xffe00000`:

```sh
cargo run -- diff \
  tests/fixtures/gce-svsm/gce-svsm-0932e060.igvm \
  tests/fixtures/gce-svsm/gce-svsm-d5341027.igvm
```

Compare two confidential-dot-ai (c8s) SEV-SNP releases. These 147 MiB images are pulled from the OCI bundles listed in `tests/fixtures/c8s/manifest.json` and are not committed. Between v0.99.1 and v0.99.9 the only measured change is the dm-verity `roothash=` on the UKI's kernel command line. Set `IGVM_DIFF_C8S_DIR` to run `tests/c8s.rs` against downloaded copies.

Compare OpenHCL's standard and confidential-VM variants from the same build:

```sh
cargo run -- diff \
  tests/fixtures/openhcl/38639549342/x64-openhcl-igvm/openhcl-x64.bin \
  tests/fixtures/openhcl/38639549342/x64-openhcl-igvm-cvm/openhcl-x64-cvm.bin
```

## What it compares

- Platform definitions and guest policies, resolving compatibility masks by platform type.
- Page addresses, types, shared/unmeasured flags, and payload SHA-256 digests.
- Parameter areas, parameter directives, insertions, memory requirements, and relocation settings.
- SNP/SEV-ES, VBS, and native/SEV CPU state payloads. SNP and VBS reports also show selected registers, including RIP, CR3, and EFER.
- SNP ID blocks, VBS measurement records, and CoRIM document/signature payloads. CoRIM contents are compared as opaque bytes.
- Payloads behind changed page contents. For each platform, the pages are assembled into guest memory and scanned at page boundaries for UEFI firmware volumes, Linux bzImages, ELF images, and PE images. Changed pages outside these are counted separately.
- Attestation impact, per isolation platform: whether measured page data changed, which changes the launch measurement; whether unmeasured or shared page data changed, which the launch measurement does not cover; and whether the VP context, guest policy, identity records (SNP ID block, VBS measurement, CoRIM), platform definitions, or boot parameters changed. Whether the launch measurement changes is taken from the computed digests when they are available, because page flags alone miss an added or moved unmeasured page, whose address is still measured, and would flag a mask-only change. Measured status per page comes only from the IGVM page data flags (`unmeasured`, `shared`). The `native` platform has no launch measurement and is left out.
- ELF images by section, and by function when a symbol table is present. Functions are matched by name with compiler hash suffixes removed (`17h<hash>E`, `.llvm.<n>`) and legacy Rust mangling decoded, so a rebuilt function is reported as changed rather than as removed and added.
- PE images, such as Unified Kernel Images, by section: the report names the PE sections whose bytes changed, and for short text sections (`.cmdline`, `.osrel`, `.uname`) shows the words removed and added.
- Firmware modules inside those firmware volumes, including LZMA-compressed and nested volumes. Modules are matched by file GUID, so a changed volume layout still compares module by module. Each module is compared on its FFS file type, attributes and state, its section types, lengths and GUID-defined headers, and its section contents. Modules that differ only in the PE/COFF timestamps, the optional-header checksum, or the signature and path of a CodeView (`RSDS`/`NB10`) record are listed apart from modified ones. PE normalization is all or nothing. The module is compared as raw bytes if the debug directory or the CodeView record is not inside the raw data of a non-executable section that does not hold the entry point, if there is more than one CodeView record, if the record overlaps the directory or has a non-ASCII path, or if there are more than 16 debug entries. Section flags come from the vendor's build, so these checks limit what can be masked rather than prove it is debug data; debug-data-only modules are therefore always listed by name. Bytes of a volume outside its files (headers, pad files, and any non-erased padding or free space) are compared as one entry per volume. Other build noise, such as build paths compiled into code, still counts as a modification. Modules are grouped by the PI boot phase that runs them (SEC, PEI, DXE, MM, UEFI applications), based on their FFS file type; the Volume Top File, which holds the reset vector, is listed under SEC.

## Current scope

Supports x64 IGVM v1 and v2 with 4 KiB pages, using the `igvm` parser. AArch64/CCA and 2 MiB pages are not supported. Unknown records and VMSAs with obfuscated registers return an error.

Each input is limited to 256 MiB, 131,072 records, and 512 MiB of referenced or implicit payloads; published SEV-SNP images with a kernel and initrd reach about 147 MiB and 38,000 records. VBS contexts support the boot processor with up to 256 registers per context. Comparisons run locally and leave both files unchanged.

Payload analysis is best effort and never changes the exit code. A firmware volume that cannot be decoded is reported with the reason. Only EDK2 LZMA encapsulation is decompressed. For each input and platform, decoding is limited to 128 MiB of decompressed data, 16,384 firmware files, and 8 nesting levels. Other compressed sections and TE images are compared as bytes. ELF, PE, and bzImage payloads are located but not decoded.

Launch measurements are computed for SEV-SNP (launch digest), TDX (MRTD) and VBS (boot measurement digest) with the `igvm` crate's `measurement` module. For SEV-SNP the report also shows the value computed the way COCONUT-SVSM `igvmmeasure --native-zero` does (zero-filled pages measured as SNP ZERO pages) when it differs, and checks the file's SNP ID block launch digest against the computed values. Loaders differ in how they measure zero-filled and shared pages. SEV-SNP values measure the file's VMSAs as stored; QEMU/KVM instead copies selected registers into each vCPU and measures the VMSA KVM builds (QEMU `target/i386/sev.c`, `sev_apply_cpu_context`), which is why the c8s images' published digests, taken from launched guests, cannot be computed from the file. Compare the computed values with the vendor's published reference and with your attestation reports. The fixtures pin these values against vendor-published ones: every GCE SVSM object name equals the `--native-zero` value, and the OpenHCL CVM image's published `snp_ld`, `tdx_mrtd` and `vbs_boot_digest` equal the `igvm` crate values.

The report helps focus a source and build review. It does not verify signatures or decide whether a build is safe to accept.

## Development

Install Rust through [rustup](https://rustup.rs/), then run:

```sh
rustup toolchain install --profile minimal
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
```

## License

Licensed under the [MIT License](LICENSE).

## Contributions

Issues and pull requests are welcome. Keep changes focused and run the development checks above before submitting a pull request.
