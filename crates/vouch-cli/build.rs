// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Embed a VERSIONINFO resource into `vouch.exe`.
//!
//! Windows Defender's ML heuristics score executables without version
//! metadata as more suspicious, which has repeatedly tripped the winget
//! validation pipeline's security check on new releases. FILEVERSION and
//! PRODUCTVERSION are derived from `CARGO_PKG_VERSION` by winresource.

fn main() -> std::io::Result<()> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set("CompanyName", "Smoke Turner, LLC")
            .set("ProductName", "Vouch")
            .set(
                "FileDescription",
                "Vouch - hardware-backed identity for developers",
            )
            .set("LegalCopyright", "Copyright (c) Smoke Turner, LLC")
            .set("OriginalFilename", "vouch.exe")
            .set("InternalName", "vouch")
            .compile()?;
    }
    Ok(())
}
