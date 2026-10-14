// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};

const FILES: [&str; 5] = [
    "SOURCE-MANIFEST.json",
    "SHA256SUMS",
    "bin/openvmm.exe",
    "guest/vmlinux",
    "guest/initramfs.cpio.gz",
];

pub(crate) fn run() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MICROVM");
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let source = PathBuf::from(
        std::env::var_os("DEP_ACI_EDGE_SANDBOXES_ARTIFACTS_DIR")
            .expect("the bundled NVX dependency did not export its artifact directory"),
    );
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let target = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has target/profile ancestors")
        .join("nvx");

    for relative in FILES {
        let from = source.join(relative);
        let to = target.join(relative);
        println!("cargo:rerun-if-changed={}", from.display());
        copy(&from, &to);
    }
}

fn copy(from: &Path, to: &Path) {
    let parent = to.parent().expect("staged NVX files have parents");
    std::fs::create_dir_all(parent)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    std::fs::copy(from, to).unwrap_or_else(|error| {
        panic!(
            "cannot stage bundled NVX artifact {} to {}: {error}",
            from.display(),
            to.display()
        )
    });
}
