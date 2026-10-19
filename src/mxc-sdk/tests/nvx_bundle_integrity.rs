// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[allow(dead_code)]
#[path = "../build/build_nvx_bundled.rs"]
mod build_nvx_bundled;

use sha2::{Digest, Sha256};

fn digest(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture() -> (tempfile::TempDir, Vec<(&'static str, String)>) {
    let directory = tempfile::tempdir().expect("bundle fixture");
    let files = [
        ("SHA256SUMS", b"checksums".as_slice()),
        ("SOURCE-MANIFEST.json", b"source manifest".as_slice()),
        ("bin/direct-images.exe", b"image tool".as_slice()),
        ("guest/initramfs-edge.cpio.gz", b"guest".as_slice()),
    ];
    for (relative, contents) in files {
        let path = directory.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("create fixture parent");
        std::fs::write(path, contents).expect("write fixture");
    }
    let expected = files
        .into_iter()
        .map(|(path, contents)| (path, digest(contents)))
        .collect();
    (directory, expected)
}

fn verify(directory: &std::path::Path, expected: &[(&str, String)]) {
    let expected: Vec<(&str, &str)> = expected
        .iter()
        .map(|(path, digest)| (*path, digest.as_str()))
        .collect();
    build_nvx_bundled::verify_bundle_against(directory, &expected);
}

#[test]
fn accepts_complete_pinned_bundle() {
    let (directory, expected) = fixture();
    verify(directory.path(), &expected);
}

#[test]
fn rejects_modified_guest_helper_and_checksum_metadata() {
    for relative in [
        "guest/initramfs-edge.cpio.gz",
        "bin/direct-images.exe",
        "SHA256SUMS",
        "SOURCE-MANIFEST.json",
    ] {
        let (directory, expected) = fixture();
        std::fs::write(directory.path().join(relative), b"modified").expect("tamper fixture");
        let result = std::panic::catch_unwind(|| verify(directory.path(), &expected));
        assert!(result.is_err(), "modified {relative} must be rejected");
    }
}

#[test]
fn rejects_missing_or_unlisted_bundle_files() {
    let (directory, expected) = fixture();
    std::fs::remove_file(directory.path().join("guest/initramfs-edge.cpio.gz"))
        .expect("remove fixture");
    assert!(
        std::panic::catch_unwind(|| verify(directory.path(), &expected)).is_err(),
        "missing official files must be rejected"
    );

    let (directory, expected) = fixture();
    std::fs::write(directory.path().join("mutable-release.txt"), b"unexpected")
        .expect("write unexpected fixture");
    assert!(
        std::panic::catch_unwind(|| verify(directory.path(), &expected)).is_err(),
        "unlisted files must be rejected"
    );
}
