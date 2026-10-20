// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

const OFFICIAL_BUNDLE_FILES: &[(&str, &str)] = &[
    (
        "SHA256SUMS",
        "d86b7768ca51e6ea93c40880cc027c85280e718e960e1efe3e0e80bd23727fce",
    ),
    (
        "SOURCE-MANIFEST.json",
        "d5487737b07d663d983373dec82d917bbfcab58e39fed45b6642e8885c3fb01b",
    ),
    (
        "bin/aci_edge_agent.dll",
        "a203e58b97a642bd4a68824c0387965541895b25582e18db6f55e28947f5f135",
    ),
    (
        "bin/direct-images.exe",
        "633b679a8f8f2586626b7475b1e5e3faa3d2ea7119082ffc5873191194feb6fe",
    ),
    (
        "bin/openvmm.exe",
        "697f8221e62a1ea4efb3846fefde6f595c89f4f81c0153a2609bf6fb4c81ea9e",
    ),
    (
        "bundle-manifest.json",
        "44c9c355dee41bd0cd098b9ccfb623ddb7508407c213ca3343090500348e9253",
    ),
    (
        "guest/initramfs-edge.cpio.gz",
        "5e42d4617c1508e9116df8c330c0ff72243e954d7f132091ecdecfc743d904ed",
    ),
    (
        "guest/nvx-edge-agent",
        "d29acada883da8f2977036958704516545cb295114e94999eb269094b81aaff7",
    ),
    (
        "guest/vmlinux",
        "b36ab45b22d1c14438047b24c3724f54cc71dd03601d0f3cbdca11438f40e768",
    ),
    (
        "guest/vmlinux.config",
        "89228d78a10ac9d8f151384b0adc5a155c8a1ee045732b17e236a0e28b49297d",
    ),
    (
        "provenance/edge-guest.json",
        "31512ee712657ede1884ad2ed04f86200f78f282a9fb8e6f0855a4790875507b",
    ),
    (
        "provenance/edge-windows.json",
        "21f2455e680b565dac122ac4be3cf793159e31979ccc6def3a982a4013ae209f",
    ),
    (
        "provenance/licenses/linux/COPYING-LINUX",
        "4fc360c08586ee232e17eaf34e97feae0065dc3daacb2210b754921dc587a5c5",
    ),
    (
        "provenance/licenses/nvx/LICENSE",
        "7df20dcdf9197e9945c14858d41c60f11b52b93e5b69e2b63416b874d598d322",
    ),
    (
        "provenance/licenses/nvx/THIRD_PARTY_NOTICES.md",
        "d659326442a1092e29ba2edec81ff6cb3a4ad63dbdd36a166478eb08fecd9fe0",
    ),
    (
        "provenance/licenses/openvmm/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/openvmm.provenance.json",
        "adfd57d7a7197f91604acad3eea30b583fa3f442b4b8cabd1147611c5c1b3521",
    ),
    (
        "provenance/vmlinux.provenance.json",
        "a526683d54302c87c2dacbecdfcc879817c4ba2f1e21241f0d2c9d170b17cc58",
    ),
];

pub(crate) fn run() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MICROVM");
    println!("cargo:rerun-if-env-changed=DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR");
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    // Cargo does not inherit a dependency checkout's .cargo/config.toml. Authenticate the exact
    // extracted release here so downstream path and Git consumers cannot select another bundle.
    let source = PathBuf::from(
        std::env::var_os("DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR")
            .expect("microvm requires the official signed agent-bundled NVX release"),
    );
    verify_bundle(&source);

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let target = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has target/profile ancestors")
        .join("aci-edge-sandboxes");
    copy_bundle(&source, &target);
    verify_bundle(&target);
}

fn sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "cannot read signed NVX artifact {}: {error}",
            path.display()
        )
    });
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_bundle(source: &Path) {
    verify_bundle_against(source, OFFICIAL_BUNDLE_FILES);
}

pub(crate) fn verify_bundle_against(source: &Path, expected_files: &[(&str, &str)]) {
    assert_safe_directory(source, "NVX bundle source");
    let expected: BTreeMap<&str, &str> = expected_files.iter().copied().collect();
    assert_eq!(
        expected.len(),
        expected_files.len(),
        "official NVX bundle file list contains duplicate paths"
    );

    let mut actual = BTreeMap::new();
    collect_bundle_files(source, source, &mut actual);
    let actual_paths: Vec<&str> = actual.keys().map(String::as_str).collect();
    let expected_paths: Vec<&str> = expected.keys().copied().collect();
    assert_eq!(
        actual_paths, expected_paths,
        "microvm requires the complete signed v0.1.0-dev.0430ce79d125 bundle"
    );

    for (relative, path) in actual {
        let expected_sha256 = expected[relative.as_str()];
        assert_eq!(
            sha256(&path),
            expected_sha256,
            "microvm requires the signed v0.1.0-dev.0430ce79d125 artifact {relative}"
        );
    }
}

fn collect_bundle_files(source: &Path, directory: &Path, files: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
        let kind = metadata.file_type();
        assert!(
            !kind.is_symlink() && !is_reparse_point(&metadata),
            "NVX bundle must not contain links or reparse points"
        );
        if kind.is_dir() {
            collect_bundle_files(source, &path, files);
            continue;
        }
        assert!(kind.is_file(), "NVX bundle must contain only regular files");
        let relative = path
            .strip_prefix(source)
            .expect("bundle entry remains under its source");
        assert!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "NVX bundle path is not safe: {}",
            relative.display()
        );
        let relative = relative
            .to_str()
            .unwrap_or_else(|| panic!("NVX bundle path is not UTF-8: {}", relative.display()))
            .replace('\\', "/");
        assert!(
            files.insert(relative.clone(), path).is_none(),
            "duplicate NVX bundle path: {relative}"
        );
    }
}

fn copy_bundle(source: &Path, target: &Path) {
    assert_safe_directory(source, "NVX bundle source");
    assert_safe_destination(target);
    std::fs::create_dir_all(target)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", target.display()));
    for entry in std::fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", source.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let from = entry.path();
        let to = target.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&from)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", from.display()));
        let kind = metadata.file_type();
        assert!(
            !kind.is_symlink() && !is_reparse_point(&metadata),
            "NVX bundle must not contain links or reparse points"
        );
        if kind.is_dir() {
            copy_bundle(&from, &to);
        } else {
            assert!(kind.is_file(), "NVX bundle must contain only regular files");
            println!("cargo:rerun-if-changed={}", from.display());
            let contents = std::fs::read(&from)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()));
            assert_safe_destination(&to);
            if std::fs::read(&to).is_ok_and(|existing| existing == contents) {
                continue;
            }
            std::fs::copy(&from, &to).unwrap_or_else(|error| {
                panic!(
                    "cannot stage signed NVX artifact {} to {}: {error}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}

fn assert_safe_directory(path: &Path, description: &str) {
    assert_safe_ancestors(path, description, false);
    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("cannot inspect {description} {}: {error}", path.display()));
    assert!(
        metadata.is_dir(),
        "{description} must be a directory: {}",
        path.display()
    );
}

fn assert_safe_destination(target: &Path) {
    assert_safe_ancestors(target, "NVX bundle destination", true);
}

fn assert_safe_ancestors(target: &Path, description: &str, allow_missing: bool) {
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|error| panic!("cannot resolve {description}: {error}"))
            .join(target)
    };
    // Inspect parents first, without resolving links in the untrusted path.
    let ancestors: Vec<_> = absolute.ancestors().collect();
    for path in ancestors.into_iter().rev() {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => panic!("cannot inspect {description} {}: {error}", path.display()),
        };
        assert!(
            !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
            "{description} must not traverse a link or reparse point: {}",
            path.display()
        );
    }
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn create_directory_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(original, link)
    }

    #[cfg(unix)]
    fn create_directory_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    #[cfg(windows)]
    fn create_file_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(original, link)
    }

    #[cfg(unix)]
    fn create_file_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    fn link_created_or_skipped(result: std::io::Result<()>, description: &str) -> bool {
        match result {
            Ok(()) => {
                eprintln!("executing {description}: link creation succeeded");
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping {description}: link creation is not permitted: {error}");
                false
            }
            Err(error) => panic!("cannot create link for {description}: {error}"),
        }
    }

    fn assert_source_link_rejected(action: impl FnOnce() + std::panic::UnwindSafe, link: &Path) {
        let error = std::panic::catch_unwind(action).expect_err("source link must be rejected");
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .expect("source rejection message");
        assert!(
            message.contains("NVX bundle source must not traverse a link or reparse point"),
            "{message}"
        );
        assert!(message.contains(&link.display().to_string()), "{message}");
    }

    fn check_linked_source_parent(create_link: impl FnOnce(&Path, &Path) -> std::io::Result<()>) {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let parent = root.join("parent");
        let source = parent.join("bundle");
        let linked_parent = root.join("linked-parent");
        let destination = root.join("destination");
        std::fs::create_dir_all(&source).expect("source directory");
        std::fs::create_dir(&destination).expect("destination directory");
        std::fs::write(source.join("file"), b"approved contents").expect("source file");
        let sentinel = destination.join("sentinel");
        std::fs::write(&sentinel, b"owned sentinel").expect("destination sentinel");
        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);
        let positive_destination = root.join("positive-destination");
        copy_bundle(&source, &positive_destination);
        verify_bundle_against(&positive_destination, &expected);

        if !link_created_or_skipped(
            create_link(&parent, &linked_parent),
            "linked source ancestor rejection",
        ) {
            return;
        }
        let linked_source = linked_parent.join("bundle");
        assert!(!std::fs::symlink_metadata(&linked_source)
            .expect("ordinary bundle under linked parent")
            .file_type()
            .is_symlink());
        assert_source_link_rejected(
            || verify_bundle_against(&linked_source, &expected),
            &linked_parent,
        );
        assert_source_link_rejected(|| copy_bundle(&linked_source, &destination), &linked_parent);
        assert_eq!(
            std::fs::read(&sentinel).expect("unchanged sentinel"),
            b"owned sentinel"
        );
        let entries: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree")
            .map(|entry| entry.expect("destination entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("sentinel")]);
        verify_bundle_against(&source, &expected);
    }

    #[test]
    fn rejects_linked_source_ancestor_before_reading_or_writing() {
        check_linked_source_parent(create_directory_link);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_junction_source_ancestor_before_reading_or_writing() {
        check_linked_source_parent(|original, link| {
            let output = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(link)
                .arg(original)
                .output()?;
            assert!(
                output.status.success(),
                "junction creation failed: {output:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn rejects_linked_source_root_when_supported() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let linked_source = root.join("linked-source");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::write(source.join("file"), b"contents").expect("source file");
        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);

        if !link_created_or_skipped(
            create_directory_link(&source, &linked_source),
            "linked source root rejection",
        ) {
            return;
        }

        assert_source_link_rejected(
            || verify_bundle_against(&linked_source, &expected),
            &linked_source,
        );
        let destination = root.join("destination");
        assert_source_link_rejected(|| copy_bundle(&linked_source, &destination), &linked_source);
        assert!(
            !destination.exists(),
            "source rejection precedes destination creation"
        );
    }

    #[test]
    fn rejects_linked_destination_before_writing_when_supported() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let redirected = root.join("redirected");
        let destination = root.join("destination");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::create_dir(&redirected).expect("redirected directory");
        std::fs::write(source.join("file"), b"contents").expect("source file");
        if !link_created_or_skipped(
            create_directory_link(&redirected, &destination),
            "linked destination directory rejection",
        ) {
            return;
        }

        assert!(std::panic::catch_unwind(|| copy_bundle(&source, &destination)).is_err());
        assert!(
            !redirected.join("file").exists(),
            "destination rejection must happen before the first write"
        );
    }

    #[test]
    fn rejects_linked_destination_file_before_reading_or_writing() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let positive_destination = root.join("positive-destination");
        let destination = root.join("destination");
        let sentinel = root.join("sentinel");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::create_dir(&destination).expect("destination directory");
        std::fs::write(source.join("file"), b"approved contents").expect("source file");
        std::fs::write(&sentinel, b"owned sentinel").expect("sentinel file");

        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);
        copy_bundle(&source, &positive_destination);
        assert_eq!(
            std::fs::read(positive_destination.join("file")).expect("positive staged file"),
            b"approved contents"
        );

        let destination_file = destination.join("file");
        if !link_created_or_skipped(
            create_file_link(&sentinel, &destination_file),
            "linked destination file rejection",
        ) {
            return;
        }
        let sentinel_digest = sha256(&sentinel);
        let tree_before: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree")
            .map(|entry| entry.expect("destination entry").file_name())
            .collect();

        assert!(
            std::panic::catch_unwind(|| copy_bundle(&source, &destination)).is_err(),
            "linked destination file must be rejected"
        );
        assert_eq!(
            sha256(&sentinel),
            sentinel_digest,
            "sentinel must be unchanged"
        );
        let tree_after: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree after rejection")
            .map(|entry| {
                entry
                    .expect("destination entry after rejection")
                    .file_name()
            })
            .collect();
        assert_eq!(
            tree_after, tree_before,
            "destination tree must be unchanged"
        );
        assert!(
            std::fs::symlink_metadata(&destination_file)
                .expect("destination link after rejection")
                .file_type()
                .is_symlink(),
            "destination file link must remain in place"
        );
    }
}
