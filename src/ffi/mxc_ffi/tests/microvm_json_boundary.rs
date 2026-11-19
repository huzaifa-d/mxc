// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr;

use mxc_ffi::*;

const CREATE: &str = r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"process":{"commandLine":"true"}}"#;
const EXEC: &str = r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"microvm:0123456789abcdef0123456789abcdef","process":{"commandLine":"true"}}"#;

type Spawn = unsafe extern "C" fn(
    *const std::ffi::c_char,
    i32,
    *mut *mut MxcSandbox,
    *mut MxcErrorDetail,
) -> i32;

type PtySpawn = unsafe extern "C" fn(
    *const std::ffi::c_char,
    i32,
    u16,
    u16,
    *mut *mut MxcSandbox,
    *mut MxcErrorDetail,
) -> i32;

fn spawn_failure(spawn: Spawn, request: &str, experimental: i32) -> (i32, String) {
    let request = CString::new(request).unwrap();
    let mut handle = ptr::dangling_mut();
    let mut detail = MaybeUninit::<MxcErrorDetail>::uninit();
    // SAFETY: request and fresh output locations are valid for the duration of the call.
    let status = unsafe {
        spawn(
            request.as_ptr(),
            experimental,
            &mut handle,
            detail.as_mut_ptr(),
        )
    };
    assert!(handle.is_null());
    // SAFETY: the entry point initializes detail and owns its error strings.
    let mut detail = unsafe { detail.assume_init() };
    assert!(!detail.message_utf8.is_null());
    let message = unsafe { CStr::from_ptr(detail.message_utf8) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { mxc_error_detail_free(&mut detail) };
    assert!(detail.message_utf8.is_null());
    (status, message)
}

fn pty_failure(spawn: PtySpawn, request: &str, experimental: i32) -> (i32, String) {
    let request = CString::new(request).unwrap();
    let mut handle = ptr::dangling_mut();
    let mut detail = MaybeUninit::<MxcErrorDetail>::uninit();
    // SAFETY: request, dimensions, and fresh output locations satisfy the C ABI contract.
    let status = unsafe {
        spawn(
            request.as_ptr(),
            experimental,
            24,
            80,
            &mut handle,
            detail.as_mut_ptr(),
        )
    };
    assert!(handle.is_null());
    // SAFETY: the entry point initializes detail and owns its error strings.
    let mut detail = unsafe { detail.assume_init() };
    assert!(!detail.message_utf8.is_null());
    let message = unsafe { CStr::from_ptr(detail.message_utf8) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { mxc_error_detail_free(&mut detail) };
    (status, message)
}

#[test]
fn microvm_creation_requires_opt_in_and_rejects_lifecycle_envelopes() {
    for (request, expected) in [
        (CREATE, MXC_STATUS_BACKEND_UNAVAILABLE),
        (EXEC, MXC_STATUS_MALFORMED_REQUEST),
    ] {
        let request = CString::new(request).unwrap();
        let mut result = MaybeUninit::<MxcRunResult>::uninit();
        // SAFETY: request and fresh result storage are valid.
        let status = unsafe { mxc_run_json(request.as_ptr(), 0, result.as_mut_ptr()) };
        // SAFETY: the entry point initialized the result.
        let mut result = unsafe { result.assume_init() };
        assert_eq!(status, expected);
        assert_eq!(result.status, status);
        assert!(result.stdout_utf8.is_null());
        assert!(result.stderr_utf8.is_null());
        assert!(!result.error.message_utf8.is_null());
        // SAFETY: result owns the strings returned by the call.
        unsafe { mxc_run_result_free(&mut result) };
        assert!(result.error.message_utf8.is_null());
    }

    #[cfg(all(windows, target_arch = "aarch64"))]
    {
        let request = CString::new(CREATE).unwrap();
        let mut result = MaybeUninit::<MxcRunResult>::uninit();
        // SAFETY: request and fresh result storage are valid.
        let status = unsafe { mxc_run_json(request.as_ptr(), 1, result.as_mut_ptr()) };
        // SAFETY: the entry point initialized the result and error string.
        let mut result = unsafe { result.assume_init() };
        assert_eq!(status, MXC_STATUS_BACKEND_UNAVAILABLE);
        assert!(!result.error.message_utf8.is_null());
        let message = unsafe { CStr::from_ptr(result.error.message_utf8) }
            .to_string_lossy()
            .into_owned();
        assert!(message.contains("Windows x64"), "{message}");
        // SAFETY: result owns the strings returned by the call.
        unsafe { mxc_run_result_free(&mut result) };
    }
}

#[test]
fn microvm_lifecycle_exec_exports_require_opt_in() {
    for spawn in [
        mxc_exec_state_aware_json as Spawn,
        mxc_exec_state_aware_capture_json,
        mxc_exec_state_aware_for_run_json,
    ] {
        let (status, message) = spawn_failure(spawn, EXEC, 0);
        assert_eq!(status, MXC_STATUS_BACKEND_UNAVAILABLE, "{message}");
        assert!(message.contains("experimental"), "{message}");
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let invalid_id = EXEC.replace("microvm:0123456789abcdef0123456789abcdef", "microvm:bad");
        for spawn in [
            mxc_exec_state_aware_json as Spawn,
            mxc_exec_state_aware_capture_json,
            mxc_exec_state_aware_for_run_json,
        ] {
            let (status, message) = spawn_failure(spawn, &invalid_id, 1);
            assert_eq!(status, MXC_STATUS_MALFORMED_ID, "{message}");
        }
    }

    let provision = CString::new(
        r#"{"version":"1.1.0-alpha","phase":"provision","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"}}"#,
    )
    .unwrap();
    for dry_run in [0, 1] {
        let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
        // SAFETY: request and fresh result storage are valid.
        let status = unsafe {
            mxc_run_state_aware_json(provision.as_ptr(), dry_run, 0, result.as_mut_ptr())
        };
        // SAFETY: the entry point initialized the result.
        let mut result = unsafe { result.assume_init() };
        assert_eq!(status, MXC_STATUS_BACKEND_UNAVAILABLE);
        assert_eq!(result.status, status);
        assert!(result.response_json_utf8.is_null());
        assert!(!result.error.message_utf8.is_null());
        // SAFETY: result owns the strings returned by the call.
        unsafe { mxc_state_aware_result_free(&mut result) };
    }
}

#[test]
fn microvm_pty_exports_reject_unsupported_modes() {
    for (spawn, request, expected) in [
        (
            mxc_spawn_pty_json as PtySpawn,
            CREATE,
            MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        ),
        (mxc_state_aware_exec_pty, EXEC, MXC_STATUS_UNSUPPORTED_PHASE),
    ] {
        let (status, message) = pty_failure(spawn, request, 1);
        assert_eq!(status, expected, "{message}");
        assert!(message.to_lowercase().contains("pty"), "{message}");
    }
    let (status, message) = pty_failure(mxc_state_aware_exec_pty, EXEC, 0);
    assert_eq!(status, MXC_STATUS_BACKEND_UNAVAILABLE, "{message}");
    assert!(message.contains("experimental"), "{message}");
}

#[test]
fn microvm_ambiguous_selectors_are_rejected_at_c_boundary() {
    let creation = [
        CREATE.replace(
            r#""containment":"microvm""#,
            r#""containment":"microvm","containment":"process""#,
        ),
        CREATE.replace(
            r#""containment":"microvm""#,
            r#""containment":"microvm","contain\u006dent":"microvm""#,
        ),
    ];
    let lifecycle = [
        EXEC.replace(r#""phase":"exec""#, r#""phase":"exec","phase":"start""#),
        EXEC.replace(r#""phase":"exec""#, r#""phase":"exec","ph\u0061se":"exec""#),
        EXEC.replace(
            r#""sandboxId":"microvm:0123456789abcdef0123456789abcdef""#,
            r#""sandboxId":"microvm:0123456789abcdef0123456789abcdef","sandbox\u0049d":"iso:test""#,
        ),
    ];
    for experimental in [0, 1] {
        for request in &creation {
            let (status, message) = spawn_failure(mxc_spawn_json, request, experimental);
            assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST, "{request}: {message}");
        }
        for request in &lifecycle {
            for spawn in [
                mxc_exec_state_aware_json as Spawn,
                mxc_exec_state_aware_capture_json,
            ] {
                let (status, message) = spawn_failure(spawn, request, experimental);
                assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST, "{request}: {message}");
            }
        }
    }
}
