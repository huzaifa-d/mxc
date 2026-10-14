// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod policy;
mod process;
pub mod runner;
mod runtime;
pub mod state_aware;

pub(crate) fn is_available() -> bool {
    runtime::create_client().is_ok()
}
