/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Replays saved compiler failure test cases.
//!
//! Run with:
//!   cargo test -p cedar-drt --test replay_compiler_failures
//!
//! By default, looks for failures in `fuzz/failures/compiler/`.
//! Override with COMPILER_FAILURES_DIR env var.

use cedar_drt::tests::replay_compiler_failures;
use cedar_drt::CedarCompilerEngine;

#[test]
fn replay_all_compiler_failures() {
    let dir =
        std::env::var("COMPILER_FAILURES_DIR").unwrap_or_else(|_| "fuzz/failures/compiler".into());
    let engine = CedarCompilerEngine::new();
    let count = replay_compiler_failures(&engine, &dir);
    if count > 0 {
        eprintln!("Replayed {} compiler failure test cases", count);
    } else {
        eprintln!("No compiler failure test cases found in {}", dir);
    }
}
