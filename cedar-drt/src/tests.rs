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

use cedar_testing::cedar_test_impl::{
    time_function, CedarTestImplementation, ErrorComparisonMode, TestResult, TestValidationResult,
    ValidationComparisonMode,
};

use cedar_policy::{
    eval_expression, ffi, AuthorizationError, Authorizer, Entities, Expression, PolicySet, Request,
    Response, Schema, ValidationMode, ValidationResult, Validator,
};

use cedar_policy_core::entities::TypeAndId;
use libfuzzer_sys::arbitrary::{self, Unstructured};
use log::info;
use miette::miette;
use std::collections::HashSet;
use std::fs;
use std::io::Write;

/// Times for cedar-policy authorization and validation.
pub const RUST_AUTH_MSG: &str = "rust_auth (ns) : ";
pub const RUST_VALIDATION_MSG: &str = "rust_validation (ns) : ";
pub const RUST_ENT_VALIDATION_MSG: &str = "rust_entity_validation (ns) : ";
pub const RUST_REQ_VALIDATION_MSG: &str = "rust_request_validation (ns) : ";

pub fn run_eval_test(
    custom_impl: &impl CedarTestImplementation,
    request: &Request,
    expr: &Expression,
    entities: &Entities,
) {
    let expected = eval_expression(request, entities, expr).ok();

    // `custom_impl.interpret()` returns true when the result of evaluating `expr`
    // matches `expected`
    let definitional_res = custom_impl.interpret(&request, entities, expr, expected.clone());

    match definitional_res {
        TestResult::Failure(err) => {
            // TODO(#175): Ignore cases where the definitional code returned an error due to
            // an unknown extension function.
            if err.contains("unknown extension function") {
                return;
            }
            // No other errors are expected
            panic!("Unexpected error for {request}\nExpression: {expr}\nError: {err}");
        }
        TestResult::Success(response) => {
            // The definitional interpreter response should be `true`
            assert!(
                response,
                "Incorrect evaluation result for {request}\nExpression: {expr}\nEntities:\n{}\nExpected value:\n{:?}\n",
                entities.as_ref(),
                expected
            )
        }
    }
}

/// Compare the behavior of the authorizer in `cedar-policy` against a custom Cedar
/// implementation. Panics if the two do not agree. Returns the response that
/// the two agree on.
pub fn run_auth_test(
    custom_impl: &impl CedarTestImplementation,
    request: &Request,
    policies: &PolicySet,
    entities: &Entities,
) -> Response {
    let authorizer = Authorizer::new();
    let (rust_res, rust_auth_dur) =
        time_function(|| authorizer.is_authorized(request, policies, entities));
    info!("{}{}", RUST_AUTH_MSG, rust_auth_dur.as_nanos());

    let definitional_res = custom_impl.is_authorized(&request, policies, entities);

    match definitional_res {
        TestResult::Failure(err) => {
            // TODO(#175): For now, ignore cases where the Lean code returned an error due to
            // an unknown extension function.
            if err.contains("unknown extension function") {
                rust_res
            } else {
                panic!(
                    "Unexpected error for {request}\nPolicies:\n{}\nEntities:\n{}\nError: {err}",
                    &policies,
                    &entities.as_ref()
                );
            }
        }
        TestResult::Success(definitional_res) => {
            let rust_res_for_comparison: ffi::Response = {
                let errors = match custom_impl.error_comparison_mode() {
                    ErrorComparisonMode::Ignore => HashSet::new(),
                    ErrorComparisonMode::PolicyIds => rust_res
                        .diagnostics()
                        .errors()
                        .cloned()
                        .map(|err| match err {
                            AuthorizationError::PolicyEvaluationError(err) => {
                                ffi::AuthorizationError::new_from_report(
                                    err.policy_id().clone(),
                                    miette!("{}", err.policy_id()),
                                )
                            }
                        })
                        .collect(),
                    ErrorComparisonMode::Full => rust_res
                        .diagnostics()
                        .errors()
                        .cloned()
                        .map(Into::into)
                        .collect(),
                };
                ffi::Response::new(
                    rust_res.decision(),
                    rust_res.diagnostics().reason().cloned().collect(),
                    errors,
                )
            };
            assert_eq!(
                rust_res_for_comparison,
                definitional_res.response,
                "Mismatch for {request}\nPolicies:\n{policies}\nEntities:\n{}",
                entities.as_ref()
            );
            rust_res
        }
    }
}

/// Save a failing test case to disk in Cedar integration test format.
/// Creates a directory with .cedar, .entities.json, and .json files that can
/// be replayed via the replay runner.
///
/// `component` is "compiler" or "lean" — determines the output directory.
fn save_failure(
    request: &Request,
    policies: &PolicySet,
    entities: &Entities,
    rust_response: &ffi::Response,
    component: &str,
    kind: &str,
) {
    let env_var = format!("{}_FAILURES_DIR", component.to_uppercase());
    let default_dir = format!("fuzz/failures/{}", component);
    let base = std::env::var(&env_var).unwrap_or_else(|_| default_dir);
    let _ = fs::create_dir_all(&base);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = format!("fail_{}_{}", kind, timestamp);
    let dir = format!("{}/{}", base, name);
    let _ = fs::create_dir_all(&dir);

    // policy.cedar
    let policy_text: String = policies
        .as_ref()
        .static_policies()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = fs::write(format!("{}/policy.cedar", dir), &policy_text);

    // entities.json
    if let Ok(f) = fs::File::create(format!("{}/entities.json", dir)) {
        let _ = entities.write_to_json(f);
    }

    // test.json — Cedar integration test format
    let euid_to_json = |euid: &cedar_policy::EntityUid| -> serde_json::Value {
        let tyid = TypeAndId::from(euid.as_ref());
        serde_json::to_value(tyid).unwrap_or(serde_json::Value::Null)
    };

    let context_json = request
        .context()
        .map(|ctx| {
            ctx.clone()
                .into_iter()
                .map(|(k, pval)| {
                    (
                        k,
                        pval.as_ref()
                            .to_natural_json()
                            .unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>()
        })
        .map(serde_json::Value::Object)
        .unwrap_or(serde_json::json!({}));

    let json_request = cedar_testing::integration_testing::JsonRequest {
        description: format!("Compiler {} failure", kind),
        principal: euid_to_json(request.principal().unwrap()),
        action: euid_to_json(request.action().unwrap()),
        resource: euid_to_json(request.resource().unwrap()),
        context: context_json,
        validate_request: false,
        decision: rust_response.decision(),
        reason: rust_response.diagnostics().reason().cloned().collect(),
        errors: rust_response
            .diagnostics()
            .errors()
            .map(|e| e.policy_id().clone())
            .collect(),
    };

    let test = cedar_testing::integration_testing::JsonTest {
        schema: String::new(),
        policies: "policy.cedar".into(),
        entities: "entities.json".into(),
        should_validate: false,
        requests: vec![json_request],
    };

    if let Ok(f) = fs::File::create(format!("{}/test.json", dir)) {
        let _ = serde_json::to_writer_pretty(f, &test);
    }
}

/// Compare the behavior of the authorizer across three implementations:
/// Rust interpreter, Lean spec, and compiled policies.
/// Panics if any two do not agree.
pub fn run_three_way_auth_test(
    lean_impl: &impl CedarTestImplementation,
    compiler_impl: &impl CedarTestImplementation,
    request: &Request,
    policies: &PolicySet,
    entities: &Entities,
) -> Response {
    let authorizer = Authorizer::new();
    let (rust_res, rust_auth_dur) =
        time_function(|| authorizer.is_authorized(request, policies, entities));
    info!("{}{}", RUST_AUTH_MSG, rust_auth_dur.as_nanos());

    // Get Lean result
    let lean_res = lean_impl.is_authorized(&request, policies, entities);

    // Get Compiler result
    let compiler_res = compiler_impl.is_authorized(&request, policies, entities);

    // Helper to convert rust response for comparison
    let rust_res_for_comparison = |error_mode: ErrorComparisonMode| -> ffi::Response {
        let errors = match error_mode {
            ErrorComparisonMode::Ignore => HashSet::new(),
            ErrorComparisonMode::PolicyIds => rust_res
                .diagnostics()
                .errors()
                .cloned()
                .map(|err| match err {
                    AuthorizationError::PolicyEvaluationError(err) => {
                        ffi::AuthorizationError::new_from_report(
                            err.policy_id().clone(),
                            miette!("{}", err.policy_id()),
                        )
                    }
                })
                .collect(),
            ErrorComparisonMode::Full => rust_res
                .diagnostics()
                .errors()
                .cloned()
                .map(Into::into)
                .collect(),
        };
        ffi::Response::new(
            rust_res.decision(),
            rust_res.diagnostics().reason().cloned().collect(),
            errors,
        )
    };

    // Compare Rust vs Lean
    let rust_cmp_for_lean = rust_res_for_comparison(lean_impl.error_comparison_mode());
    match lean_res {
        TestResult::Failure(ref err) => {
            if !err.contains("unknown extension function") {
                save_failure(
                    request,
                    policies,
                    entities,
                    &rust_cmp_for_lean,
                    "lean",
                    "error",
                );
                panic!(
                    "Lean error for {request}\nPolicies:\n{}\nEntities:\n{}\nError: {err}",
                    &policies,
                    &entities.as_ref()
                );
            }
        }
        TestResult::Success(ref lean_result) => {
            if rust_cmp_for_lean != lean_result.response {
                save_failure(
                    request,
                    policies,
                    entities,
                    &rust_cmp_for_lean,
                    "lean",
                    "mismatch",
                );
            }
            assert_eq!(
                rust_cmp_for_lean,
                lean_result.response,
                "Rust vs Lean mismatch for {request}\nPolicies:\n{policies}\nEntities:\n{}",
                entities.as_ref()
            );
        }
    }

    // Compare Rust vs Compiler
    let rust_cmp_for_compiler = rust_res_for_comparison(compiler_impl.error_comparison_mode());
    match compiler_res {
        TestResult::Failure(ref err) => {
            save_failure(
                request,
                policies,
                entities,
                &rust_cmp_for_compiler,
                "compiler",
                "error",
            );
            panic!(
                "Compiler error for {request}\nPolicies:\n{}\nEntities:\n{}\nError: {err}",
                &policies,
                &entities.as_ref()
            );
        }
        TestResult::Success(ref compiler_result) => {
            if rust_cmp_for_compiler != compiler_result.response {
                save_failure(
                    request,
                    policies,
                    entities,
                    &rust_cmp_for_compiler,
                    "compiler",
                    "mismatch",
                );
            }
            assert_eq!(
                rust_cmp_for_compiler,
                compiler_result.response,
                "Rust vs Compiler mismatch for {request}\nPolicies:\n{policies}\nEntities:\n{}",
                entities.as_ref()
            );
        }
    }

    rust_res
}

/// Compare the behavior of the validator in `cedar-policy` against a custom Cedar
/// implementation. Panics if the two do not agree.
pub fn run_val_test(
    custom_impl: &impl CedarTestImplementation,
    schema: Schema,
    policies: &PolicySet,
    mode: ValidationMode,
) {
    let validator = Validator::new(schema.clone());
    let (rust_res, rust_validation_dur) = time_function(|| validator.validate(policies, mode));
    info!("{}{}", RUST_VALIDATION_MSG, rust_validation_dur.as_nanos());
    let definitional_res = custom_impl.validate(&schema, policies, mode);
    compare_validation_results(
        policies,
        &schema,
        custom_impl.validation_comparison_mode(),
        rust_res,
        definitional_res,
    );
}

pub fn run_level_val_test(
    custom_impl: &impl CedarTestImplementation,
    schema: Schema,
    policies: &PolicySet,
    mode: ValidationMode,
    level: i32,
) {
    let validator = Validator::new(schema.clone());
    let (rust_res, rust_validation_dur) =
        time_function(|| validator.validate_with_level(policies, mode, level as u32));
    info!("{}{}", RUST_VALIDATION_MSG, rust_validation_dur.as_nanos());
    let definitional_res = custom_impl.validate_with_level(&schema, policies, mode, level);
    compare_validation_results(
        policies,
        &schema,
        custom_impl.validation_comparison_mode(),
        rust_res,
        definitional_res,
    );
}

fn compare_validation_results(
    policies: &PolicySet,
    schema: &Schema,
    comparison_mode: ValidationComparisonMode,
    rust_res: ValidationResult,
    definitional_res: TestResult<TestValidationResult>,
) {
    match definitional_res {
        TestResult::Failure(err) => {
            // TODO(#175): For now, ignore cases where the Lean code returned an error due to
            // an unknown extension function.
            if !err.contains("unknown extension function")
                && !err.contains("unknown extension type")
            {
                panic!(
                    "Unexpected error\nPolicies:\n{}\nSchema:\n{:?}\nError: {err}",
                    &policies, schema
                );
            }
        }
        TestResult::Success(definitional_res) => {
            if rust_res.validation_passed() {
                // If `cedar-policy` does not return an error, then the spec should not return an error.
                // This implies type soundness of the `cedar-policy` validator since type soundness of the
                // spec is formally proven.
                //
                // In particular, we have proven that if the spec validator does not return an error (B),
                // then there are no authorization-time errors modulo some restrictions (C). So (B) ==> (C).
                // DRT checks that if the `cedar-policy` validator does not return an error (A), then neither
                // does the spec validator (B). So (A) ==> (B). By transitivity then, (A) ==> (C).
                assert!(
                    definitional_res.validation_passed(),
                    "Mismatch for Policies:\n{}\nSchema:\n{:?}\ncedar-policy response: {:?}\nTest engine response: {:?}\n",
                    &policies,
                    schema,
                    rust_res,
                    definitional_res,
                );
            } else {
                // If `cedar-policy` returns an error, then only check the spec response
                // if the validation comparison mode is `AgreeOnAll`.
                match comparison_mode {
                    ValidationComparisonMode::AgreeOnAll => {
                        assert!(
                            !definitional_res.validation_passed(),
                            "Mismatch for Policies:\n{}\nSchema:\n{:?}\ncedar-policy response: {:?}\nTest engine response: {:?}\n",
                            &policies,
                            schema,
                            rust_res,
                            definitional_res,
                        );
                    }
                    ValidationComparisonMode::AgreeOnValid => {} // ignore
                };
            }
        }
    }
}

pub fn run_ent_val_test(
    custom_impl: &impl CedarTestImplementation,
    schema: Schema,
    entities: Entities,
) {
    let (rust_res, rust_auth_dur) =
        time_function(|| Entities::from_entities(entities.iter().cloned(), Some(&schema)));
    info!("{}{}", RUST_ENT_VALIDATION_MSG, rust_auth_dur.as_nanos());
    match custom_impl.validate_entities(&schema, &entities) {
        TestResult::Failure(e) => {
            panic!("failed to execute entity validation: {e}");
        }
        TestResult::Success(definitional_res) => {
            if rust_res.is_ok() {
                assert!(
                    definitional_res.validation_passed(),
                    "Definitional Errors: {:?}\n, Rust output: {:?}",
                    definitional_res.errors,
                    rust_res.unwrap()
                );
            } else {
                assert!(
                    !definitional_res.validation_passed(),
                    "Errors: {:?}",
                    definitional_res.errors
                );
            }
        }
    }
}

pub fn run_req_val_test(
    custom_impl: &impl CedarTestImplementation,
    schema: Schema,
    request: Request,
) {
    let (rust_res, rust_auth_dur) = time_function(|| {
        Request::new(
            request.principal().unwrap().clone(),
            request.action().unwrap().clone(),
            request.resource().unwrap().clone(),
            request.context().unwrap().clone(),
            Some(&schema),
        )
    });
    info!("{}{}", RUST_REQ_VALIDATION_MSG, rust_auth_dur.as_nanos());

    match custom_impl.validate_request(&schema, &request) {
        TestResult::Failure(e) => {
            panic!("failed to execute request validation: {e}");
        }
        TestResult::Success(definitional_res) => {
            if rust_res.is_ok() {
                assert!(
                    definitional_res.validation_passed(),
                    "Definitional Errors: {:?}\n, Rust output: {:?}",
                    definitional_res.errors,
                    rust_res.unwrap()
                );
            } else {
                assert!(
                    !definitional_res.validation_passed(),
                    "Errors: {:?}",
                    definitional_res.errors
                );
            }
        }
    }
}

/// Replay saved compiler failure test cases from a directory.
/// Each subdirectory should contain:
///   - `policy.cedar` — the policy text
///   - `entities.json` — entities in Cedar JSON format
///   - `test.json` — test descriptor with request and expected decision
///
/// Returns the number of test cases replayed.
/// Panics if the compiler disagrees with the Rust authorizer on any replayed case.
pub fn replay_compiler_failures(
    compiler_impl: &impl CedarTestImplementation,
    failures_dir: &str,
) -> usize {
    use cedar_testing::integration_testing::JsonTest;
    use std::str::FromStr;

    let dir = std::path::Path::new(failures_dir);
    if !dir.exists() {
        return 0;
    }

    let mut count = 0;
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("Failed to read failures directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let test_dir = entry.path();
        let test_json_path = test_dir.join("test.json");
        let policy_path = test_dir.join("policy.cedar");
        let entities_path = test_dir.join("entities.json");

        if !test_json_path.exists() || !policy_path.exists() || !entities_path.exists() {
            continue;
        }

        let test_name = test_dir.file_name().unwrap().to_string_lossy().to_string();
        eprintln!("Replaying: {}", test_name);

        let test_json_str = fs::read_to_string(&test_json_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", test_json_path.display(), e));
        let test: JsonTest = serde_json::from_str(&test_json_str)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", test_json_path.display(), e));

        let policy_text = fs::read_to_string(&policy_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", policy_path.display(), e));
        let policies = PolicySet::from_str(&policy_text)
            .unwrap_or_else(|e| panic!("Failed to parse policy in {}: {}", test_name, e));

        let entities_str = fs::read_to_string(&entities_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", entities_path.display(), e));
        let entities = Entities::from_json_str(&entities_str, None)
            .unwrap_or_else(|e| panic!("Failed to parse entities in {}: {}", test_name, e));

        let authorizer = Authorizer::new();

        for json_req in &test.requests {
            let principal = cedar_policy::EntityUid::from_json(json_req.principal.clone())
                .unwrap_or_else(|e| panic!("Bad principal in {}: {}", test_name, e));
            let action = cedar_policy::EntityUid::from_json(json_req.action.clone())
                .unwrap_or_else(|e| panic!("Bad action in {}: {}", test_name, e));
            let resource = cedar_policy::EntityUid::from_json(json_req.resource.clone())
                .unwrap_or_else(|e| panic!("Bad resource in {}: {}", test_name, e));
            let context = cedar_policy::Context::from_json_value(json_req.context.clone(), None)
                .unwrap_or_else(|e| panic!("Bad context in {}: {}", test_name, e));

            let request = Request::new(principal, action, resource, context, None)
                .expect("Failed to build request");

            // Get Rust authorizer result
            let rust_res = authorizer.is_authorized(&request, &policies, &entities);

            // Get compiler result
            let compiler_res = compiler_impl.is_authorized(&request, &policies, &entities);

            match compiler_res {
                TestResult::Failure(err) => {
                    panic!(
                        "Replay {}: compiler error: {}\nRequest: {}\nPolicies:\n{}",
                        test_name, err, request, policies,
                    );
                }
                TestResult::Success(compiler_result) => {
                    assert_eq!(
                        rust_res.decision(),
                        compiler_result.response.decision(),
                        "Replay {}: decision mismatch\nRequest: {}\nPolicies:\n{}\nRust: {:?}\nCompiler: {:?}",
                        test_name, request, policies, rust_res.decision(), compiler_result.response.decision(),
                    );
                }
            }
        }
        count += 1;
    }
    count
}

/// Randomly drop some of the entities from the list so the generator can produce
/// some invalid references.
pub fn drop_some_entities(
    entities: Entities,
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<Entities> {
    let should_drop: bool = u.arbitrary()?;
    if should_drop {
        let mut set: Vec<_> = vec![];
        for entity in entities.iter() {
            match u.int_in_range(0..=9)? {
                0 => (),
                _ => {
                    set.push(entity.clone());
                }
            }
        }
        Ok(Entities::from_entities(set, None).expect("Should be valid"))
    } else {
        Ok(entities)
    }
}
