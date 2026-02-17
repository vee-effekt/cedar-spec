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

use cedar_policy::{
    ffi, Effect, Entities, EvalResult, Expression, PolicySet, Request, Schema, ValidationMode,
};
use cedar_policy_core::ast as core_ast;

use cedar_testing::cedar_test_impl::{
    CedarTestImplementation, ErrorComparisonMode, Micros, TestResponse, TestResult,
    TestValidationResult, ValidationComparisonMode,
};

use cedar_policy_compiler::Compiler;
use miette::miette;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;

fn log_to_file(msg: &str) {
    let path = std::env::var("COMPILER_LOG").unwrap_or_else(|_| "compiler_harness.log".into());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", msg);
    }
}

pub struct CedarCompilerEngine {
    compiler: Compiler,
}

impl CedarCompilerEngine {
    pub fn new() -> Self {
        Self {
            compiler: Compiler::new(),
        }
    }
}

impl CedarTestImplementation for CedarCompilerEngine {
    fn is_authorized(
        &self,
        request: &Request,
        policies: &PolicySet,
        entities: &Entities,
    ) -> TestResult<TestResponse> {
        log_to_file(&format!(
            "--- is_authorized called ---\nPolicies:\n{}\nRequest: {}\nEntities: {}\n",
            policies,
            request,
            entities.as_ref()
        ));

        let mut eval_time_total = 0u128;
        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

        // Access the core PolicySet to get condition expressions directly,
        // avoiding text round-trip parsing issues
        let core_policy_set: &core_ast::PolicySet = policies.as_ref();

        for (policy, core_policy) in policies.policies().zip(core_policy_set.policies()) {
            let policy_id = policy.id();
            let is_forbid = policy.effect() == Effect::Forbid;
            let condition = core_policy.condition();

            let start = Instant::now();
            let decision = self
                .compiler
                .evaluate_condition(&condition, request, entities);
            let duration = start.elapsed().as_nanos();
            eval_time_total += duration;

            match decision {
                1 => {
                    if is_forbid {
                        satisfied_forbids.push(policy_id.clone());
                    } else {
                        satisfied_permits.push(policy_id.clone());
                    }
                }
                0 => {
                    // Policy not satisfied — no contribution to decision
                }
                2 => {
                    errors.push(ffi::AuthorizationError::new_from_report(
                        policy_id.clone(),
                        miette!("{}", policy_id),
                    ));
                }
                n => {
                    return TestResult::Failure(format!(
                        "Policy {} returned unknown decision value: {}",
                        policy_id, n
                    ));
                }
            }
        }

        // Cedar authorization semantics: forbid overrides permit
        let (decision, determining_policies) = if !satisfied_forbids.is_empty() {
            (cedar_policy::Decision::Deny, satisfied_forbids)
        } else if !satisfied_permits.is_empty() {
            (cedar_policy::Decision::Allow, satisfied_permits)
        } else {
            (cedar_policy::Decision::Deny, vec![])
        };

        log_to_file(&format!("Result: {:?}\n", decision));

        TestResult::Success(TestResponse {
            response: ffi::Response::new(
                decision,
                determining_policies.into_iter().collect(),
                errors.into_iter().collect(),
            ),
            timing_info: HashMap::from([
                ("evaluate".into(), Micros(eval_time_total / 1000)),
                ("authorize".into(), Micros(eval_time_total / 1000)),
            ]),
        })
    }

    /// Custom evaluator entry point. The bool return value indicates whether
    /// evaluating the provided expression produces the expected value.
    /// `expected` is optional to allow for the case where no return value is
    /// expected due to errors.
    fn interpret(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expression,
        expected: Option<EvalResult>,
    ) -> TestResult<bool> {
        // For now, the compiler doesn't have a separate expression evaluator
        // We'll fall back to the standard evaluator
        let result = cedar_policy::eval_expression(request, entities, expr).ok();
        TestResult::Success(result == expected)
    }

    /// Custom validator entry point.
    fn validate(
        &self,
        schema: &Schema,
        policies: &PolicySet,
        mode: ValidationMode,
    ) -> TestResult<TestValidationResult> {
        // The compiler doesn't currently have a separate validator
        // We'll use the standard validator from cedar-policy
        let validator = cedar_policy::Validator::new(schema.clone());
        let start = Instant::now();
        let result = validator.validate(policies, mode);
        let duration = start.elapsed().as_nanos();

        let errors = if result.validation_passed() {
            Vec::new()
        } else {
            result.validation_errors().map(|e| e.to_string()).collect()
        };

        TestResult::Success(TestValidationResult {
            errors,
            timing_info: HashMap::from([("validate".into(), Micros(duration / 1000))]),
        })
    }

    /// Custom validator entry point with level.
    fn validate_with_level(
        &self,
        schema: &Schema,
        policies: &PolicySet,
        mode: ValidationMode,
        level: i32,
    ) -> TestResult<TestValidationResult> {
        // The compiler doesn't currently have a separate validator
        let validator = cedar_policy::Validator::new(schema.clone());
        let start = Instant::now();
        let result = validator.validate_with_level(policies, mode, level as u32);
        let duration = start.elapsed().as_nanos();

        let errors = if result.validation_passed() {
            Vec::new()
        } else {
            result.validation_errors().map(|e| e.to_string()).collect()
        };

        TestResult::Success(TestValidationResult {
            errors,
            timing_info: HashMap::from([("validate".into(), Micros(duration / 1000))]),
        })
    }

    fn validate_request(
        &self,
        schema: &Schema,
        request: &Request,
    ) -> TestResult<TestValidationResult> {
        let start = Instant::now();
        let result = Request::new(
            request.principal().unwrap().clone(),
            request.action().unwrap().clone(),
            request.resource().unwrap().clone(),
            request.context().unwrap().clone(),
            Some(schema),
        );
        let duration = start.elapsed().as_nanos();

        let errors = if result.is_ok() {
            Vec::new()
        } else {
            vec![result.unwrap_err().to_string()]
        };

        TestResult::Success(TestValidationResult {
            errors,
            timing_info: HashMap::from([("validate_request".into(), Micros(duration / 1000))]),
        })
    }

    fn validate_entities(
        &self,
        schema: &Schema,
        entities: &Entities,
    ) -> TestResult<TestValidationResult> {
        let start = Instant::now();
        let result = Entities::from_entities(entities.iter().cloned(), Some(schema));
        let duration = start.elapsed().as_nanos();

        let errors = if result.is_ok() {
            Vec::new()
        } else {
            vec![result.unwrap_err().to_string()]
        };

        TestResult::Success(TestValidationResult {
            errors,
            timing_info: HashMap::from([("validate_entities".into(), Micros(duration / 1000))]),
        })
    }

    /// `ErrorComparisonMode` that should be used for this `CedarTestImplementation`
    fn error_comparison_mode(&self) -> ErrorComparisonMode {
        ErrorComparisonMode::PolicyIds
    }

    /// `ValidationComparisonMode` that should be used for this `CedarTestImplementation`
    fn validation_comparison_mode(&self) -> ValidationComparisonMode {
        ValidationComparisonMode::AgreeOnValid
    }
}
