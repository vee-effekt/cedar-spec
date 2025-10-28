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
    ffi, Entities, EvalResult, Expression, PolicySet, Request, Schema, ValidationMode,
};

use cedar_testing::cedar_test_impl::{
    CedarTestImplementation, ErrorComparisonMode, Micros, TestResponse, TestResult,
    TestValidationResult, ValidationComparisonMode,
};

use cedar_policy_compiler::Compiler;
use miette::miette;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;
use wasmer::{Instance, Module, Store, Value};

pub struct CedarCompilerEngine {
    compiler: Compiler,
    store: RefCell<Store>,
}

impl CedarCompilerEngine {
    pub fn new() -> Self {
        Self {
            compiler: Compiler::new(),
            store: RefCell::new(Store::default()),
        }
    }

    /// Helper to compile a policy and measure timing
    /// Returns the WASM bytes and compilation time in nanoseconds
    fn compile_policy_timed(&self, policy_text: &str) -> Result<(Vec<u8>, u128), String> {
        let start = Instant::now();
        let wasm_bytes = self
            .compiler
            .compile_str(policy_text)
            .map_err(|e| e.to_string())?;
        let duration = start.elapsed().as_nanos();
        Ok((wasm_bytes, duration))
    }

    /// Execute compiled WASM bytecode and return the decision
    /// Returns (decision as i64, execution time in ns)
    fn execute_wasm(&self, wasm_bytes: &[u8]) -> Result<(i64, u128), String> {
        let start = Instant::now();
        let mut store = self.store.borrow_mut();

        // Compile WASM module
        let module = Module::new(&*store, wasm_bytes)
            .map_err(|e| format!("Failed to compile WASM module: {}", e))?;

        // Instantiate the module
        let instance = Instance::new(&mut *store, &module, &wasmer::imports! {})
            .map_err(|e| format!("Failed to instantiate WASM module: {}", e))?;

        // Get the exported "evaluate" function
        let evaluate = instance
            .exports
            .get_function("evaluate")
            .map_err(|e| format!("Failed to get evaluate function: {}", e))?;

        // Call the function (no arguments for now)
        let result = evaluate
            .call(&mut *store, &[])
            .map_err(|e| format!("Failed to execute WASM function: {}", e))?;

        let duration = start.elapsed().as_nanos();

        // Extract the i64 result (Decision)
        match result.first() {
            Some(Value::I64(decision)) => Ok((*decision, duration)),
            Some(other) => Err(format!("Unexpected return type: {:?}", other)),
            None => Err("No return value from evaluate function".to_string()),
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
        // NOTE: Currently, we compile and execute each policy individually.
        // The WASM module doesn't yet handle request/entity context - it just
        // evaluates the policy logic in isolation.

        let mut compile_time_total = 0u128;
        let mut eval_time_total = 0u128;
        let mut determining_policies = vec![];
        let mut errors = vec![];

        // Compile and execute each policy
        for (policy_id, policy) in policies.policies() {
            let policy_text = policy.to_string();

            // Compile the policy
            let wasm_bytes = match self.compile_policy_timed(&policy_text) {
                Ok((bytes, compile_time)) => {
                    compile_time_total += compile_time;
                    bytes
                }
                Err(err) => {
                    errors.push(ffi::AuthorizationError::new_from_report(
                        policy_id.clone(),
                        miette!("Compilation error: {}", err),
                    ));
                    continue;
                }
            };

            // Execute the WASM
            match self.execute_wasm(&wasm_bytes) {
                Ok((decision_value, exec_time)) => {
                    eval_time_total += exec_time;

                    // Decision values from runtime.rs:
                    // Deny = 0, Permit = 1, Error = 2
                    match decision_value {
                        1 => {
                            // Permit decision
                            determining_policies.push(policy_id.clone());
                        }
                        0 => {
                            // Deny decision - no action needed
                        }
                        2 => {
                            // Error during evaluation
                            errors.push(ffi::AuthorizationError::new_from_report(
                                policy_id.clone(),
                                miette!("Policy evaluation returned error"),
                            ));
                        }
                        _ => {
                            errors.push(ffi::AuthorizationError::new_from_report(
                                policy_id.clone(),
                                miette!("Unknown decision value: {}", decision_value),
                            ));
                        }
                    }
                }
                Err(err) => {
                    errors.push(ffi::AuthorizationError::new_from_report(
                        policy_id.clone(),
                        miette!("Execution error: {}", err),
                    ));
                }
            }
        }

        let total_time = compile_time_total + eval_time_total;

        // Determine overall decision
        let decision = if !determining_policies.is_empty() {
            cedar_policy::Decision::Allow
        } else {
            cedar_policy::Decision::Deny
        };

        TestResult::Success(TestResponse {
            response: ffi::Response::new(
                decision,
                determining_policies.into_iter().collect(),
                errors.into_iter().collect(),
            ),
            timing_info: HashMap::from([
                ("compile".into(), Micros(compile_time_total / 1000)),
                ("evaluate".into(), Micros(eval_time_total / 1000)),
                ("authorize".into(), Micros(total_time / 1000)),
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
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect()
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
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect()
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
