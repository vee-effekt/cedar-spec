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
        // Each policy is compiled to WASM and executed individually.
        // The WASM evaluate() returns: 1 = satisfied, 0 = not satisfied, 2 = error.
        // The engine uses the policy's effect (permit/forbid) to determine the
        // overall authorization decision per Cedar semantics:
        //   - If any satisfied forbid → Deny (forbid overrides permit)
        //   - Else if any satisfied permit → Allow
        //   - Else → Deny (default deny)

        let mut compile_time_total = 0u128;
        let mut eval_time_total = 0u128;
        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

        // Compile and execute each policy
        for policy in policies.policies() {
            let policy_id = policy.id();
            let policy_text = policy.to_string();
            let is_forbid = policy.effect() == Effect::Forbid;

            // Compile the policy
            let wasm_bytes = match self.compile_policy_timed(&policy_text) {
                Ok((bytes, compile_time)) => {
                    compile_time_total += compile_time;
                    bytes
                }
                Err(err) => {
                    // Compilation failure is a bug in the compiler, not an authorization error
                    return TestResult::Failure(format!(
                        "Failed to compile policy {}: {}",
                        policy_id, err
                    ));
                }
            };

            // Execute the WASM
            match self.execute_wasm(&wasm_bytes) {
                Ok((decision_value, exec_time)) => {
                    eval_time_total += exec_time;

                    // WASM return values:
                    // 1 = policy is satisfied (scope + conditions match)
                    // 0 = policy is not satisfied
                    // 2 = error during evaluation
                    match decision_value {
                        1 => {
                            // Policy is satisfied — file under permit or forbid
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
                            // Error during evaluation
                            errors.push(ffi::AuthorizationError::new_from_report(
                                policy_id.clone(),
                                miette!("Policy evaluation returned error"),
                            ));
                        }
                        _ => {
                            // Unknown decision value is a compiler bug
                            return TestResult::Failure(format!(
                                "Policy {} returned unknown decision value: {}",
                                policy_id, decision_value
                            ));
                        }
                    }
                }
                Err(err) => {
                    // Execution failure (e.g., WASM validation error) is a compiler bug
                    return TestResult::Failure(format!(
                        "Failed to execute WASM for policy {}: {}",
                        policy_id, err
                    ));
                }
            }
        }

        let total_time = compile_time_total + eval_time_total;

        // Cedar authorization semantics: forbid overrides permit
        let (decision, determining_policies) = if !satisfied_forbids.is_empty() {
            (cedar_policy::Decision::Deny, satisfied_forbids)
        } else if !satisfied_permits.is_empty() {
            (cedar_policy::Decision::Allow, satisfied_permits)
        } else {
            (cedar_policy::Decision::Deny, vec![])
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
