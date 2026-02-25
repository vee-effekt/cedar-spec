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
use cedar_policy_core::ast;
use cedar_policy_core::entities::Entities as CoreEntities;

use cedar_testing::cedar_test_impl::{
    CedarTestImplementation, ErrorComparisonMode, Micros, TestResponse, TestResult,
    TestValidationResult, ValidationComparisonMode,
};

use cedar_policy_compiler::helpers::RuntimeCtx;
use cedar_policy_compiler::layout::CompiledEntityStore;
use cedar_policy_compiler::Compiler;
use miette::miette;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Function signature for compiled native policy code.
/// Returns: 1 = satisfied, 0 = not satisfied, 2 = error.
type EvaluateFn = unsafe extern "C" fn() -> i64;

pub struct CedarCompilerEngine {
    compiler: Compiler,
}

impl CedarCompilerEngine {
    pub fn new() -> Self {
        Self {
            compiler: Compiler::new(),
        }
    }

    /// Compile a policy to native AArch64 machine code and measure timing.
    /// Returns the machine code bytes and compilation time in nanoseconds.
    fn compile_policy_timed(&self, policy_text: &str) -> Result<(Vec<u8>, u128), String> {
        let start = Instant::now();
        let code = self
            .compiler
            .compile_str(policy_text)
            .map_err(|e| e.to_string())?;
        let duration = start.elapsed().as_nanos();
        Ok((code, duration))
    }

    /// Load compiled AArch64 machine code into an executable memory region and call it.
    /// Returns (decision as i64, execution time in ns).
    fn execute_native(&self, code: &[u8]) -> Result<(i64, u128), String> {
        use std::ptr;

        let start = Instant::now();

        // Allocate a page-aligned RW region, copy the code, then mark it RX.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let alloc_size = (code.len() + page_size - 1) & !(page_size - 1);

        let mem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                alloc_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mem == libc::MAP_FAILED {
            return Err("mmap failed".to_string());
        }

        unsafe { ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len()) };

        let rc = unsafe { libc::mprotect(mem, alloc_size, libc::PROT_READ | libc::PROT_EXEC) };
        if rc != 0 {
            unsafe { libc::munmap(mem, alloc_size) };
            return Err("mprotect failed".to_string());
        }

        let f: EvaluateFn = unsafe { std::mem::transmute(mem) };
        let decision = unsafe { f() };

        unsafe { libc::munmap(mem, alloc_size) };

        let duration = start.elapsed().as_nanos();
        Ok((decision, duration))
    }
}

impl CedarTestImplementation for CedarCompilerEngine {
    fn is_authorized(
        &self,
        request: &Request,
        policies: &PolicySet,
        entities: &Entities,
    ) -> TestResult<TestResponse> {
<<<<<<< HEAD
        let start = Instant::now();

        let core_pset: &ast::PolicySet = policies.as_ref();
        let core_policies: Vec<&ast::Policy> = core_pset.policies().collect();

        let schema_ref = self.schema.borrow();
        let compiled = match self.compiler.compile_conditions(&core_policies, schema_ref.as_ref()) {
            Ok(c) => c,
            Err(e) => return TestResult::Failure(format!("Compilation error: {}", e)),
        };

        // Create runtime context with request and entities
        let core_request: &ast::Request = request.as_ref();
        let core_entities: &CoreEntities = entities.as_ref();

        // Build compiled entity store if schema layout is available
        let entity_store = compiled.schema_layout.as_ref().map(|layout| {
            CompiledEntityStore::new(Arc::clone(layout), core_entities)
        });

        let runtime_ctx = if let Some(ref store) = entity_store {
            // Schema-directed: pre-resolve principal/resource pointers
            let principal_data = core_request
                .principal()
                .uid()
                .map(|uid| store.get(uid))
                .unwrap_or(std::ptr::null());
            let resource_data = core_request
                .resource()
                .uid()
                .map(|uid| store.get(uid))
                .unwrap_or(std::ptr::null());
            RuntimeCtx::new_with_flat_data(
                core_request,
                core_entities,
                principal_data,
                resource_data,
                compiled.patterns.clone(),
                compiled.interned_strings.clone(),
                compiled.string_pool.clone(),
            )
        } else {
            RuntimeCtx::new(
                core_request,
                core_entities,
                compiled.patterns.clone(),
                compiled.interned_strings.clone(),
                compiled.string_pool.clone(),
            )
        };
        let ctx_ptr = &runtime_ctx as *const RuntimeCtx;
=======
        // Each policy is compiled to native AArch64 and executed individually.
        // The evaluate function returns: 1 = satisfied, 0 = not satisfied, 2 = error.
        // The engine applies Cedar authorization semantics on top:
        //   - If any satisfied forbid → Deny (forbid overrides permit)
        //   - Else if any satisfied permit → Allow
        //   - Else → Deny (default deny)
>>>>>>> e5882dd (fresh)

        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

<<<<<<< HEAD
        for (i, (policy, _core_policy)) in policies.policies().zip(core_pset.policies()).enumerate() {
            let decision = compiled.call(i, ctx_ptr);

            if std::env::var("COMPILER_DEBUG").is_ok() {
                eprintln!("  evaluate_{} returned: {}", i, decision);
            }

            match decision {
                1 => {
                    if policy.effect() == Effect::Forbid {
                        satisfied_forbids.push(policy.id().clone());
                    } else {
                        satisfied_permits.push(policy.id().clone());
                    }
                }
                0 => { /* not satisfied */ }
                2 => {
                    errors.push(ffi::AuthorizationError::new_from_report(
                        policy.id().clone(),
                        miette!("{}", policy.id()),
                    ));
                }
                n => {
                    return TestResult::Failure(format!(
                        "Policy {} returned unknown decision value: {}",
                        policy.id(), n
=======
        for policy in policies.policies() {
            let policy_id = policy.id();
            let policy_text = policy.to_string();
            let is_forbid = policy.effect() == Effect::Forbid;

            let code = match self.compile_policy_timed(&policy_text) {
                Ok((bytes, compile_time)) => {
                    compile_time_total += compile_time;
                    bytes
                }
                Err(err) => {
                    return TestResult::Failure(format!(
                        "Failed to compile policy {}: {}",
                        policy_id, err
                    ));
                }
            };

            match self.execute_native(&code) {
                Ok((decision_value, exec_time)) => {
                    eval_time_total += exec_time;

                    match decision_value {
                        1 => {
                            if is_forbid {
                                satisfied_forbids.push(policy_id.clone());
                            } else {
                                satisfied_permits.push(policy_id.clone());
                            }
                        }
                        0 => {}
                        2 => {
                            errors.push(ffi::AuthorizationError::new_from_report(
                                policy_id.clone(),
                                miette!("Policy evaluation returned error"),
                            ));
                        }
                        _ => {
                            return TestResult::Failure(format!(
                                "Policy {} returned unknown decision value: {}",
                                policy_id, decision_value
                            ));
                        }
                    }
                }
                Err(err) => {
                    return TestResult::Failure(format!(
                        "Failed to execute native code for policy {}: {}",
                        policy_id, err
>>>>>>> e5882dd (fresh)
                    ));
                }
            }
        }

        let duration = start.elapsed().as_nanos();

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
                ("evaluate".into(), Micros(duration / 1000)),
                ("authorize".into(), Micros(duration / 1000)),
            ]),
        })
    }

    fn interpret(
        &self,
        request: &Request,
        entities: &Entities,
        expr: &Expression,
        expected: Option<EvalResult>,
    ) -> TestResult<bool> {
        let result = cedar_policy::eval_expression(request, entities, expr).ok();
        TestResult::Success(result == expected)
    }

    fn validate(
        &self,
        schema: &Schema,
        policies: &PolicySet,
        mode: ValidationMode,
    ) -> TestResult<TestValidationResult> {
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

    fn validate_with_level(
        &self,
        schema: &Schema,
        policies: &PolicySet,
        mode: ValidationMode,
        level: i32,
    ) -> TestResult<TestValidationResult> {
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

    fn error_comparison_mode(&self) -> ErrorComparisonMode {
        ErrorComparisonMode::PolicyIds
    }

    fn validation_comparison_mode(&self) -> ValidationComparisonMode {
        ValidationComparisonMode::AgreeOnValid
    }
}
