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
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

pub struct CedarCompilerEngine {
    compiler: Compiler,
    schema: RefCell<Option<Schema>>,
}

impl CedarCompilerEngine {
    pub fn new() -> Self {
        Self {
            compiler: Compiler::new(),
            schema: RefCell::new(None),
        }
    }

    pub fn set_schema(&self, schema: &Schema) {
        *self.schema.borrow_mut() = Some(schema.clone());
    }
}

impl CedarTestImplementation for CedarCompilerEngine {
    fn is_authorized(
        &self,
        request: &Request,
        policies: &PolicySet,
        entities: &Entities,
    ) -> TestResult<TestResponse> {
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

        let mut satisfied_permits = vec![];
        let mut satisfied_forbids = vec![];
        let mut errors = vec![];

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
