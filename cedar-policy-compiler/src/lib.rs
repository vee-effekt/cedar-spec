pub mod asm;
pub mod codegen;
pub mod helpers;
pub mod layout;
pub mod mem;
pub mod runtime;

use cedar_policy_core::ast::{self, Pattern};
use codegen::ExprCompiler;
use helpers::RuntimeCtx;
use layout::SchemaLayout;
use mem::ExecutableMemory;
use smol_str::SmolStr;
use std::fmt;
use std::sync::Arc;

/// Compiled function signature: extern "C" fn(ctx: *const RuntimeCtx) -> i64
/// Returns: 1=satisfied, 0=not-satisfied, 2=error
type CompiledFn = unsafe extern "C" fn(*const RuntimeCtx) -> i64;

#[derive(Debug)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompileError: {}", self.0)
    }
}

impl std::error::Error for CompileError {}

pub struct Compiler;

impl Compiler {
    pub fn new() -> Self {
        Self
    }

    /// Compile a single policy from its text representation.
    pub fn compile_str(&self, policy_text: &str) -> Result<Vec<u8>, CompileError> {
        let policy_set = cedar_policy_core::parser::parse_policyset(policy_text)
            .map_err(|e| CompileError(format!("Parse error: {}", e)))?;
        let policies: Vec<&ast::Policy> = policy_set.policies().collect();
        if policies.is_empty() {
            return Err(CompileError("No policies found".into()));
        }
        let condition = Box::new(policies[0].condition());
        let compiler = ExprCompiler::new();
        let compiled = compiler.compile_condition(condition);
        Ok(compiled.code)
    }

    /// Compile conditions for a batch of policies.
    /// Returns a CompiledConditions object that can evaluate each policy.
    pub fn compile_conditions(
        &self,
        policies: &[&ast::Policy],
        _schema: Option<&cedar_policy::Schema>,
    ) -> Result<CompiledConditions, CompileError> {
        let mut entries = Vec::with_capacity(policies.len());
        let mut all_patterns = Vec::new();
        let mut all_interned_strings = Vec::new();
        let mut all_string_pool = Vec::new();

        for policy in policies {
            let condition = Box::new(policy.condition());
            let compiler = ExprCompiler::new();
            let compiled = compiler.compile_condition(condition);

            let exec_mem = ExecutableMemory::new(&compiled.code)
                .map_err(|e| CompileError(format!("Failed to map executable memory: {}", e)))?;

            // Collect patterns/strings from this compilation
            all_patterns.extend(compiled.patterns);
            all_interned_strings.extend(compiled.interned_strings);
            all_string_pool.extend(compiled.string_pool);

            let func_ptr = exec_mem.as_ptr();

            entries.push(CompiledEntry {
                _exec_mem: exec_mem,
                func_ptr,
                // Keep the pinned data alive
                _entity_literals: compiled._entity_literals,
                _string_literals: compiled._string_literals,
                _entity_type_literals: compiled._entity_type_literals,
                _condition: compiled._condition,
            });
        }

        Ok(CompiledConditions {
            entries,
            pub_patterns: Arc::new(all_patterns),
            pub_interned_strings: Arc::new(all_interned_strings),
            pub_string_pool: Arc::new(all_string_pool),
            schema_layout: None,
        })
    }
}

struct CompiledEntry {
    _exec_mem: ExecutableMemory,
    func_ptr: *const u8,
    // Pinned data whose addresses are embedded in the machine code
    _entity_literals: Vec<Box<ast::EntityUID>>,
    _string_literals: Vec<Box<SmolStr>>,
    _entity_type_literals: Vec<Box<ast::EntityType>>,
    // The original condition expression — machine code may embed pointers to sub-expressions
    _condition: Box<ast::Expr>,
}

// Safety: function pointers to executable memory are safe to share.
// The pinned data is immutable after construction.
unsafe impl Send for CompiledEntry {}
unsafe impl Sync for CompiledEntry {}

pub struct CompiledConditions {
    entries: Vec<CompiledEntry>,
    pub_patterns: Arc<Vec<Pattern>>,
    pub_interned_strings: Arc<Vec<String>>,
    pub_string_pool: Arc<Vec<SmolStr>>,
    pub schema_layout: Option<Arc<SchemaLayout>>,
}

impl CompiledConditions {
    pub fn patterns(&self) -> &Arc<Vec<Pattern>> {
        &self.pub_patterns
    }

    pub fn interned_strings(&self) -> &Arc<Vec<String>> {
        &self.pub_interned_strings
    }

    pub fn string_pool(&self) -> &Arc<Vec<SmolStr>> {
        &self.pub_string_pool
    }

    /// Call the compiled condition for policy at `index`.
    /// Returns: 1=satisfied, 0=not-satisfied, 2=error
    pub fn call(&self, index: usize, ctx: *const RuntimeCtx) -> i64 {
        let entry = &self.entries[index];
        let f: CompiledFn = unsafe { std::mem::transmute(entry.func_ptr) };
        unsafe { f(ctx) }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_permit_all() {
        let compiler = Compiler::new();
        let result = compiler.compile_str("permit(principal, action, resource);");
        assert!(result.is_ok());
        let code = result.unwrap();
        assert!(!code.is_empty());
    }

    #[test]
    fn test_compile_forbid_all() {
        let compiler = Compiler::new();
        let result = compiler.compile_str("forbid(principal, action, resource);");
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_permit_all() {
        use cedar_policy_core::ast as core_ast;
        use cedar_policy_core::entities::Entities;

        let compiler = Compiler::new();
        let pset = cedar_policy_core::parser::parse_policyset(
            "permit(principal, action, resource);"
        ).unwrap();
        let policies: Vec<&core_ast::Policy> = pset.policies().collect();
        let compiled = compiler.compile_conditions(&policies, None).unwrap();

        // Create a minimal request and entities
        let request = core_ast::Request::new_unchecked(
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("User", "alice").unwrap(),
                None,
            ),
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("Action", "view").unwrap(),
                None,
            ),
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("Resource", "doc1").unwrap(),
                None,
            ),
            Some(core_ast::Context::empty()),
        );
        let entities = Entities::new();

        let ctx = RuntimeCtx::new(
            &request,
            &entities,
            compiled.patterns().clone(),
            compiled.interned_strings().clone(),
            compiled.string_pool().clone(),
        );
        let ctx_ptr = &ctx as *const RuntimeCtx;

        // permit(principal, action, resource) should always be satisfied (condition is `true`)
        let result = compiled.call(0, ctx_ptr);
        assert_eq!(result, 1, "permit(principal, action, resource) should return 1 (satisfied)");
    }

    #[test]
    fn test_execute_when_false() {
        use cedar_policy_core::ast as core_ast;
        use cedar_policy_core::entities::Entities;

        let compiler = Compiler::new();
        let pset = cedar_policy_core::parser::parse_policyset(
            "permit(principal, action, resource) when { false };"
        ).unwrap();
        let policies: Vec<&core_ast::Policy> = pset.policies().collect();
        let compiled = compiler.compile_conditions(&policies, None).unwrap();

        let request = core_ast::Request::new_unchecked(
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("User", "alice").unwrap(),
                None,
            ),
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("Action", "view").unwrap(),
                None,
            ),
            core_ast::EntityUIDEntry::known(
                core_ast::EntityUID::with_eid_and_type("Resource", "doc1").unwrap(),
                None,
            ),
            Some(core_ast::Context::empty()),
        );
        let entities = Entities::new();

        let ctx = RuntimeCtx::new(
            &request,
            &entities,
            compiled.patterns().clone(),
            compiled.interned_strings().clone(),
            compiled.string_pool().clone(),
        );
        let ctx_ptr = &ctx as *const RuntimeCtx;

        // when { false } should make the condition not satisfied
        let result = compiled.call(0, ctx_ptr);
        assert_eq!(result, 0, "permit with when-false should return 0 (not satisfied)");
    }
}
