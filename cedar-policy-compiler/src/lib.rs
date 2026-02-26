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
        let condition = policies[0].condition();
        let compiler = ExprCompiler::new();
        let compiled = compiler.compile_condition(&condition);
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
            let condition = policy.condition();
            let compiler = ExprCompiler::new();
            let compiled = compiler.compile_condition(&condition);

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
                _entity_literals: compiled._entity_literals,
                _string_literals: compiled._string_literals,
                _entity_type_literals: compiled._entity_type_literals,
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
