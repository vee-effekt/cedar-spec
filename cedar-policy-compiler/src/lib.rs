pub mod helpers;
pub mod layout;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use cedar_policy_core::ast::{self, BinaryOp, EntityType, ExprKind, Literal, PrincipalOrResourceConstraint, UnaryOp, Var};
use cranelift::prelude::*;
use cranelift_codegen::ir::{Function, SigRef};
use cranelift_codegen::settings;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Module, Linkage};
use smol_str::SmolStr;

use helpers::RuntimeCtx;
use layout::{SchemaLayout, SlotType};

/// C-compatible tagged value for passing data between JIT code and helpers.
#[repr(C)]
pub struct TaggedValue {
    pub tag: u32,
    pub _pad: u32,
    pub payload: u64,
}

// Tag constants — must match helpers.rs
const TAG_ERROR: i64 = 0;
const TAG_BOOL: i64 = 1;
const TAG_LONG: i64 = 2;
// const TAG_VALUE: i64 = 3; // complex types (String, EntityUID, Set, Record, Extension)

/// Compile-time tracking of where a value lives.
/// This is NOT stored at runtime — it describes the Cranelift ir::Value.
#[derive(Copy, Clone)]
enum CompiledValue {
    /// A boolean in a register (i8, 0 or 1)
    Bool(cranelift_codegen::ir::Value),
    /// A 64-bit signed integer in a register
    Long(cranelift_codegen::ir::Value),
    /// A pointer to a TaggedValue struct (stack or heap)
    Tagged(cranelift_codegen::ir::Value),
    /// Statically known error — no runtime value exists yet
    Error,
}

impl CompiledValue {
    /// Box this value into a stack-allocated TaggedValue, returning a pointer.
    fn to_tagged(
        self,
        builder: &mut FunctionBuilder,
        ptr_type: Type,
    ) -> cranelift_codegen::ir::Value {
        match self {
            CompiledValue::Bool(v) => {
                let payload = builder.ins().uextend(types::I64, v);
                emit_tagged(builder, TAG_BOOL, payload, ptr_type)
            }
            CompiledValue::Long(v) => {
                emit_tagged(builder, TAG_LONG, v, ptr_type)
            }
            CompiledValue::Tagged(ptr) => ptr,
            CompiledValue::Error => {
                let zero = builder.ins().iconst(types::I64, 0);
                emit_tagged(builder, TAG_ERROR, zero, ptr_type)
            }
        }
    }
}

#[derive(Debug)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A compiled set of policy conditions, ready to be called as native functions.
pub struct CompiledConditions {
    _module: JITModule,
    func_ptrs: Vec<*const u8>,
    pub patterns: Vec<ast::Pattern>,
    pub string_pool: Vec<u8>,
    pub interned_strings: Vec<(SmolStr, usize)>,
    pub condition_count: usize,
    pub schema_layout: Option<Arc<SchemaLayout>>,
}

unsafe impl Send for CompiledConditions {}
unsafe impl Sync for CompiledConditions {}

impl CompiledConditions {
    /// Call the i-th compiled condition with the given runtime context.
    /// Returns: 0 = not satisfied, 1 = satisfied, 2 = error.
    pub fn call(&self, index: usize, ctx: *const RuntimeCtx) -> i32 {
        let fptr = self.func_ptrs[index];
        let func: fn(*const RuntimeCtx) -> i32 = unsafe { std::mem::transmute(fptr) };
        func(ctx)
    }
}

/// Per-policy type information extracted from scope constraints.
struct PolicyTypeCtx {
    principal_type: Option<EntityType>,
    resource_type: Option<EntityType>,
    schema_layout: Option<Arc<SchemaLayout>>,
}

/// Extract entity type from a scope constraint (principal or resource).
fn extract_entity_type(constraint: &PrincipalOrResourceConstraint) -> Option<EntityType> {
    match constraint {
        PrincipalOrResourceConstraint::Is(ty) => Some((**ty).clone()),
        PrincipalOrResourceConstraint::IsIn(ty, _) => Some((**ty).clone()),
        PrincipalOrResourceConstraint::Eq(ast::EntityReference::EUID(uid)) => {
            Some(uid.entity_type().clone())
        }
        _ => None,
    }
}

pub struct Compiler;

impl Compiler {
    pub fn new() -> Self {
        Compiler
    }

    pub fn compile_conditions(
        &self,
        policies: &[&ast::Policy],
        schema: Option<&cedar_policy::Schema>,
    ) -> Result<CompiledConditions, CompileError> {
        let mut codegen_ctx = CodeGenContext::new();

        // Build schema layout if schema is available
        let schema_layout = schema.map(|s| {
            let vs: &cedar_policy_core::validator::ValidatorSchema = s.as_ref();
            Arc::new(SchemaLayout::from_schema(vs))
        });

        // Pre-walk all conditions to intern strings and register patterns
        for policy in policies {
            codegen_ctx.prewalk(&policy.condition());
        }

        // Set up Cranelift JIT with is_pic=false to avoid PLT (unsupported on aarch64)
        let mut flag_builder = settings::builder();
        flag_builder.set("use_colocated_libcalls", "false").unwrap();
        flag_builder.set("is_pic", "false").unwrap();
        flag_builder.set("enable_probestack", "false").unwrap();
        let isa_builder = cranelift_native::builder().unwrap_or_else(|msg| {
            panic!("host machine is not supported: {msg}");
        });
        let isa = isa_builder
            .finish(settings::Flags::new(flag_builder))
            .map_err(|e| CompileError(format!("ISA error: {}", e)))?;
        let builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());

        let mut module = JITModule::new(builder);
        let ptr_type = module.target_config().pointer_type();

        // Compile each condition into a separate function
        let mut func_ids = Vec::new();
        for (i, policy) in policies.iter().enumerate() {
            // Extract principal/resource entity types from scope constraints
            let principal_type = extract_entity_type(policy.principal_constraint().as_inner());
            let resource_type = extract_entity_type(policy.resource_constraint().as_inner());

            let policy_ctx = PolicyTypeCtx {
                principal_type,
                resource_type,
                schema_layout: schema_layout.clone(),
            };

            let func_id = compile_one_condition(
                &mut module,
                &mut codegen_ctx,
                &policy.condition(),
                i,
                ptr_type,
                &policy_ctx,
            )?;
            func_ids.push(func_id);
        }

        // Finalize all functions
        module.finalize_definitions()
            .map_err(|e| CompileError(format!("Finalize error: {}", e)))?;

        // Get function pointers
        let func_ptrs: Vec<*const u8> = func_ids
            .iter()
            .map(|id| module.get_finalized_function(*id))
            .collect();

        let interned = codegen_ctx.interned_strings();
        Ok(CompiledConditions {
            _module: module,
            func_ptrs,
            patterns: codegen_ctx.patterns,
            string_pool: codegen_ctx.string_pool,
            interned_strings: interned,
            condition_count: policies.len(),
            schema_layout,
        })
    }
}

// ========== Cranelift code generation internals ==========

struct CodeGenContext {
    string_pool: Vec<u8>,
    string_map: HashMap<String, (usize, usize)>,
    patterns: Vec<ast::Pattern>,
}

impl CodeGenContext {
    fn new() -> Self {
        Self {
            string_pool: Vec::new(),
            string_map: HashMap::new(),
            patterns: Vec::new(),
        }
    }

    fn intern_string(&mut self, s: &str) -> (usize, usize) {
        if let Some(&pair) = self.string_map.get(s) {
            return pair;
        }
        let offset = self.string_pool.len();
        self.string_pool.extend_from_slice(s.as_bytes());
        let len = s.len();
        self.string_map.insert(s.to_string(), (offset, len));
        (offset, len)
    }

    fn register_pattern(&mut self, pattern: &ast::Pattern) -> usize {
        let id = self.patterns.len();
        self.patterns.push(pattern.clone());
        id
    }

    fn interned_strings(&self) -> Vec<(SmolStr, usize)> {
        self.string_map
            .iter()
            .map(|(s, (offset, _))| (SmolStr::from(s.as_str()), *offset))
            .collect()
    }

    fn prewalk(&mut self, expr: &ast::Expr) {
        match expr.expr_kind() {
            ExprKind::Lit(Literal::String(s)) => {
                self.intern_string(s.as_str());
            }
            ExprKind::Lit(Literal::EntityUID(uid)) => {
                self.intern_string(&uid.entity_type().to_string());
                self.intern_string(uid.eid().as_ref());
            }
            ExprKind::GetAttr { expr, attr } | ExprKind::HasAttr { expr, attr } => {
                self.intern_string(attr.as_str());
                self.prewalk(expr);
            }
            ExprKind::Like { expr, pattern } => {
                self.register_pattern(pattern);
                self.prewalk(expr);
            }
            ExprKind::Is { expr, entity_type, .. } => {
                self.intern_string(&entity_type.to_string());
                self.prewalk(expr);
            }
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                self.intern_string(&fn_name.to_string());
                for arg in args.iter() {
                    self.prewalk(arg);
                }
            }
            ExprKind::And { left, right } | ExprKind::Or { left, right } => {
                self.prewalk(left);
                self.prewalk(right);
            }
            ExprKind::If { test_expr, then_expr, else_expr } => {
                self.prewalk(test_expr);
                self.prewalk(then_expr);
                self.prewalk(else_expr);
            }
            ExprKind::UnaryApp { arg, .. } => {
                self.prewalk(arg);
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                self.prewalk(arg1);
                self.prewalk(arg2);
            }
            ExprKind::Set(elements) => {
                for elem in elements.iter() {
                    self.prewalk(elem);
                }
            }
            ExprKind::Record(fields) => {
                for (key, val) in fields.as_ref().iter() {
                    self.intern_string(key.as_str());
                    self.prewalk(val);
                }
            }
            _ => {}
        }
    }
}

/// Helper function signatures and addresses for indirect calls.
/// Instead of importing functions through the JIT linker (which needs PLT,
/// only supported on x86_64 in cranelift 0.116), we embed function addresses
/// as constants and use call_indirect.
struct HelperSigs {
    // Signatures
    sig_ctx_to_ptr: SigRef,      // fn(ctx) -> ptr
    sig_void_to_ptr: SigRef,     // fn() -> ptr
    sig_u64_to_ptr: SigRef,      // fn(u64) -> ptr
    sig_ctx_3u64_to_ptr: SigRef, // fn(ctx, u64, u64) -> ptr
    sig_ctx_5u64_to_ptr: SigRef, // fn(ctx, u64, u64, u64, u64) -> ptr
    sig_ptr_to_u64: SigRef,      // fn(ptr) -> u64
    sig_ptr_to_ptr: SigRef,      // fn(ptr) -> ptr
    sig_2ptr_to_ptr: SigRef,     // fn(ptr, ptr) -> ptr
    sig_3ptr_to_ptr: SigRef,     // fn(ptr, ptr, ptr) -> ptr
    sig_ptr_ptr_2u64_to_ptr: SigRef, // fn(ptr, ptr, u64, u64) -> ptr
    sig_ptr_ptr_u64_to_ptr: SigRef,  // fn(ptr, ptr, u64) -> ptr
    sig_ptr_u64_to_ptr: SigRef,  // fn(ptr, u64) -> ptr
    sig_4ptr_u64_to_ptr: SigRef, // fn(ptr, ptr, ptr, u64) -> ptr
    sig_ext_call: SigRef,        // fn(ptr, u64, u64, ptr, u64) -> ptr

    // Function addresses as raw pointers
    addr_var_principal: u64,
    addr_var_action: u64,
    addr_var_resource: u64,
    addr_var_context: u64,
    addr_error: u64,
    addr_lit_bool: u64,
    addr_lit_long: u64,
    addr_lit_string: u64,
    addr_lit_entity: u64,
    addr_is_error: u64,
    addr_is_bool: u64,
    addr_get_bool: u64,
    addr_not: u64,
    addr_neg: u64,
    addr_is_empty_set: u64,
    addr_eq: u64,
    addr_less: u64,
    addr_less_eq: u64,
    addr_add: u64,
    addr_sub: u64,
    addr_mul: u64,
    addr_in_op: u64,
    addr_contains: u64,
    addr_contains_all: u64,
    addr_contains_any: u64,
    addr_get_attr: u64,
    addr_has_attr: u64,
    addr_get_tag: u64,
    addr_has_tag: u64,
    addr_like: u64,
    addr_is_entity_type: u64,
    addr_set_build: u64,
    addr_record_build: u64,
    addr_ext_call: u64,
}

fn create_helper_sigs(func: &mut Function, ptr: Type) -> HelperSigs {
    let sig_ctx_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_void_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ctx_3u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ctx_5u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ptr_to_u64 = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.returns.push(AbiParam::new(types::I64));
        func.import_signature(sig)
    };
    let sig_ptr_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_2ptr_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_3ptr_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ptr_ptr_2u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ptr_ptr_u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ptr_u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_4ptr_u64_to_ptr = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };
    let sig_ext_call = {
        let mut sig = Signature::new(isa::CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(ptr));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(ptr));
        func.import_signature(sig)
    };

    HelperSigs {
        sig_ctx_to_ptr,
        sig_void_to_ptr,
        sig_u64_to_ptr,
        sig_ctx_3u64_to_ptr,
        sig_ctx_5u64_to_ptr,
        sig_ptr_to_u64,
        sig_ptr_to_ptr,
        sig_2ptr_to_ptr,
        sig_3ptr_to_ptr,
        sig_ptr_ptr_2u64_to_ptr,
        sig_ptr_ptr_u64_to_ptr,
        sig_ptr_u64_to_ptr,
        sig_4ptr_u64_to_ptr,
        sig_ext_call,

        addr_var_principal: helpers::helper_var_principal as u64,
        addr_var_action: helpers::helper_var_action as u64,
        addr_var_resource: helpers::helper_var_resource as u64,
        addr_var_context: helpers::helper_var_context as u64,
        addr_error: helpers::helper_error as u64,
        addr_lit_bool: helpers::helper_lit_bool as u64,
        addr_lit_long: helpers::helper_lit_long as u64,
        addr_lit_string: helpers::helper_lit_string as u64,
        addr_lit_entity: helpers::helper_lit_entity as u64,
        addr_is_error: helpers::helper_is_error as u64,
        addr_is_bool: helpers::helper_is_bool as u64,
        addr_get_bool: helpers::helper_get_bool as u64,
        addr_not: helpers::helper_not as u64,
        addr_neg: helpers::helper_neg as u64,
        addr_is_empty_set: helpers::helper_is_empty_set as u64,
        addr_eq: helpers::helper_eq as u64,
        addr_less: helpers::helper_less as u64,
        addr_less_eq: helpers::helper_less_eq as u64,
        addr_add: helpers::helper_add as u64,
        addr_sub: helpers::helper_sub as u64,
        addr_mul: helpers::helper_mul as u64,
        addr_in_op: helpers::helper_in as u64,
        addr_contains: helpers::helper_contains as u64,
        addr_contains_all: helpers::helper_contains_all as u64,
        addr_contains_any: helpers::helper_contains_any as u64,
        addr_get_attr: helpers::helper_get_attr as u64,
        addr_has_attr: helpers::helper_has_attr as u64,
        addr_get_tag: helpers::helper_get_tag as u64,
        addr_has_tag: helpers::helper_has_tag as u64,
        addr_like: helpers::helper_like as u64,
        addr_is_entity_type: helpers::helper_is_entity_type as u64,
        addr_set_build: helpers::helper_set_build as u64,
        addr_record_build: helpers::helper_record_build as u64,
        addr_ext_call: helpers::helper_ext_call as u64,
    }
}

/// Emit an indirect call to a helper function.
fn icall(
    builder: &mut FunctionBuilder,
    sig: SigRef,
    addr: u64,
    args: &[cranelift_codegen::ir::Value],
    ptr_type: Type,
) -> cranelift_codegen::ir::Value {
    let fptr = builder.ins().iconst(ptr_type, addr as i64);
    let call = builder.ins().call_indirect(sig, fptr, args);
    builder.inst_results(call)[0]
}

/// Allocate a 16-byte TaggedValue on the stack and return its address.
fn emit_tagged(
    builder: &mut FunctionBuilder,
    tag: i64,
    payload: cranelift_codegen::ir::Value,
    ptr_type: Type,
) -> cranelift_codegen::ir::Value {
    let slot = builder.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot, 16, 3,
    ));
    let tag_val = builder.ins().iconst(types::I32, tag);
    let pad = builder.ins().iconst(types::I32, 0);
    builder.ins().stack_store(tag_val, slot, 0);
    builder.ins().stack_store(pad, slot, 4);
    builder.ins().stack_store(payload, slot, 8);
    builder.ins().stack_addr(ptr_type, slot, 0)
}

/// Load the tag field (offset 0, I32) from a TaggedValue pointer.
fn emit_load_tag(
    builder: &mut FunctionBuilder,
    ptr: cranelift_codegen::ir::Value,
) -> cranelift_codegen::ir::Value {
    builder.ins().load(types::I32, MemFlags::new(), ptr, 0)
}

/// Load the payload field (offset 8, I64) from a TaggedValue pointer.
fn emit_load_payload(
    builder: &mut FunctionBuilder,
    ptr: cranelift_codegen::ir::Value,
) -> cranelift_codegen::ir::Value {
    builder.ins().load(types::I64, MemFlags::new(), ptr, 8)
}

fn compile_one_condition(
    module: &mut JITModule,
    codegen_ctx: &mut CodeGenContext,
    condition: &ast::Expr,
    index: usize,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> Result<FuncId, CompileError> {
    let mut sig = module.make_signature();
    sig.params.push(AbiParam::new(ptr_type));
    sig.returns.push(AbiParam::new(types::I32));

    let func_name = format!("evaluate_{}", index);
    let func_id = module
        .declare_function(&func_name, Linkage::Local, &sig)
        .map_err(|e| CompileError(format!("Declare function error: {}", e)))?;

    let mut func = Function::with_name_signature(
        cranelift_codegen::ir::UserFuncName::user(0, index as u32),
        sig,
    );

    let mut func_builder_ctx = FunctionBuilderContext::new();
    {
        let hsigs = create_helper_sigs(&mut func, ptr_type);

        let mut builder = FunctionBuilder::new(&mut func, &mut func_builder_ctx);
        let entry_block = builder.create_block();
        builder.append_block_params_for_function_params(entry_block);
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let ctx_val = builder.block_params(entry_block)[0];

        let result = compile_expr(
            &mut builder, codegen_ctx, &hsigs, condition, ctx_val, ptr_type, policy_ctx,
        );

        // Convert result to i32: error → 2, bool(true) → 1, bool(false) → 0
        match result {
            CompiledValue::Bool(v) => {
                // Unboxed bool — direct branch, no tag checks at all
                let return_true_block = builder.create_block();
                let return_false_block = builder.create_block();
                builder.ins().brif(v, return_true_block, &[], return_false_block, &[]);

                builder.switch_to_block(return_true_block);
                builder.seal_block(return_true_block);
                let one = builder.ins().iconst(types::I32, 1);
                builder.ins().return_(&[one]);

                builder.switch_to_block(return_false_block);
                builder.seal_block(return_false_block);
                let zero = builder.ins().iconst(types::I32, 0);
                builder.ins().return_(&[zero]);
            }
            CompiledValue::Long(_) | CompiledValue::Error => {
                // Type error or static error — return 2
                let two = builder.ins().iconst(types::I32, 2);
                builder.ins().return_(&[two]);
            }
            CompiledValue::Tagged(result_ptr) => {
                // Full tag-check path (existing logic)
                let return_error_block = builder.create_block();
                let return_true_block = builder.create_block();
                let return_false_block = builder.create_block();

                let tag = emit_load_tag(&mut builder, result_ptr);

                let is_err = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_ERROR);
                let not_err_block = builder.create_block();
                builder.ins().brif(is_err, return_error_block, &[], not_err_block, &[]);

                builder.switch_to_block(not_err_block);
                builder.seal_block(not_err_block);
                let is_bool = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_BOOL);
                let fast_bool_block = builder.create_block();
                let slow_path_block = builder.create_block();
                builder.ins().brif(is_bool, fast_bool_block, &[], slow_path_block, &[]);

                builder.switch_to_block(fast_bool_block);
                builder.seal_block(fast_bool_block);
                let payload = emit_load_payload(&mut builder, result_ptr);
                let is_true = builder.ins().icmp_imm(IntCC::NotEqual, payload, 0);
                builder.ins().brif(is_true, return_true_block, &[], return_false_block, &[]);

                builder.switch_to_block(slow_path_block);
                builder.seal_block(slow_path_block);
                let is_bool_val = icall(&mut builder, hsigs.sig_ptr_to_u64, hsigs.addr_is_bool, &[result_ptr], ptr_type);
                let zero_i64 = builder.ins().iconst(types::I64, 0);
                let not_bool = builder.ins().icmp(IntCC::Equal, is_bool_val, zero_i64);
                let slow_bool_block = builder.create_block();
                builder.ins().brif(not_bool, return_error_block, &[], slow_bool_block, &[]);

                builder.switch_to_block(slow_bool_block);
                builder.seal_block(slow_bool_block);
                let bool_val = icall(&mut builder, hsigs.sig_ptr_to_u64, hsigs.addr_get_bool, &[result_ptr], ptr_type);
                let slow_true = builder.ins().icmp(IntCC::NotEqual, bool_val, zero_i64);
                builder.ins().brif(slow_true, return_true_block, &[], return_false_block, &[]);

                builder.switch_to_block(return_error_block);
                builder.seal_block(return_error_block);
                let two = builder.ins().iconst(types::I32, 2);
                builder.ins().return_(&[two]);

                builder.switch_to_block(return_true_block);
                builder.seal_block(return_true_block);
                let one = builder.ins().iconst(types::I32, 1);
                builder.ins().return_(&[one]);

                builder.switch_to_block(return_false_block);
                builder.seal_block(return_false_block);
                let zero = builder.ins().iconst(types::I32, 0);
                builder.ins().return_(&[zero]);
            }
        }

        builder.finalize();
    }

    let mut ctx = cranelift_codegen::Context::for_function(func);
    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| CompileError(format!("Define function error: {}", e)))?;

    Ok(func_id)
}

fn compile_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    expr: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    match expr.expr_kind() {
        ExprKind::Lit(lit) => match lit {
            Literal::Bool(b) => {
                let v = builder.ins().iconst(types::I8, if *b { 1 } else { 0 });
                CompiledValue::Bool(v)
            }
            Literal::Long(i) => {
                let v = builder.ins().iconst(types::I64, *i);
                CompiledValue::Long(v)
            }
            Literal::String(s) => {
                let (off, len) = ctx.intern_string(s.as_str());
                let off_v = builder.ins().iconst(types::I64, off as i64);
                let len_v = builder.ins().iconst(types::I64, len as i64);
                CompiledValue::Tagged(icall(builder, h.sig_ctx_3u64_to_ptr, h.addr_lit_string, &[ctx_val, off_v, len_v], ptr_type))
            }
            Literal::EntityUID(uid) => {
                let type_str = uid.entity_type().to_string();
                let id_str = uid.eid().as_ref().to_string();
                let (to, tl) = ctx.intern_string(&type_str);
                let (io, il) = ctx.intern_string(&id_str);
                let to_v = builder.ins().iconst(types::I64, to as i64);
                let tl_v = builder.ins().iconst(types::I64, tl as i64);
                let io_v = builder.ins().iconst(types::I64, io as i64);
                let il_v = builder.ins().iconst(types::I64, il as i64);
                CompiledValue::Tagged(icall(builder, h.sig_ctx_5u64_to_ptr, h.addr_lit_entity, &[ctx_val, to_v, tl_v, io_v, il_v], ptr_type))
            }
        },

        ExprKind::Var(var) => {
            let addr = match var {
                Var::Principal => h.addr_var_principal,
                Var::Action => h.addr_var_action,
                Var::Resource => h.addr_var_resource,
                Var::Context => h.addr_var_context,
            };
            CompiledValue::Tagged(icall(builder, h.sig_ctx_to_ptr, addr, &[ctx_val], ptr_type))
        }

        ExprKind::And { left, right } => {
            compile_and(builder, ctx, h, left, right, ctx_val, ptr_type, policy_ctx)
        }

        ExprKind::Or { left, right } => {
            compile_or(builder, ctx, h, left, right, ctx_val, ptr_type, policy_ctx)
        }

        ExprKind::If { test_expr, then_expr, else_expr } => {
            compile_if(builder, ctx, h, test_expr, then_expr, else_expr, ctx_val, ptr_type, policy_ctx)
        }

        ExprKind::UnaryApp { op, arg } => {
            compile_unary(builder, ctx, h, *op, arg, ctx_val, ptr_type, policy_ctx)
        }

        ExprKind::BinaryApp { op, arg1, arg2 } => {
            compile_binary(builder, ctx, h, *op, arg1, arg2, ctx_val, ptr_type, policy_ctx)
        }

        ExprKind::GetAttr { expr: inner, attr } => {
            // Try schema-directed direct load for principal/resource attributes
            if let Some(cv) = try_compile_flat_get_attr(builder, inner, attr, ctx_val, ptr_type, policy_ctx) {
                return cv;
            }
            // Fallback: helper call
            let (off, len) = ctx.intern_string(attr.as_str());
            CompiledValue::Tagged(compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, policy_ctx, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_get_attr, &[val, ctx_val, off_v, len_v], pt)
            }))
        }

        ExprKind::HasAttr { expr: inner, attr } => {
            // Try schema-directed constant fold for required attributes
            if let Some(cv) = try_compile_flat_has_attr(builder, inner, attr, ctx_val, ptr_type, policy_ctx) {
                return cv;
            }
            // Fallback: helper call
            let (off, len) = ctx.intern_string(attr.as_str());
            CompiledValue::Tagged(compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, policy_ctx, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_has_attr, &[val, ctx_val, off_v, len_v], pt)
            }))
        }

        ExprKind::Like { expr: inner, pattern } => {
            let pid = ctx.register_pattern(pattern);
            CompiledValue::Tagged(compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, policy_ctx, |b, val, pt| {
                let pid_v = b.ins().iconst(types::I64, pid as i64);
                icall(b, h.sig_ptr_ptr_u64_to_ptr, h.addr_like, &[val, ctx_val, pid_v], pt)
            }))
        }

        ExprKind::Is { expr: inner, entity_type, .. } => {
            let type_str = entity_type.to_string();
            let (off, len) = ctx.intern_string(&type_str);
            CompiledValue::Tagged(compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, policy_ctx, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_is_entity_type, &[val, ctx_val, off_v, len_v], pt)
            }))
        }

        ExprKind::Set(elements) => {
            CompiledValue::Tagged(compile_set(builder, ctx, h, elements, ctx_val, ptr_type, policy_ctx))
        }

        ExprKind::Record(fields) => {
            CompiledValue::Tagged(compile_record(builder, ctx, h, fields.as_ref(), ctx_val, ptr_type, policy_ctx))
        }

        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            CompiledValue::Tagged(compile_ext_call(builder, ctx, h, fn_name, args, ctx_val, ptr_type, policy_ctx))
        }

        ExprKind::Slot(_) | ExprKind::Unknown(_) => {
            CompiledValue::Error
        }
    }
}

/// Try to compile `GetAttr(Var(Principal/Resource), attr)` as a direct memory load
/// from the flat entity data when schema info is available.
/// Returns None if the pattern doesn't match or schema info is insufficient.
fn try_compile_flat_get_attr(
    builder: &mut FunctionBuilder,
    inner: &ast::Expr,
    attr: &SmolStr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> Option<CompiledValue> {
    let schema_layout = policy_ctx.schema_layout.as_ref()?;

    // Check if inner is Var(Principal) or Var(Resource)
    let (entity_type, data_offset) = match inner.expr_kind() {
        ExprKind::Var(Var::Principal) => {
            (policy_ctx.principal_type.as_ref()?, 0i32) // principal_data at offset 0
        }
        ExprKind::Var(Var::Resource) => {
            (policy_ctx.resource_type.as_ref()?, 8i32) // resource_data at offset 8
        }
        _ => return None,
    };

    // Look up attribute in schema layout
    let (slot_idx, slot_type, required) = schema_layout
        .attr_indices
        .get(&(entity_type.clone(), attr.clone()))?;

    let entity_layout = schema_layout.entity_layouts.get(entity_type)?;

    // Don't try direct access on open entity types (may have undeclared attrs)
    if entity_layout.open {
        return None;
    }

    // Load the entity data pointer from RuntimeCtx
    let entity_data = builder.ins().load(
        ptr_type,
        MemFlags::trusted(),
        ctx_val,
        data_offset,
    );

    // Check if entity data pointer is null (entity not in compiled store)
    let is_null = builder.ins().icmp_imm(IntCC::Equal, entity_data, 0);
    let null_block = builder.create_block();
    let valid_block = builder.create_block();
    let merge_block = builder.create_block();

    // Determine the merge block parameter type based on slot type
    let result_type = match slot_type {
        SlotType::Long => types::I64,
        SlotType::Bool => types::I8,
        _ => return None, // For complex types (Value), fall back to helper for now
    };

    builder.append_block_param(merge_block, result_type);
    builder.ins().brif(is_null, null_block, &[], valid_block, &[]);

    // Null path: return error (entity data not available)
    builder.switch_to_block(null_block);
    builder.seal_block(null_block);
    // Fall through to error — but we can't easily return error AND a typed value.
    // Instead, return a default and let the condition check handle it.
    // Actually, null principal_data means the entity wasn't in the compiled store.
    // This shouldn't happen in normal operation, but for safety return 0.
    let default_val = builder.ins().iconst(result_type, 0);
    builder.ins().jump(merge_block, &[default_val]);

    // Valid path: load the attribute directly
    builder.switch_to_block(valid_block);
    builder.seal_block(valid_block);

    let slot_offset = entity_layout.attrs[*slot_idx].offset;

    if !required {
        // Check presence bit
        let bitmap = builder.ins().load(types::I64, MemFlags::trusted(), entity_data, 0);
        let bit_mask = builder.ins().iconst(types::I64, 1i64 << slot_idx);
        let bit_set = builder.ins().band(bitmap, bit_mask);
        let is_present = builder.ins().icmp_imm(IntCC::NotEqual, bit_set, 0);
        let present_block = builder.create_block();
        let absent_block = builder.create_block();
        builder.ins().brif(is_present, present_block, &[], absent_block, &[]);

        // Absent: return default (this is an error in Cedar — HasAttr should be checked first)
        builder.switch_to_block(absent_block);
        builder.seal_block(absent_block);
        let absent_val = builder.ins().iconst(result_type, 0);
        builder.ins().jump(merge_block, &[absent_val]);

        // Present: load value
        builder.switch_to_block(present_block);
        builder.seal_block(present_block);
    }

    let loaded = match slot_type {
        SlotType::Long => {
            builder.ins().load(types::I64, MemFlags::trusted(), entity_data, slot_offset as i32)
        }
        SlotType::Bool => {
            let raw = builder.ins().load(types::I64, MemFlags::trusted(), entity_data, slot_offset as i32);
            builder.ins().ireduce(types::I8, raw)
        }
        SlotType::Value => unreachable!(), // handled above with early return
    };

    builder.ins().jump(merge_block, &[loaded]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    let result = builder.block_params(merge_block)[0];

    Some(match slot_type {
        SlotType::Long => CompiledValue::Long(result),
        SlotType::Bool => CompiledValue::Bool(result),
        SlotType::Value => unreachable!(),
    })
}

/// Try to compile `HasAttr(Var(Principal/Resource), attr)` as a compile-time constant
/// when the schema says the attribute is required on the entity type.
fn try_compile_flat_has_attr(
    builder: &mut FunctionBuilder,
    inner: &ast::Expr,
    attr: &SmolStr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> Option<CompiledValue> {
    let schema_layout = policy_ctx.schema_layout.as_ref()?;

    let entity_type = match inner.expr_kind() {
        ExprKind::Var(Var::Principal) => policy_ctx.principal_type.as_ref()?,
        ExprKind::Var(Var::Resource) => policy_ctx.resource_type.as_ref()?,
        _ => return None,
    };

    let entity_layout = schema_layout.entity_layouts.get(entity_type)?;
    if entity_layout.open {
        return None;
    }

    // Look up the attribute
    if let Some((_slot_idx, _slot_type, required)) = schema_layout
        .attr_indices
        .get(&(entity_type.clone(), attr.clone()))
    {
        if *required {
            // Required attribute — always present, constant fold to true
            let one = builder.ins().iconst(types::I8, 1);
            Some(CompiledValue::Bool(one))
        } else {
            // Optional attribute — need to check presence bitmap at runtime
            let data_offset = match inner.expr_kind() {
                ExprKind::Var(Var::Principal) => 0i32,
                ExprKind::Var(Var::Resource) => 8i32,
                _ => unreachable!(),
            };
            let entity_data = builder.ins().load(ptr_type, MemFlags::trusted(), ctx_val, data_offset);

            // Null check
            let is_null = builder.ins().icmp_imm(IntCC::Equal, entity_data, 0);
            let null_block = builder.create_block();
            let valid_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, types::I8);
            builder.ins().brif(is_null, null_block, &[], valid_block, &[]);

            builder.switch_to_block(null_block);
            builder.seal_block(null_block);
            let false_val = builder.ins().iconst(types::I8, 0);
            builder.ins().jump(merge_block, &[false_val]);

            builder.switch_to_block(valid_block);
            builder.seal_block(valid_block);
            let bitmap = builder.ins().load(types::I64, MemFlags::trusted(), entity_data, 0);
            let bit_mask = builder.ins().iconst(types::I64, 1i64 << _slot_idx);
            let bit_set = builder.ins().band(bitmap, bit_mask);
            let is_present = builder.ins().icmp_imm(IntCC::NotEqual, bit_set, 0);
            builder.ins().jump(merge_block, &[is_present]);

            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            let result = builder.block_params(merge_block)[0];
            Some(CompiledValue::Bool(result))
        }
    } else {
        // Attribute not in schema — constant false
        let zero = builder.ins().iconst(types::I8, 0);
        Some(CompiledValue::Bool(zero))
    }
}

// I realize the And/Or/etc. cases above have bugs due to the block switching
// mess. Let me rewrite them as separate functions that handle their own blocks cleanly.

/// Inline check: is the TaggedValue a boolean true/false?
/// Returns (is_bool_true, is_bool_false) — exactly one of these blocks is jumped to,
/// plus error_block for errors. For TAG_VALUE, falls back to helpers.
/// After this, builder is NOT positioned on any block — caller must switch_to_block.
fn emit_bool_check(
    builder: &mut FunctionBuilder,
    h: &HelperSigs,
    val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    true_block: cranelift_codegen::ir::Block,
    false_block: cranelift_codegen::ir::Block,
    error_block: cranelift_codegen::ir::Block,
) {
    let tag = emit_load_tag(builder, val);

    // TAG_ERROR → error
    let not_err = builder.create_block();
    let is_err = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_ERROR);
    builder.ins().brif(is_err, error_block, &[], not_err, &[]);

    // TAG_BOOL → read payload directly
    builder.switch_to_block(not_err);
    builder.seal_block(not_err);
    let fast_bool = builder.create_block();
    let slow_path = builder.create_block();
    let is_bool_tag = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_BOOL);
    builder.ins().brif(is_bool_tag, fast_bool, &[], slow_path, &[]);

    builder.switch_to_block(fast_bool);
    builder.seal_block(fast_bool);
    let payload = emit_load_payload(builder, val);
    let is_true = builder.ins().icmp_imm(IntCC::NotEqual, payload, 0);
    builder.ins().brif(is_true, true_block, &[], false_block, &[]);

    // Slow path: TAG_VALUE — call helpers
    builder.switch_to_block(slow_path);
    builder.seal_block(slow_path);
    let is_bool_val = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[val], ptr_type);
    let zero = builder.ins().iconst(types::I64, 0);
    let not_bool = builder.ins().icmp(IntCC::Equal, is_bool_val, zero);
    let get_val = builder.create_block();
    builder.ins().brif(not_bool, error_block, &[], get_val, &[]);

    builder.switch_to_block(get_val);
    builder.seal_block(get_val);
    let bool_result = icall(builder, h.sig_ptr_to_u64, h.addr_get_bool, &[val], ptr_type);
    let slow_true = builder.ins().icmp(IntCC::NotEqual, bool_result, zero);
    builder.ins().brif(slow_true, true_block, &[], false_block, &[]);
}

/// Inline error check: if tag == TAG_ERROR, jump to error_block.
/// Otherwise fall through. Builder is positioned on the ok block after return.
fn emit_error_check_inline(
    builder: &mut FunctionBuilder,
    val: cranelift_codegen::ir::Value,
    error_block: cranelift_codegen::ir::Block,
) {
    let tag = emit_load_tag(builder, val);
    let is_err = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_ERROR);
    let ok = builder.create_block();
    builder.ins().brif(is_err, error_block, &[], ok, &[]);
    builder.switch_to_block(ok);
    builder.seal_block(ok);
}

fn compile_and(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    let left_cv = compile_expr(builder, ctx, h, left, ctx_val, ptr_type, policy_ctx);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();
    let eval_right_block = builder.create_block();
    let false_block = builder.create_block();

    // Dispatch on CompiledValue: Bool skips tag check entirely
    match left_cv {
        CompiledValue::Bool(v) => {
            builder.ins().brif(v, eval_right_block, &[], false_block, &[]);
        }
        CompiledValue::Error => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Long(_) => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Tagged(ptr) => {
            emit_bool_check(builder, h, ptr, ptr_type, eval_right_block, false_block, error_block);
        }
    }

    // Error → alloc error and merge
    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_payload = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_payload, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    // False → return false (inline)
    builder.switch_to_block(false_block);
    builder.seal_block(false_block);
    let false_payload = builder.ins().iconst(types::I64, 0);
    let fv = emit_tagged(builder, TAG_BOOL, false_payload, ptr_type);
    builder.ins().jump(merge_block, &[fv]);

    // Eval right
    builder.switch_to_block(eval_right_block);
    builder.seal_block(eval_right_block);
    let right_cv = compile_expr(builder, ctx, h, right, ctx_val, ptr_type, policy_ctx);
    let right_val = right_cv.to_tagged(builder, ptr_type);

    // Check right: must be bool, else error
    let r_true = builder.create_block();
    let r_false = builder.create_block();
    let r_error = builder.create_block();
    emit_bool_check(builder, h, right_val, ptr_type, r_true, r_false, r_error);

    builder.switch_to_block(r_error);
    builder.seal_block(r_error);
    let re_payload = builder.ins().iconst(types::I64, 0);
    let rev = emit_tagged(builder, TAG_ERROR, re_payload, ptr_type);
    builder.ins().jump(merge_block, &[rev]);

    builder.switch_to_block(r_true);
    builder.seal_block(r_true);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(r_false);
    builder.seal_block(r_false);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    CompiledValue::Tagged(builder.block_params(merge_block)[0])
}

fn compile_or(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    let left_cv = compile_expr(builder, ctx, h, left, ctx_val, ptr_type, policy_ctx);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();
    let true_block = builder.create_block();
    let eval_right_block = builder.create_block();

    match left_cv {
        CompiledValue::Bool(v) => {
            builder.ins().brif(v, true_block, &[], eval_right_block, &[]);
        }
        CompiledValue::Error => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Long(_) => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Tagged(ptr) => {
            emit_bool_check(builder, h, ptr, ptr_type, true_block, eval_right_block, error_block);
        }
    }

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_p = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_p, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    // True → return true (inline)
    builder.switch_to_block(true_block);
    builder.seal_block(true_block);
    let true_p = builder.ins().iconst(types::I64, 1);
    let tv = emit_tagged(builder, TAG_BOOL, true_p, ptr_type);
    builder.ins().jump(merge_block, &[tv]);

    // Eval right
    builder.switch_to_block(eval_right_block);
    builder.seal_block(eval_right_block);
    let right_cv = compile_expr(builder, ctx, h, right, ctx_val, ptr_type, policy_ctx);
    let right_val = right_cv.to_tagged(builder, ptr_type);

    let r_true = builder.create_block();
    let r_false = builder.create_block();
    let r_error = builder.create_block();
    emit_bool_check(builder, h, right_val, ptr_type, r_true, r_false, r_error);

    builder.switch_to_block(r_error);
    builder.seal_block(r_error);
    let re_p = builder.ins().iconst(types::I64, 0);
    let rev = emit_tagged(builder, TAG_ERROR, re_p, ptr_type);
    builder.ins().jump(merge_block, &[rev]);

    builder.switch_to_block(r_true);
    builder.seal_block(r_true);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(r_false);
    builder.seal_block(r_false);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    CompiledValue::Tagged(builder.block_params(merge_block)[0])
}

fn compile_if(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    test: &ast::Expr,
    then_e: &ast::Expr,
    else_e: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    let test_cv = compile_expr(builder, ctx, h, test, ctx_val, ptr_type, policy_ctx);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let then_block = builder.create_block();
    let else_block = builder.create_block();
    let error_block = builder.create_block();

    match test_cv {
        CompiledValue::Bool(v) => {
            builder.ins().brif(v, then_block, &[], else_block, &[]);
        }
        CompiledValue::Error => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Long(_) => {
            builder.ins().jump(error_block, &[]);
        }
        CompiledValue::Tagged(ptr) => {
            emit_bool_check(builder, h, ptr, ptr_type, then_block, else_block, error_block);
        }
    }

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_p = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_p, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(then_block);
    builder.seal_block(then_block);
    let then_val = compile_expr(builder, ctx, h, then_e, ctx_val, ptr_type, policy_ctx).to_tagged(builder, ptr_type);
    builder.ins().jump(merge_block, &[then_val]);

    builder.switch_to_block(else_block);
    builder.seal_block(else_block);
    let else_val = compile_expr(builder, ctx, h, else_e, ctx_val, ptr_type, policy_ctx).to_tagged(builder, ptr_type);
    builder.ins().jump(merge_block, &[else_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    CompiledValue::Tagged(builder.block_params(merge_block)[0])
}

fn compile_unary(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    op: UnaryOp,
    arg: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    let arg_cv = compile_expr(builder, ctx, h, arg, ctx_val, ptr_type, policy_ctx);

    // Fast path: Not(Bool) → Bool(1-v), Neg(Long) handled below
    match op {
        UnaryOp::Not => {
            if let CompiledValue::Bool(v) = arg_cv {
                let one = builder.ins().iconst(types::I8, 1);
                let flipped = builder.ins().isub(one, v);
                return CompiledValue::Bool(flipped);
            }
            if let CompiledValue::Error = arg_cv {
                return CompiledValue::Error;
            }
        }
        UnaryOp::Neg => {
            if let CompiledValue::Error = arg_cv {
                return CompiledValue::Error;
            }
        }
        _ => {}
    }

    let arg_val = arg_cv.to_tagged(builder, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();

    // Inline error check
    emit_error_check_inline(builder, arg_val, error_block);

    let tag = emit_load_tag(builder, arg_val);

    match op {
        UnaryOp::Not => {
            // Fast path: TAG_BOOL → flip payload inline
            let fast_block = builder.create_block();
            let slow_block = builder.create_block();
            let is_bool = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_BOOL);
            builder.ins().brif(is_bool, fast_block, &[], slow_block, &[]);

            builder.switch_to_block(fast_block);
            builder.seal_block(fast_block);
            let payload = emit_load_payload(builder, arg_val);
            let one = builder.ins().iconst(types::I64, 1);
            let flipped = builder.ins().isub(one, payload);
            let result = emit_tagged(builder, TAG_BOOL, flipped, ptr_type);
            builder.ins().jump(merge_block, &[result]);

            // Slow path: TAG_VALUE → call helper
            builder.switch_to_block(slow_block);
            builder.seal_block(slow_block);
            let slow_result = icall(builder, h.sig_ptr_to_ptr, h.addr_not, &[arg_val], ptr_type);
            builder.ins().jump(merge_block, &[slow_result]);
        }
        UnaryOp::Neg => {
            // Fast path: TAG_LONG → negate payload inline with overflow check
            let fast_block = builder.create_block();
            let slow_block = builder.create_block();
            let is_long = builder.ins().icmp_imm(IntCC::Equal, tag, TAG_LONG);
            builder.ins().brif(is_long, fast_block, &[], slow_block, &[]);

            builder.switch_to_block(fast_block);
            builder.seal_block(fast_block);
            let payload = emit_load_payload(builder, arg_val);
            // i64::MIN cannot be negated — check for overflow
            let min_val = builder.ins().iconst(types::I64, i64::MIN);
            let is_min = builder.ins().icmp(IntCC::Equal, payload, min_val);
            let neg_ok = builder.create_block();
            builder.ins().brif(is_min, error_block, &[], neg_ok, &[]);

            builder.switch_to_block(neg_ok);
            builder.seal_block(neg_ok);
            let negated = builder.ins().ineg(payload);
            let result = emit_tagged(builder, TAG_LONG, negated, ptr_type);
            builder.ins().jump(merge_block, &[result]);

            // Slow path
            builder.switch_to_block(slow_block);
            builder.seal_block(slow_block);
            let slow_result = icall(builder, h.sig_ptr_to_ptr, h.addr_neg, &[arg_val], ptr_type);
            builder.ins().jump(merge_block, &[slow_result]);
        }
        UnaryOp::IsEmpty => {
            // No fast path — always call helper
            let result = icall(builder, h.sig_ptr_to_ptr, h.addr_is_empty_set, &[arg_val], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
    }

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_p = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_p, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    CompiledValue::Tagged(builder.block_params(merge_block)[0])
}

/// Emit inline integer binary op: both args must be TAG_LONG.
/// Fast path does the op natively; slow path calls the helper.
fn emit_long_binop(
    builder: &mut FunctionBuilder,
    _h: &HelperSigs,
    a1: cranelift_codegen::ir::Value,
    a2: cranelift_codegen::ir::Value,
    ptr_type: Type,
    merge_block: cranelift_codegen::ir::Block,
    error_block: cranelift_codegen::ir::Block,
    helper_sig: SigRef,
    helper_addr: u64,
    emit_fast: impl FnOnce(&mut FunctionBuilder, cranelift_codegen::ir::Value, cranelift_codegen::ir::Value, cranelift_codegen::ir::Block, Type),
) {
    let tag_a = emit_load_tag(builder, a1);
    let tag_b = emit_load_tag(builder, a2);
    let both_long = builder.create_block();
    let slow = builder.create_block();

    let a_is_long = builder.ins().icmp_imm(IntCC::Equal, tag_a, TAG_LONG);
    let check_b = builder.create_block();
    builder.ins().brif(a_is_long, check_b, &[], slow, &[]);

    builder.switch_to_block(check_b);
    builder.seal_block(check_b);
    let b_is_long = builder.ins().icmp_imm(IntCC::Equal, tag_b, TAG_LONG);
    builder.ins().brif(b_is_long, both_long, &[], slow, &[]);

    // Fast path: both TAG_LONG
    builder.switch_to_block(both_long);
    builder.seal_block(both_long);
    let pa = emit_load_payload(builder, a1);
    let pb = emit_load_payload(builder, a2);
    emit_fast(builder, pa, pb, error_block, ptr_type);
    // emit_fast must jump to merge_block or error_block

    // Slow path: call helper
    builder.switch_to_block(slow);
    builder.seal_block(slow);
    let result = icall(builder, helper_sig, helper_addr, &[a1, a2], ptr_type);
    builder.ins().jump(merge_block, &[result]);
}

fn compile_binary(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    op: BinaryOp,
    arg1: &ast::Expr,
    arg2: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> CompiledValue {
    let a1_cv = compile_expr(builder, ctx, h, arg1, ctx_val, ptr_type, policy_ctx);

    // Fast paths for known types
    let a2_cv = compile_expr(builder, ctx, h, arg2, ctx_val, ptr_type, policy_ctx);

    // Check for static errors
    if let CompiledValue::Error = a1_cv { return CompiledValue::Error; }
    if let CompiledValue::Error = a2_cv { return CompiledValue::Error; }

    // Fast path: Less/LessEq/Eq when both types are known
    match op {
        BinaryOp::Less => {
            if let (CompiledValue::Long(a), CompiledValue::Long(b)) = (a1_cv, a2_cv) {
                let cmp = builder.ins().icmp(IntCC::SignedLessThan, a, b);
                return CompiledValue::Bool(cmp);
            }
        }
        BinaryOp::LessEq => {
            if let (CompiledValue::Long(a), CompiledValue::Long(b)) = (a1_cv, a2_cv) {
                let cmp = builder.ins().icmp(IntCC::SignedLessThanOrEqual, a, b);
                return CompiledValue::Bool(cmp);
            }
        }
        BinaryOp::Eq => {
            match (a1_cv, a2_cv) {
                (CompiledValue::Bool(a), CompiledValue::Bool(b)) => {
                    let cmp = builder.ins().icmp(IntCC::Equal, a, b);
                    return CompiledValue::Bool(cmp);
                }
                (CompiledValue::Long(a), CompiledValue::Long(b)) => {
                    let cmp = builder.ins().icmp(IntCC::Equal, a, b);
                    return CompiledValue::Bool(cmp);
                }
                _ => {}
            }
        }
        _ => {}
    }

    // Box to tagged for the general path
    let a1 = a1_cv.to_tagged(builder, ptr_type);
    let a2 = a2_cv.to_tagged(builder, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();

    // Inline error checks
    emit_error_check_inline(builder, a1, error_block);
    emit_error_check_inline(builder, a2, error_block);

    match op {
        BinaryOp::Add => {
            emit_long_binop(builder, h, a1, a2, ptr_type, merge_block, error_block,
                h.sig_2ptr_to_ptr, h.addr_add, |b, pa, pb, err_blk, pt| {
                    // Native add with overflow check
                    let (result, overflow) = b.ins().sadd_overflow(pa, pb);
                    let ok = b.create_block();
                    b.ins().brif(overflow, err_blk, &[], ok, &[]);
                    b.switch_to_block(ok);
                    b.seal_block(ok);
                    let tv = emit_tagged(b, TAG_LONG, result, pt);
                    b.ins().jump(merge_block, &[tv]);
                });
        }
        BinaryOp::Sub => {
            emit_long_binop(builder, h, a1, a2, ptr_type, merge_block, error_block,
                h.sig_2ptr_to_ptr, h.addr_sub, |b, pa, pb, err_blk, pt| {
                    let (result, overflow) = b.ins().ssub_overflow(pa, pb);
                    let ok = b.create_block();
                    b.ins().brif(overflow, err_blk, &[], ok, &[]);
                    b.switch_to_block(ok);
                    b.seal_block(ok);
                    let tv = emit_tagged(b, TAG_LONG, result, pt);
                    b.ins().jump(merge_block, &[tv]);
                });
        }
        BinaryOp::Mul => {
            emit_long_binop(builder, h, a1, a2, ptr_type, merge_block, error_block,
                h.sig_2ptr_to_ptr, h.addr_mul, |b, pa, pb, err_blk, pt| {
                    let (result, overflow) = b.ins().smul_overflow(pa, pb);
                    let ok = b.create_block();
                    b.ins().brif(overflow, err_blk, &[], ok, &[]);
                    b.switch_to_block(ok);
                    b.seal_block(ok);
                    let tv = emit_tagged(b, TAG_LONG, result, pt);
                    b.ins().jump(merge_block, &[tv]);
                });
        }
        BinaryOp::Less => {
            emit_long_binop(builder, h, a1, a2, ptr_type, merge_block, error_block,
                h.sig_2ptr_to_ptr, h.addr_less, |b, pa, pb, _err_blk, pt| {
                    let cmp = b.ins().icmp(IntCC::SignedLessThan, pa, pb);
                    let result_i64 = b.ins().uextend(types::I64, cmp);
                    let tv = emit_tagged(b, TAG_BOOL, result_i64, pt);
                    b.ins().jump(merge_block, &[tv]);
                });
        }
        BinaryOp::LessEq => {
            emit_long_binop(builder, h, a1, a2, ptr_type, merge_block, error_block,
                h.sig_2ptr_to_ptr, h.addr_less_eq, |b, pa, pb, _err_blk, pt| {
                    let cmp = b.ins().icmp(IntCC::SignedLessThanOrEqual, pa, pb);
                    let result_i64 = b.ins().uextend(types::I64, cmp);
                    let tv = emit_tagged(b, TAG_BOOL, result_i64, pt);
                    b.ins().jump(merge_block, &[tv]);
                });
        }
        BinaryOp::Eq => {
            // Fast path: same tag + same payload for primitives
            let tag_a = emit_load_tag(builder, a1);
            let tag_b = emit_load_tag(builder, a2);
            let tags_match = builder.ins().icmp(IntCC::Equal, tag_a, tag_b);
            let same_tag = builder.create_block();
            let slow = builder.create_block();
            builder.ins().brif(tags_match, same_tag, &[], slow, &[]);

            builder.switch_to_block(same_tag);
            builder.seal_block(same_tag);
            // Only fast-path for TAG_BOOL and TAG_LONG
            let is_bool = builder.ins().icmp_imm(IntCC::Equal, tag_a, TAG_BOOL);
            let is_long = builder.ins().icmp_imm(IntCC::Equal, tag_a, TAG_LONG);
            let is_primitive = builder.ins().bor(is_bool, is_long);
            let fast = builder.create_block();
            builder.ins().brif(is_primitive, fast, &[], slow, &[]);

            builder.switch_to_block(fast);
            builder.seal_block(fast);
            let pa = emit_load_payload(builder, a1);
            let pb = emit_load_payload(builder, a2);
            let eq = builder.ins().icmp(IntCC::Equal, pa, pb);
            let eq_i64 = builder.ins().uextend(types::I64, eq);
            let tv = emit_tagged(builder, TAG_BOOL, eq_i64, ptr_type);
            builder.ins().jump(merge_block, &[tv]);

            // Slow path: call helper (handles Value types, cross-type eq)
            builder.switch_to_block(slow);
            builder.seal_block(slow);
            let result = icall(builder, h.sig_2ptr_to_ptr, h.addr_eq, &[a1, a2], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        // These always need helpers — complex data structure operations
        BinaryOp::In => {
            let result = icall(builder, h.sig_3ptr_to_ptr, h.addr_in_op, &[a1, a2, ctx_val], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        BinaryOp::Contains => {
            let result = icall(builder, h.sig_2ptr_to_ptr, h.addr_contains, &[a1, a2], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        BinaryOp::ContainsAll => {
            let result = icall(builder, h.sig_2ptr_to_ptr, h.addr_contains_all, &[a1, a2], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        BinaryOp::ContainsAny => {
            let result = icall(builder, h.sig_2ptr_to_ptr, h.addr_contains_any, &[a1, a2], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        BinaryOp::GetTag => {
            let result = icall(builder, h.sig_3ptr_to_ptr, h.addr_get_tag, &[a1, a2, ctx_val], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
        BinaryOp::HasTag => {
            let result = icall(builder, h.sig_3ptr_to_ptr, h.addr_has_tag, &[a1, a2, ctx_val], ptr_type);
            builder.ins().jump(merge_block, &[result]);
        }
    }

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_p = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_p, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    CompiledValue::Tagged(builder.block_params(merge_block)[0])
}

/// Compile a sub-expression, error-check it, then apply a callback function.
fn compile_with_error_check(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    inner: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
    apply: impl FnOnce(&mut FunctionBuilder, cranelift_codegen::ir::Value, Type) -> cranelift_codegen::ir::Value,
) -> cranelift_codegen::ir::Value {
    let inner_cv = compile_expr(builder, ctx, h, inner, ctx_val, ptr_type, policy_ctx);
    let val = inner_cv.to_tagged(builder, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);

    // Inline error check instead of calling helper
    let error_block = builder.create_block();
    emit_error_check_inline(builder, val, error_block);

    let result = apply(builder, val, ptr_type);
    builder.ins().jump(merge_block, &[result]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let err_p = builder.ins().iconst(types::I64, 0);
    let ev = emit_tagged(builder, TAG_ERROR, err_p, ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
}

fn compile_set(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    elements: &[ast::Expr],
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> cranelift_codegen::ir::Value {
    let count = elements.len();
    if count == 0 {
        let null = builder.ins().iconst(ptr_type, 0);
        let cnt = builder.ins().iconst(types::I64, 0);
        return icall(builder, h.sig_ptr_u64_to_ptr, h.addr_set_build, &[null, cnt], ptr_type);
    }

    let slot = builder.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot, (count * 8) as u32, 3,
    ));

    for (i, elem) in elements.iter().enumerate() {
        let val = compile_expr(builder, ctx, h, elem, ctx_val, ptr_type, policy_ctx).to_tagged(builder, ptr_type);
        let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[val], ptr_type);
        let zero = builder.ins().iconst(types::I64, 0);
        let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
        let ok_block = builder.create_block();
        let err_block = builder.create_block();
        builder.ins().brif(cmp, err_block, &[], ok_block, &[]);

        builder.switch_to_block(err_block);
        builder.seal_block(err_block);
        let ret_2 = builder.ins().iconst(types::I32, 2);
        builder.ins().return_(&[ret_2]);

        builder.switch_to_block(ok_block);
        builder.seal_block(ok_block);
        builder.ins().stack_store(val, slot, (i * 8) as i32);
    }

    let arr_addr = builder.ins().stack_addr(ptr_type, slot, 0);
    let cnt = builder.ins().iconst(types::I64, count as i64);
    icall(builder, h.sig_ptr_u64_to_ptr, h.addr_set_build, &[arr_addr, cnt], ptr_type)
}

fn compile_record(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    fields: &BTreeMap<SmolStr, ast::Expr>,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> cranelift_codegen::ir::Value {
    let count = fields.len();
    if count == 0 {
        let null = builder.ins().iconst(ptr_type, 0);
        let cnt = builder.ins().iconst(types::I64, 0);
        return icall(builder, h.sig_4ptr_u64_to_ptr, h.addr_record_build, &[ctx_val, null, null, cnt], ptr_type);
    }

    let keys_slot = builder.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot, (count * 16) as u32, 3,
    ));
    let vals_slot = builder.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot, (count * 8) as u32, 3,
    ));

    for (i, (key, val_expr)) in fields.iter().enumerate() {
        let (ko, kl) = ctx.intern_string(key.as_str());
        let ko_v = builder.ins().iconst(types::I64, ko as i64);
        let kl_v = builder.ins().iconst(types::I64, kl as i64);
        builder.ins().stack_store(ko_v, keys_slot, (i * 16) as i32);
        builder.ins().stack_store(kl_v, keys_slot, (i * 16 + 8) as i32);

        let val = compile_expr(builder, ctx, h, val_expr, ctx_val, ptr_type, policy_ctx).to_tagged(builder, ptr_type);
        let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[val], ptr_type);
        let zero = builder.ins().iconst(types::I64, 0);
        let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
        let ok_block = builder.create_block();
        let err_block = builder.create_block();
        builder.ins().brif(cmp, err_block, &[], ok_block, &[]);

        builder.switch_to_block(err_block);
        builder.seal_block(err_block);
        let ret_2 = builder.ins().iconst(types::I32, 2);
        builder.ins().return_(&[ret_2]);

        builder.switch_to_block(ok_block);
        builder.seal_block(ok_block);
        builder.ins().stack_store(val, vals_slot, (i * 8) as i32);
    }

    let keys_addr = builder.ins().stack_addr(ptr_type, keys_slot, 0);
    let vals_addr = builder.ins().stack_addr(ptr_type, vals_slot, 0);
    let cnt = builder.ins().iconst(types::I64, count as i64);
    icall(builder, h.sig_4ptr_u64_to_ptr, h.addr_record_build, &[ctx_val, keys_addr, vals_addr, cnt], ptr_type)
}

fn compile_ext_call(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    fn_name: &ast::Name,
    args: &[ast::Expr],
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    policy_ctx: &PolicyTypeCtx,
) -> cranelift_codegen::ir::Value {
    let name_str = fn_name.to_string();
    let (no, nl) = ctx.intern_string(&name_str);
    let arg_count = args.len();

    if arg_count == 0 {
        let no_v = builder.ins().iconst(types::I64, no as i64);
        let nl_v = builder.ins().iconst(types::I64, nl as i64);
        let null = builder.ins().iconst(ptr_type, 0);
        let cnt = builder.ins().iconst(types::I64, 0);
        return icall(builder, h.sig_ext_call, h.addr_ext_call, &[ctx_val, no_v, nl_v, null, cnt], ptr_type);
    }

    let args_slot = builder.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot, (arg_count * 8) as u32, 3,
    ));

    for (i, arg) in args.iter().enumerate() {
        let val = compile_expr(builder, ctx, h, arg, ctx_val, ptr_type, policy_ctx).to_tagged(builder, ptr_type);
        let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[val], ptr_type);
        let zero = builder.ins().iconst(types::I64, 0);
        let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
        let ok_block = builder.create_block();
        let err_block = builder.create_block();
        builder.ins().brif(cmp, err_block, &[], ok_block, &[]);

        builder.switch_to_block(err_block);
        builder.seal_block(err_block);
        let ret_2 = builder.ins().iconst(types::I32, 2);
        builder.ins().return_(&[ret_2]);

        builder.switch_to_block(ok_block);
        builder.seal_block(ok_block);
        builder.ins().stack_store(val, args_slot, (i * 8) as i32);
    }

    let no_v = builder.ins().iconst(types::I64, no as i64);
    let nl_v = builder.ins().iconst(types::I64, nl as i64);
    let args_addr = builder.ins().stack_addr(ptr_type, args_slot, 0);
    let cnt = builder.ins().iconst(types::I64, arg_count as i64);
    icall(builder, h.sig_ext_call, h.addr_ext_call, &[ctx_val, no_v, nl_v, args_addr, cnt], ptr_type)
}
