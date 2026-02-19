pub mod helpers;

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use cedar_policy_core::ast::{self, BinaryOp, ExprKind, Literal, UnaryOp, Var};
use cranelift::prelude::*;
use cranelift_codegen::ir::{Function, SigRef};
use cranelift_codegen::settings;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Module, Linkage};
use smol_str::SmolStr;

use helpers::RuntimeCtx;

/// C-compatible tagged value for passing data between JIT code and helpers.
#[repr(C)]
pub struct TaggedValue {
    pub tag: u32,
    pub _pad: u32,
    pub payload: u64,
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

pub struct Compiler;

impl Compiler {
    pub fn new() -> Self {
        Compiler
    }

    pub fn compile_conditions(
        &self,
        conditions: &[ast::Expr],
    ) -> Result<CompiledConditions, CompileError> {
        let mut codegen_ctx = CodeGenContext::new();

        // Pre-walk all conditions to intern strings and register patterns
        for condition in conditions {
            codegen_ctx.prewalk(condition);
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
        for (i, condition) in conditions.iter().enumerate() {
            let func_id = compile_one_condition(
                &mut module,
                &mut codegen_ctx,
                condition,
                i,
                ptr_type,
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
            condition_count: conditions.len(),
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

fn compile_one_condition(
    module: &mut JITModule,
    codegen_ctx: &mut CodeGenContext,
    condition: &ast::Expr,
    index: usize,
    ptr_type: Type,
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

        let result_ptr = compile_expr(
            &mut builder, codegen_ctx, &hsigs, condition, ctx_val, ptr_type,
        );

        // Convert result to i32: is_error → 2, is_bool && get_bool → 1, else → 0
        let is_err = icall(&mut builder, hsigs.sig_ptr_to_u64, hsigs.addr_is_error, &[result_ptr], ptr_type);
        let zero_i64 = builder.ins().iconst(types::I64, 0);
        let err_cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero_i64);

        let not_error_block = builder.create_block();
        let return_error_block = builder.create_block();
        let return_true_block = builder.create_block();
        let return_false_block = builder.create_block();

        builder.ins().brif(err_cmp, return_error_block, &[], not_error_block, &[]);

        builder.switch_to_block(not_error_block);
        builder.seal_block(not_error_block);
        let is_bool_val = icall(&mut builder, hsigs.sig_ptr_to_u64, hsigs.addr_is_bool, &[result_ptr], ptr_type);
        let bool_cmp = builder.ins().icmp(IntCC::Equal, is_bool_val, zero_i64);
        let is_bool_block = builder.create_block();
        builder.ins().brif(bool_cmp, return_error_block, &[], is_bool_block, &[]);

        builder.switch_to_block(is_bool_block);
        builder.seal_block(is_bool_block);
        let bool_val = icall(&mut builder, hsigs.sig_ptr_to_u64, hsigs.addr_get_bool, &[result_ptr], ptr_type);
        let true_cmp = builder.ins().icmp(IntCC::NotEqual, bool_val, zero_i64);
        builder.ins().brif(true_cmp, return_true_block, &[], return_false_block, &[]);

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
) -> cranelift_codegen::ir::Value {
    match expr.expr_kind() {
        ExprKind::Lit(lit) => match lit {
            Literal::Bool(b) => {
                let v = builder.ins().iconst(types::I64, if *b { 1 } else { 0 });
                icall(builder, h.sig_u64_to_ptr, h.addr_lit_bool, &[v], ptr_type)
            }
            Literal::Long(i) => {
                let v = builder.ins().iconst(types::I64, *i);
                icall(builder, h.sig_u64_to_ptr, h.addr_lit_long, &[v], ptr_type)
            }
            Literal::String(s) => {
                let (off, len) = ctx.intern_string(s.as_str());
                let off_v = builder.ins().iconst(types::I64, off as i64);
                let len_v = builder.ins().iconst(types::I64, len as i64);
                icall(builder, h.sig_ctx_3u64_to_ptr, h.addr_lit_string, &[ctx_val, off_v, len_v], ptr_type)
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
                icall(builder, h.sig_ctx_5u64_to_ptr, h.addr_lit_entity, &[ctx_val, to_v, tl_v, io_v, il_v], ptr_type)
            }
        },

        ExprKind::Var(var) => {
            let addr = match var {
                Var::Principal => h.addr_var_principal,
                Var::Action => h.addr_var_action,
                Var::Resource => h.addr_var_resource,
                Var::Context => h.addr_var_context,
            };
            icall(builder, h.sig_ctx_to_ptr, addr, &[ctx_val], ptr_type)
        }

        ExprKind::And { left, right } => {
            compile_and(builder, ctx, h, left, right, ctx_val, ptr_type)
        }

        ExprKind::Or { left, right } => {
            compile_or(builder, ctx, h, left, right, ctx_val, ptr_type)
        }

        ExprKind::If { test_expr, then_expr, else_expr } => {
            compile_if(builder, ctx, h, test_expr, then_expr, else_expr, ctx_val, ptr_type)
        }

        ExprKind::UnaryApp { op, arg } => {
            compile_unary(builder, ctx, h, *op, arg, ctx_val, ptr_type)
        }

        ExprKind::BinaryApp { op, arg1, arg2 } => {
            compile_binary(builder, ctx, h, *op, arg1, arg2, ctx_val, ptr_type)
        }

        ExprKind::GetAttr { expr: inner, attr } => {
            let (off, len) = ctx.intern_string(attr.as_str());
            compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_get_attr, &[val, ctx_val, off_v, len_v], pt)
            })
        }

        ExprKind::HasAttr { expr: inner, attr } => {
            let (off, len) = ctx.intern_string(attr.as_str());
            compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_has_attr, &[val, ctx_val, off_v, len_v], pt)
            })
        }

        ExprKind::Like { expr: inner, pattern } => {
            let pid = ctx.register_pattern(pattern);
            compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, |b, val, pt| {
                let pid_v = b.ins().iconst(types::I64, pid as i64);
                icall(b, h.sig_ptr_ptr_u64_to_ptr, h.addr_like, &[val, ctx_val, pid_v], pt)
            })
        }

        ExprKind::Is { expr: inner, entity_type, .. } => {
            let type_str = entity_type.to_string();
            let (off, len) = ctx.intern_string(&type_str);
            compile_with_error_check(builder, ctx, h, inner, ctx_val, ptr_type, |b, val, pt| {
                let off_v = b.ins().iconst(types::I64, off as i64);
                let len_v = b.ins().iconst(types::I64, len as i64);
                icall(b, h.sig_ptr_ptr_2u64_to_ptr, h.addr_is_entity_type, &[val, ctx_val, off_v, len_v], pt)
            })
        }

        ExprKind::Set(elements) => {
            compile_set(builder, ctx, h, elements, ctx_val, ptr_type)
        }

        ExprKind::Record(fields) => {
            compile_record(builder, ctx, h, fields.as_ref(), ctx_val, ptr_type)
        }

        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            compile_ext_call(builder, ctx, h, fn_name, args, ctx_val, ptr_type)
        }

        ExprKind::Slot(_) | ExprKind::Unknown(_) => {
            icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type)
        }
    }
}

// I realize the And/Or/etc. cases above have bugs due to the block switching
// mess. Let me rewrite them as separate functions that handle their own blocks cleanly.

fn compile_and(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
) -> cranelift_codegen::ir::Value {
    let left_val = compile_expr(builder, ctx, h, left, ctx_val, ptr_type);
    let zero_i64 = builder.ins().iconst(types::I64, 0);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);

    // Check is_error(left)
    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[left_val], ptr_type);
    let err_cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero_i64);
    let error_block = builder.create_block();
    let check_bool_block = builder.create_block();
    builder.ins().brif(err_cmp, error_block, &[], check_bool_block, &[]);

    // Error → return error
    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    // Check bool
    builder.switch_to_block(check_bool_block);
    builder.seal_block(check_bool_block);
    let is_bool = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[left_val], ptr_type);
    let zero2 = builder.ins().iconst(types::I64, 0);
    let not_bool = builder.ins().icmp(IntCC::Equal, is_bool, zero2);
    let check_true_block = builder.create_block();
    let error2_block = builder.create_block();
    builder.ins().brif(not_bool, error2_block, &[], check_true_block, &[]);

    builder.switch_to_block(error2_block);
    builder.seal_block(error2_block);
    let ev2 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev2]);

    // Check if true
    builder.switch_to_block(check_true_block);
    builder.seal_block(check_true_block);
    let bool_v = icall(builder, h.sig_ptr_to_u64, h.addr_get_bool, &[left_val], ptr_type);
    let zero3 = builder.ins().iconst(types::I64, 0);
    let is_true = builder.ins().icmp(IntCC::NotEqual, bool_v, zero3);
    let eval_right_block = builder.create_block();
    let false_block = builder.create_block();
    builder.ins().brif(is_true, eval_right_block, &[], false_block, &[]);

    // False → return false
    builder.switch_to_block(false_block);
    builder.seal_block(false_block);
    let fv = builder.ins().iconst(types::I64, 0);
    let false_tv = icall(builder, h.sig_u64_to_ptr, h.addr_lit_bool, &[fv], ptr_type);
    builder.ins().jump(merge_block, &[false_tv]);

    // Eval right
    builder.switch_to_block(eval_right_block);
    builder.seal_block(eval_right_block);
    let right_val = compile_expr(builder, ctx, h, right, ctx_val, ptr_type);

    // Check right for error/non-bool
    let r_is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[right_val], ptr_type);
    let zero4 = builder.ins().iconst(types::I64, 0);
    let r_err_cmp = builder.ins().icmp(IntCC::NotEqual, r_is_err, zero4);
    let r_err_block = builder.create_block();
    let r_check_bool = builder.create_block();
    builder.ins().brif(r_err_cmp, r_err_block, &[], r_check_bool, &[]);

    builder.switch_to_block(r_err_block);
    builder.seal_block(r_err_block);
    let ev3 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev3]);

    builder.switch_to_block(r_check_bool);
    builder.seal_block(r_check_bool);
    let r_is_bool = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[right_val], ptr_type);
    let zero5 = builder.ins().iconst(types::I64, 0);
    let r_not_bool = builder.ins().icmp(IntCC::Equal, r_is_bool, zero5);
    let r_ok = builder.create_block();
    let r_err2 = builder.create_block();
    builder.ins().brif(r_not_bool, r_err2, &[], r_ok, &[]);

    builder.switch_to_block(r_err2);
    builder.seal_block(r_err2);
    let ev4 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev4]);

    builder.switch_to_block(r_ok);
    builder.seal_block(r_ok);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
}

fn compile_or(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
) -> cranelift_codegen::ir::Value {
    let left_val = compile_expr(builder, ctx, h, left, ctx_val, ptr_type);
    let zero_i64 = builder.ins().iconst(types::I64, 0);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);

    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[left_val], ptr_type);
    let err_cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero_i64);
    let error_block = builder.create_block();
    let check_bool_block = builder.create_block();
    builder.ins().brif(err_cmp, error_block, &[], check_bool_block, &[]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(check_bool_block);
    builder.seal_block(check_bool_block);
    let is_bool = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[left_val], ptr_type);
    let zero2 = builder.ins().iconst(types::I64, 0);
    let not_bool = builder.ins().icmp(IntCC::Equal, is_bool, zero2);
    let check_false_block = builder.create_block();
    let error2_block = builder.create_block();
    builder.ins().brif(not_bool, error2_block, &[], check_false_block, &[]);

    builder.switch_to_block(error2_block);
    builder.seal_block(error2_block);
    let ev2 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev2]);

    builder.switch_to_block(check_false_block);
    builder.seal_block(check_false_block);
    let bool_v = icall(builder, h.sig_ptr_to_u64, h.addr_get_bool, &[left_val], ptr_type);
    let zero3 = builder.ins().iconst(types::I64, 0);
    let is_false = builder.ins().icmp(IntCC::Equal, bool_v, zero3);
    let eval_right_block = builder.create_block();
    let true_block = builder.create_block();
    builder.ins().brif(is_false, eval_right_block, &[], true_block, &[]);

    // True → return true
    builder.switch_to_block(true_block);
    builder.seal_block(true_block);
    let tv = builder.ins().iconst(types::I64, 1);
    let true_tv = icall(builder, h.sig_u64_to_ptr, h.addr_lit_bool, &[tv], ptr_type);
    builder.ins().jump(merge_block, &[true_tv]);

    // Eval right
    builder.switch_to_block(eval_right_block);
    builder.seal_block(eval_right_block);
    let right_val = compile_expr(builder, ctx, h, right, ctx_val, ptr_type);

    let r_is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[right_val], ptr_type);
    let zero4 = builder.ins().iconst(types::I64, 0);
    let r_err_cmp = builder.ins().icmp(IntCC::NotEqual, r_is_err, zero4);
    let r_err_block = builder.create_block();
    let r_check_bool = builder.create_block();
    builder.ins().brif(r_err_cmp, r_err_block, &[], r_check_bool, &[]);

    builder.switch_to_block(r_err_block);
    builder.seal_block(r_err_block);
    let ev3 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev3]);

    builder.switch_to_block(r_check_bool);
    builder.seal_block(r_check_bool);
    let r_is_bool = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[right_val], ptr_type);
    let zero5 = builder.ins().iconst(types::I64, 0);
    let r_not_bool = builder.ins().icmp(IntCC::Equal, r_is_bool, zero5);
    let r_ok = builder.create_block();
    let r_err2 = builder.create_block();
    builder.ins().brif(r_not_bool, r_err2, &[], r_ok, &[]);

    builder.switch_to_block(r_err2);
    builder.seal_block(r_err2);
    let ev4 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev4]);

    builder.switch_to_block(r_ok);
    builder.seal_block(r_ok);
    builder.ins().jump(merge_block, &[right_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
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
) -> cranelift_codegen::ir::Value {
    let test_val = compile_expr(builder, ctx, h, test, ctx_val, ptr_type);
    let zero_i64 = builder.ins().iconst(types::I64, 0);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);

    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[test_val], ptr_type);
    let err_cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero_i64);
    let error_block = builder.create_block();
    let check_bool = builder.create_block();
    builder.ins().brif(err_cmp, error_block, &[], check_bool, &[]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(check_bool);
    builder.seal_block(check_bool);
    let is_bool = icall(builder, h.sig_ptr_to_u64, h.addr_is_bool, &[test_val], ptr_type);
    let zero2 = builder.ins().iconst(types::I64, 0);
    let not_bool = builder.ins().icmp(IntCC::Equal, is_bool, zero2);
    let check_true = builder.create_block();
    let error2 = builder.create_block();
    builder.ins().brif(not_bool, error2, &[], check_true, &[]);

    builder.switch_to_block(error2);
    builder.seal_block(error2);
    let ev2 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev2]);

    builder.switch_to_block(check_true);
    builder.seal_block(check_true);
    let bool_v = icall(builder, h.sig_ptr_to_u64, h.addr_get_bool, &[test_val], ptr_type);
    let zero3 = builder.ins().iconst(types::I64, 0);
    let is_true = builder.ins().icmp(IntCC::NotEqual, bool_v, zero3);
    let then_block = builder.create_block();
    let else_block = builder.create_block();
    builder.ins().brif(is_true, then_block, &[], else_block, &[]);

    builder.switch_to_block(then_block);
    builder.seal_block(then_block);
    let then_val = compile_expr(builder, ctx, h, then_e, ctx_val, ptr_type);
    builder.ins().jump(merge_block, &[then_val]);

    builder.switch_to_block(else_block);
    builder.seal_block(else_block);
    let else_val = compile_expr(builder, ctx, h, else_e, ctx_val, ptr_type);
    builder.ins().jump(merge_block, &[else_val]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
}

fn compile_unary(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    op: UnaryOp,
    arg: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
) -> cranelift_codegen::ir::Value {
    let arg_val = compile_expr(builder, ctx, h, arg, ctx_val, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();

    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[arg_val], ptr_type);
    let zero = builder.ins().iconst(types::I64, 0);
    let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
    let ok_block = builder.create_block();
    builder.ins().brif(cmp, error_block, &[], ok_block, &[]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(ok_block);
    builder.seal_block(ok_block);
    let (sig, addr) = match op {
        UnaryOp::Not => (h.sig_ptr_to_ptr, h.addr_not),
        UnaryOp::Neg => (h.sig_ptr_to_ptr, h.addr_neg),
        UnaryOp::IsEmpty => (h.sig_ptr_to_ptr, h.addr_is_empty_set),
    };
    let result = icall(builder, sig, addr, &[arg_val], ptr_type);
    builder.ins().jump(merge_block, &[result]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
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
) -> cranelift_codegen::ir::Value {
    let a1 = compile_expr(builder, ctx, h, arg1, ctx_val, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);
    let error_block = builder.create_block();

    // Check a1 error
    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[a1], ptr_type);
    let zero = builder.ins().iconst(types::I64, 0);
    let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
    let a1_ok = builder.create_block();
    builder.ins().brif(cmp, error_block, &[], a1_ok, &[]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(a1_ok);
    builder.seal_block(a1_ok);
    let a2 = compile_expr(builder, ctx, h, arg2, ctx_val, ptr_type);

    // Check a2 error
    let is_err2 = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[a2], ptr_type);
    let zero2 = builder.ins().iconst(types::I64, 0);
    let cmp2 = builder.ins().icmp(IntCC::NotEqual, is_err2, zero2);
    let a2_ok = builder.create_block();
    let err2_block = builder.create_block();
    builder.ins().brif(cmp2, err2_block, &[], a2_ok, &[]);

    builder.switch_to_block(err2_block);
    builder.seal_block(err2_block);
    let ev2 = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev2]);

    builder.switch_to_block(a2_ok);
    builder.seal_block(a2_ok);

    let result = match op {
        BinaryOp::Eq => icall(builder, h.sig_2ptr_to_ptr, h.addr_eq, &[a1, a2], ptr_type),
        BinaryOp::Less => icall(builder, h.sig_2ptr_to_ptr, h.addr_less, &[a1, a2], ptr_type),
        BinaryOp::LessEq => icall(builder, h.sig_2ptr_to_ptr, h.addr_less_eq, &[a1, a2], ptr_type),
        BinaryOp::Add => icall(builder, h.sig_2ptr_to_ptr, h.addr_add, &[a1, a2], ptr_type),
        BinaryOp::Sub => icall(builder, h.sig_2ptr_to_ptr, h.addr_sub, &[a1, a2], ptr_type),
        BinaryOp::Mul => icall(builder, h.sig_2ptr_to_ptr, h.addr_mul, &[a1, a2], ptr_type),
        BinaryOp::In => icall(builder, h.sig_3ptr_to_ptr, h.addr_in_op, &[a1, a2, ctx_val], ptr_type),
        BinaryOp::Contains => icall(builder, h.sig_2ptr_to_ptr, h.addr_contains, &[a1, a2], ptr_type),
        BinaryOp::ContainsAll => icall(builder, h.sig_2ptr_to_ptr, h.addr_contains_all, &[a1, a2], ptr_type),
        BinaryOp::ContainsAny => icall(builder, h.sig_2ptr_to_ptr, h.addr_contains_any, &[a1, a2], ptr_type),
        BinaryOp::GetTag => icall(builder, h.sig_3ptr_to_ptr, h.addr_get_tag, &[a1, a2, ctx_val], ptr_type),
        BinaryOp::HasTag => icall(builder, h.sig_3ptr_to_ptr, h.addr_has_tag, &[a1, a2, ctx_val], ptr_type),
    };
    builder.ins().jump(merge_block, &[result]);

    builder.switch_to_block(merge_block);
    builder.seal_block(merge_block);
    builder.block_params(merge_block)[0]
}

/// Compile a sub-expression, error-check it, then apply a callback function.
fn compile_with_error_check(
    builder: &mut FunctionBuilder,
    ctx: &mut CodeGenContext,
    h: &HelperSigs,
    inner: &ast::Expr,
    ctx_val: cranelift_codegen::ir::Value,
    ptr_type: Type,
    apply: impl FnOnce(&mut FunctionBuilder, cranelift_codegen::ir::Value, Type) -> cranelift_codegen::ir::Value,
) -> cranelift_codegen::ir::Value {
    let val = compile_expr(builder, ctx, h, inner, ctx_val, ptr_type);

    let merge_block = builder.create_block();
    builder.append_block_param(merge_block, ptr_type);

    let is_err = icall(builder, h.sig_ptr_to_u64, h.addr_is_error, &[val], ptr_type);
    let zero = builder.ins().iconst(types::I64, 0);
    let cmp = builder.ins().icmp(IntCC::NotEqual, is_err, zero);
    let ok_block = builder.create_block();
    let error_block = builder.create_block();
    builder.ins().brif(cmp, error_block, &[], ok_block, &[]);

    builder.switch_to_block(error_block);
    builder.seal_block(error_block);
    let ev = icall(builder, h.sig_void_to_ptr, h.addr_error, &[], ptr_type);
    builder.ins().jump(merge_block, &[ev]);

    builder.switch_to_block(ok_block);
    builder.seal_block(ok_block);
    let result = apply(builder, val, ptr_type);
    builder.ins().jump(merge_block, &[result]);

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
        let val = compile_expr(builder, ctx, h, elem, ctx_val, ptr_type);
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

        let val = compile_expr(builder, ctx, h, val_expr, ctx_val, ptr_type);
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
        let val = compile_expr(builder, ctx, h, arg, ctx_val, ptr_type);
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
