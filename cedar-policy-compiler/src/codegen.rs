/// AArch64 code generator for Cedar policy expressions.
///
/// Compiles Cedar AST expressions into native AArch64 machine code.
/// Uses a stack-machine approach: each expression leaves its result in (x0, x1)
/// where x0=tag and x1=payload (matching RuntimeValue layout).
///
/// Register conventions:
///   x0, x1: current result (tag, payload)
///   x19: pointer to RuntimeCtx (callee-saved)
///   x20-x24: scratch callee-saved registers for temporaries
///   x29: frame pointer
///   x30: link register
///   sp: stack pointer (16-byte aligned)

use crate::asm::*;
use crate::runtime::*;
use cedar_policy_core::ast::{self, BinaryOp, EntityUID, ExprKind, Literal, Pattern, UnaryOp, Var};
use smol_str::SmolStr;
use std::collections::BTreeMap;

pub struct ExprCompiler {
    buf: CodeBuffer,
    /// Stack offset tracking for nested expression evaluation
    stack_depth: i32,
    /// Patterns collected for `like` expressions
    pub patterns: Vec<Pattern>,
    /// Interned strings for extension function names
    pub interned_strings: Vec<String>,
    /// String pool for string literals
    pub string_pool: Vec<SmolStr>,
    /// Heap-pinned EntityUID literals (stable pointers)
    entity_literals: Vec<Box<EntityUID>>,
    /// Heap-pinned SmolStr literals (stable pointers)
    string_literals: Vec<Box<SmolStr>>,
    /// Heap-pinned EntityType literals
    entity_type_literals: Vec<Box<ast::EntityType>>,
}

// Frame layout: we save x19-x24, x29, x30 = 8 registers = 64 bytes
// Plus 16 bytes of scratch area = 80 bytes, rounded up to 96 for alignment
const FRAME_SIZE: i32 = 96;

impl ExprCompiler {
    pub fn new() -> Self {
        Self {
            buf: CodeBuffer::new(),
            stack_depth: 0,
            patterns: Vec::new(),
            interned_strings: Vec::new(),
            string_pool: Vec::new(),
            entity_literals: Vec::new(),
            string_literals: Vec::new(),
            entity_type_literals: Vec::new(),
        }
    }

    /// Compile an expression, producing a callable function and its associated data.
    /// The generated function has signature: extern "C" fn(ctx: *const RuntimeCtx) -> i64
    /// Returns: 1=satisfied (bool true), 0=not-satisfied (bool false), 2=error
    ///
    /// The returned `CompiledCode` must be kept alive as long as the compiled code is executable,
    /// because the machine code contains embedded pointers into the pinned data.
    pub fn compile_condition(mut self, expr: &ast::Expr) -> CompiledCode {
        self.emit_prologue();
        self.emit_expr(expr);
        self.emit_epilogue();
        let code = self.buf.finish();
        CompiledCode {
            code,
            patterns: self.patterns,
            interned_strings: self.interned_strings,
            string_pool: self.string_pool,
            _entity_literals: self.entity_literals,
            _string_literals: self.string_literals,
            _entity_type_literals: self.entity_type_literals,
        }
    }

    fn emit_prologue(&mut self) {
        // Save frame pointer and link register
        self.buf.stp_pre(X29, X30, SP, -FRAME_SIZE);
        // Set up frame pointer
        self.buf.mov_reg(X29, SP);
        // Save callee-saved registers
        self.buf.stp_pre(X19, X20, SP, -16);
        // stack is now at SP-16 from frame
        // Actually, let's use a simpler scheme: pre-allocate the full frame
        // Redo: allocate frame, save everything at known offsets

        // Reset and use a cleaner approach
        self.buf = CodeBuffer::new();

        // SUB SP, SP, #FRAME_SIZE
        self.buf.sub_imm(SP, SP, FRAME_SIZE as u32);
        // STP x29, x30, [SP, #0]
        self.buf.stp_offset(X29, X30, SP, 0);
        // STP x19, x20, [SP, #16]
        self.buf.stp_offset(X19, X20, SP, 16);
        // STP x21, x22, [SP, #32]
        self.buf.stp_offset(X21, X22, SP, 32);
        // STP x23, x24, [SP, #48]
        self.buf.stp_offset(X23, X24, SP, 48);
        // MOV x29, SP (frame pointer)
        // Note: use add_imm since mov_reg(ORR) treats reg 31 as XZR, not SP
        self.buf.add_imm(X29, SP, 0);
        // Save ctx (x0) to x19
        self.buf.mov_reg(X19, X0);
    }

    fn emit_epilogue(&mut self) {
        // x0 = tag, x1 = payload from the expression result.
        // Convert to i64 return value:
        //   if tag == TAG_BOOL && payload == 1 → return 1 (satisfied)
        //   if tag == TAG_BOOL && payload == 0 → return 0 (not satisfied)
        //   else → return 2 (error)

        // Check tag == TAG_BOOL (1)
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let not_bool = self.buf.emit_bcond_placeholder(COND_NE);

        // tag is bool, result = payload (0 or 1)
        self.buf.mov_reg(X0, X1);
        let done = self.buf.emit_branch_placeholder();

        // not a bool → return 2 (error)
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(not_bool, error_label);
        self.buf.movz(X0, 2, 0);

        let end_label = self.buf.current_offset();
        self.buf.patch_branch(done, end_label);

        // Restore callee-saved registers
        self.buf.ldp_offset(X23, X24, SP, 48);
        self.buf.ldp_offset(X21, X22, SP, 32);
        self.buf.ldp_offset(X19, X20, SP, 16);
        self.buf.ldp_offset(X29, X30, SP, 0);
        self.buf.add_imm(SP, SP, FRAME_SIZE as u32);
        self.buf.ret();
    }

    /// Main expression dispatch. Result in (x0=tag, x1=payload).
    fn emit_expr(&mut self, expr: &ast::Expr) {
        match expr.expr_kind() {
            ExprKind::Lit(lit) => self.emit_lit(lit),
            ExprKind::Var(var) => self.emit_var(*var),
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => self.emit_if(test_expr, then_expr, else_expr),
            ExprKind::And { left, right } => self.emit_and(left, right),
            ExprKind::Or { left, right } => self.emit_or(left, right),
            ExprKind::UnaryApp { op, arg } => self.emit_unary(*op, arg),
            ExprKind::BinaryApp { op, arg1, arg2 } => self.emit_binary(*op, arg1, arg2),
            ExprKind::ExtensionFunctionApp { fn_name, args } => {
                self.emit_extension_call(fn_name, args)
            }
            ExprKind::GetAttr { expr, attr } => self.emit_get_attr(expr, attr),
            ExprKind::HasAttr { expr, attr } => self.emit_has_attr(expr, attr),
            ExprKind::Like { expr, pattern } => self.emit_like(expr, pattern),
            ExprKind::Set(elements) => self.emit_set(elements),
            ExprKind::Record(fields) => self.emit_record(fields),
            ExprKind::Is { expr, entity_type } => self.emit_is(expr, entity_type),
            // Error nodes in the AST
            _ => self.emit_error(),
        }
    }

    // ---- Literal emission ----

    fn emit_lit(&mut self, lit: &Literal) {
        match lit {
            Literal::Bool(b) => {
                self.buf.movz(X0, TAG_BOOL as u16, 0);
                self.buf.movz(X1, *b as u16, 0);
            }
            Literal::Long(n) => {
                self.buf.movz(X0, TAG_LONG as u16, 0);
                self.buf.mov_imm64(X1, *n as u64);
            }
            Literal::String(s) => {
                // Store the string and load its pointer
                let idx = self.intern_string_literal(s.clone());
                let ptr = &*self.string_literals[idx] as *const SmolStr as u64;
                self.buf.movz(X0, TAG_STRING as u16, 0);
                self.buf.mov_imm64(X1, ptr);
            }
            Literal::EntityUID(uid) => {
                let idx = self.intern_entity_literal((**uid).clone());
                let ptr = &*self.entity_literals[idx] as *const EntityUID as u64;
                self.buf.movz(X0, TAG_ENTITY as u16, 0);
                self.buf.mov_imm64(X1, ptr);
            }
        }
    }

    // ---- Variable emission ----

    fn emit_var(&mut self, var: Var) {
        // Call rt_get_{principal,action,resource,context}(ctx)
        // ctx is in x19, move to x0 for the call
        self.buf.mov_reg(X0, X19);
        let func_ptr: u64 = match var {
            Var::Principal => rt_get_principal as u64,
            Var::Action => rt_get_action as u64,
            Var::Resource => rt_get_resource as u64,
            Var::Context => rt_get_context as u64,
        };
        self.buf.mov_imm64(X8, func_ptr);
        self.buf.blr(X8);
        // Result is in (x0, x1)
    }

    // ---- Control flow ----

    fn emit_if(&mut self, test: &ast::Expr, then_br: &ast::Expr, else_br: &ast::Expr) {
        // Evaluate test
        self.emit_expr(test);
        // Check tag == BOOL
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let not_bool = self.buf.emit_bcond_placeholder(COND_NE);
        // If false (payload==0), jump to else
        let false_branch = self.buf.emit_cbz_placeholder(X1);

        // Then branch
        self.emit_expr(then_br);
        let skip_else = self.buf.emit_branch_placeholder();

        // Else branch
        let else_label = self.buf.current_offset();
        self.buf.patch_branch(false_branch, else_label);
        self.emit_expr(else_br);
        let skip_error = self.buf.emit_branch_placeholder();

        // Error: test was not bool
        let err_label = self.buf.current_offset();
        self.buf.patch_branch(not_bool, err_label);
        self.emit_error();

        let end = self.buf.current_offset();
        self.buf.patch_branch(skip_else, end);
        self.buf.patch_branch(skip_error, end);
    }

    fn emit_and(&mut self, left: &ast::Expr, right: &ast::Expr) {
        // Cedar AND semantics:
        // 1. Evaluate left
        // 2. If left is not Bool → error
        // 3. If left is false → result is false (short circuit)
        // 4. Evaluate right
        // 5. If right is not Bool → error
        // 6. Result is right's value

        self.emit_expr(left);
        // Check tag == BOOL
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let not_bool = self.buf.emit_bcond_placeholder(COND_NE);
        // If payload == 0 (false), short circuit
        let short_circuit = self.buf.emit_cbz_placeholder(X1);

        // Left is true, evaluate right
        self.emit_expr(right);
        // Check right is bool
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let right_not_bool = self.buf.emit_bcond_placeholder(COND_NE);
        // Result is in (x0, x1)
        let done = self.buf.emit_branch_placeholder();

        // Short circuit: left was false, return false
        let sc_label = self.buf.current_offset();
        self.buf.patch_branch(short_circuit, sc_label);
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        self.buf.movz(X1, 0, 0);
        let done2 = self.buf.emit_branch_placeholder();

        // Error: not bool
        let err_label = self.buf.current_offset();
        self.buf.patch_branch(not_bool, err_label);
        self.buf.patch_branch(right_not_bool, err_label);
        self.emit_error();
        let done3 = self.buf.emit_branch_placeholder();

        let end = self.buf.current_offset();
        self.buf.patch_branch(done, end);
        self.buf.patch_branch(done2, end);
        self.buf.patch_branch(done3, end);
    }

    fn emit_or(&mut self, left: &ast::Expr, right: &ast::Expr) {
        // Cedar OR semantics: like AND but short-circuits on true
        self.emit_expr(left);
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let not_bool = self.buf.emit_bcond_placeholder(COND_NE);
        // If payload != 0 (true), short circuit
        let short_circuit = self.buf.emit_cbnz_placeholder(X1);

        // Left is false, evaluate right
        self.emit_expr(right);
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let right_not_bool = self.buf.emit_bcond_placeholder(COND_NE);
        let done = self.buf.emit_branch_placeholder();

        // Short circuit: left was true
        let sc_label = self.buf.current_offset();
        self.buf.patch_branch(short_circuit, sc_label);
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        self.buf.movz(X1, 1, 0);
        let done2 = self.buf.emit_branch_placeholder();

        // Error
        let err_label = self.buf.current_offset();
        self.buf.patch_branch(not_bool, err_label);
        self.buf.patch_branch(right_not_bool, err_label);
        self.emit_error();
        let done3 = self.buf.emit_branch_placeholder();

        let end = self.buf.current_offset();
        self.buf.patch_branch(done, end);
        self.buf.patch_branch(done2, end);
        self.buf.patch_branch(done3, end);
    }

    // ---- Unary operations ----

    fn emit_unary(&mut self, op: UnaryOp, arg: &ast::Expr) {
        match op {
            UnaryOp::Not => self.emit_not_inline(arg),
            UnaryOp::Neg => self.emit_neg_inline(arg),
            UnaryOp::IsEmpty => {
                self.emit_expr(arg);
                self.call_fn2(rt_is_empty as u64);
            }
        }
    }

    // ---- Binary operations ----

    fn emit_binary(&mut self, op: BinaryOp, left: &ast::Expr, right: &ast::Expr) {
        match op {
            BinaryOp::Eq => self.emit_eq_inline(left, right),
            BinaryOp::Less => self.emit_less_inline(left, right),
            BinaryOp::LessEq => self.emit_less_eq_inline(left, right),
            BinaryOp::Add => self.emit_add_inline(left, right),
            BinaryOp::Sub => self.emit_sub_inline(left, right),
            BinaryOp::Mul => self.emit_mul_inline(left, right),
            BinaryOp::In => self.emit_binary_with_ctx(left, right, rt_in as u64),
            BinaryOp::Contains => self.emit_binary_with_ctx(left, right, rt_contains as u64),
            BinaryOp::ContainsAll => self.emit_binary_4arg(left, right, rt_contains_all as u64),
            BinaryOp::ContainsAny => self.emit_binary_4arg(left, right, rt_contains_any as u64),
            BinaryOp::GetTag => self.emit_binary_with_ctx(left, right, rt_get_tag as u64),
            BinaryOp::HasTag => self.emit_binary_with_ctx(left, right, rt_has_tag as u64),
        }
    }

    /// Emit a binary operation that takes (ctx, lt, lp, rt, rp).
    fn emit_binary_with_ctx(&mut self, left: &ast::Expr, right: &ast::Expr, func: u64) {
        // Evaluate left, save to stack
        self.emit_expr(left);
        self.push_result();

        // Evaluate right, result in (x0, x1)
        self.emit_expr(right);

        // Pop left into (x2, x3), right is in (x0, x1)
        self.pop_to_x2_x3();

        // Set up args: ctx=x0_new, lt=x1_new, lp=x2_new, rt=x3_new, rp=x4_new
        // Move: right (x0,x1) → (x3,x4), left (x2,x3) → (x1,x2), ctx x19 → x0
        self.buf.mov_reg(X5, X1);  // right payload → x5
        self.buf.mov_reg(X4, X0);  // right tag → x4
        self.buf.mov_reg(X1, X2);  // left tag → x1
        self.buf.mov_reg(X2, X3);  // left payload → x2
        self.buf.mov_reg(X3, X4);  // right tag → x3
        self.buf.mov_reg(X4, X5);  // right payload → x4
        self.buf.mov_reg(X0, X19); // ctx → x0

        self.buf.mov_imm64(X8, func);
        self.buf.blr(X8);
    }

    /// Emit a binary operation that takes (lt, lp, rt, rp) — no ctx.
    fn emit_binary_4arg(&mut self, left: &ast::Expr, right: &ast::Expr, func: u64) {
        // Evaluate left, save to stack
        self.emit_expr(left);
        self.push_result();

        // Evaluate right
        self.emit_expr(right);

        // Pop left into (x2, x3)
        self.pop_to_x2_x3();

        // Args: lt=x2, lp=x3 (left), rt=x0, rp=x1 (right)
        // Rearrange to: x0=lt, x1=lp, x2=rt, x3=rp
        self.buf.mov_reg(X4, X0); // right tag → x4
        self.buf.mov_reg(X5, X1); // right payload → x5
        self.buf.mov_reg(X0, X2); // left tag → x0
        self.buf.mov_reg(X1, X3); // left payload → x1
        self.buf.mov_reg(X2, X4); // right tag → x2
        self.buf.mov_reg(X3, X5); // right payload → x3

        self.buf.mov_imm64(X8, func);
        self.buf.blr(X8);
    }

    // ---- Inlined unary operations ----

    /// Inline NOT: bool → bool. Tag check + EOR, no function call.
    fn emit_not_inline(&mut self, arg: &ast::Expr) {
        self.emit_expr(arg);
        // x0 = tag, x1 = payload
        self.buf.cmp_imm(X0, TAG_BOOL as u32);
        let br_error = self.buf.emit_bcond_placeholder(COND_NE);
        // Tag is BOOL — flip payload bit 0
        self.buf.eor_imm_one(X1, X1);
        // x0 is still TAG_BOOL from the check
        let br_done = self.buf.emit_branch_placeholder();
        // Error
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(br_error, error_label);
        self.emit_error();
        let done_label = self.buf.current_offset();
        self.buf.patch_branch(br_done, done_label);
    }

    /// Inline NEG: long → long. Tag check + SUBS from zero, overflow check.
    fn emit_neg_inline(&mut self, arg: &ast::Expr) {
        self.emit_expr(arg);
        // x0 = tag, x1 = payload
        self.buf.cmp_imm(X0, TAG_LONG as u32);
        let br_error_tag = self.buf.emit_bcond_placeholder(COND_NE);
        // Negate: x1 = 0 - x1, setting flags
        self.buf.subs_reg(X1, XZR, X1);
        let br_error_ovf = self.buf.emit_bcond_placeholder(COND_VS);
        // x0 is still TAG_LONG from the check
        let br_done = self.buf.emit_branch_placeholder();
        // Error
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(br_error_tag, error_label);
        self.buf.patch_branch(br_error_ovf, error_label);
        self.emit_error();
        let done_label = self.buf.current_offset();
        self.buf.patch_branch(br_done, done_label);
    }

    // ---- Inlined binary arithmetic ----

    /// Evaluate binary operands: left → stack, right → (x0,x1), pop left → (x2,x3).
    fn emit_binary_operands(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_expr(left);
        self.push_result();
        self.emit_expr(right);
        self.pop_to_x2_x3();
        // Now: left=(x2=tag, x3=payload), right=(x0=tag, x1=payload)
    }

    /// Inline ADD: long + long → long. Tag checks + ADDS with overflow detection.
    fn emit_add_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_binary_operands(left, right);
        // left=(x2,x3), right=(x0,x1)
        self.buf.cmp_imm(X2, TAG_LONG as u32);
        let br_err1 = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.cmp_imm(X0, TAG_LONG as u32);
        let br_err2 = self.buf.emit_bcond_placeholder(COND_NE);
        // Add payloads with overflow check
        self.buf.adds_reg(X1, X3, X1);
        let br_err_ovf = self.buf.emit_bcond_placeholder(COND_VS);
        self.buf.movz(X0, TAG_LONG as u16, 0);
        let br_done = self.buf.emit_branch_placeholder();
        // Error
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(br_err1, error_label);
        self.buf.patch_branch(br_err2, error_label);
        self.buf.patch_branch(br_err_ovf, error_label);
        self.emit_error();
        let done_label = self.buf.current_offset();
        self.buf.patch_branch(br_done, done_label);
    }

    /// Inline SUB: long - long → long. Tag checks + SUBS with overflow detection.
    fn emit_sub_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_binary_operands(left, right);
        self.buf.cmp_imm(X2, TAG_LONG as u32);
        let br_err1 = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.cmp_imm(X0, TAG_LONG as u32);
        let br_err2 = self.buf.emit_bcond_placeholder(COND_NE);
        // Subtract: left_payload - right_payload
        self.buf.subs_reg(X1, X3, X1);
        let br_err_ovf = self.buf.emit_bcond_placeholder(COND_VS);
        self.buf.movz(X0, TAG_LONG as u16, 0);
        let br_done = self.buf.emit_branch_placeholder();
        // Error
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(br_err1, error_label);
        self.buf.patch_branch(br_err2, error_label);
        self.buf.patch_branch(br_err_ovf, error_label);
        self.emit_error();
        let done_label = self.buf.current_offset();
        self.buf.patch_branch(br_done, done_label);
    }

    /// Inline MUL: long * long → long. Tag checks + MUL/SMULH overflow detection.
    fn emit_mul_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_binary_operands(left, right);
        self.buf.cmp_imm(X2, TAG_LONG as u32);
        let br_err1 = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.cmp_imm(X0, TAG_LONG as u32);
        let br_err2 = self.buf.emit_bcond_placeholder(COND_NE);
        // Save right payload (x1 will be overwritten by mul)
        self.buf.mov_reg(X8, X1);
        // Low 64 bits of product
        self.buf.mul_reg(X1, X3, X8);
        // High 64 bits (signed) for overflow check
        self.buf.smulh(X9, X3, X8);
        // Sign-extend the low result to compare with high
        self.buf.asr_imm(X10, X1, 63);
        // If high ≠ sign extension of low → overflow
        self.buf.cmp_reg(X9, X10);
        let br_err_ovf = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.movz(X0, TAG_LONG as u16, 0);
        let br_done = self.buf.emit_branch_placeholder();
        // Error
        let error_label = self.buf.current_offset();
        self.buf.patch_branch(br_err1, error_label);
        self.buf.patch_branch(br_err2, error_label);
        self.buf.patch_branch(br_err_ovf, error_label);
        self.emit_error();
        let done_label = self.buf.current_offset();
        self.buf.patch_branch(br_done, done_label);
    }

    // ---- Inlined comparison operations (fast path + fallback) ----

    /// Helper: emit the slow-path call for binary ops with ctx.
    /// Assumes left=(x2,x3), right=(x0,x1). Calls func(ctx, lt, lp, rt, rp).
    fn emit_slow_call_with_ctx(&mut self, func: u64) {
        self.buf.mov_reg(X4, X1);   // right payload → x4 (final)
        self.buf.mov_reg(X5, X0);   // right tag → x5 (temp)
        self.buf.mov_reg(X1, X2);   // left tag → x1 (final)
        self.buf.mov_reg(X2, X3);   // left payload → x2 (final)
        self.buf.mov_reg(X3, X5);   // right tag → x3 (final)
        self.buf.mov_reg(X0, X19);  // ctx → x0 (final)
        self.buf.mov_imm64(X8, func);
        self.buf.blr(X8);
    }

    /// Inline EQ: fast path for payload-comparable tags, fallback to rt_eq.
    fn emit_eq_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_binary_operands(left, right);
        // left=(x2,x3), right=(x0,x1)

        // Check if tags are equal
        self.buf.cmp_reg(X2, X0);
        let br_diff_tags = self.buf.emit_bcond_placeholder(COND_NE);

        // Same tag — check if payload-comparable
        self.buf.cmp_imm(X2, TAG_BOOL as u32);
        let br_cmp1 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_LONG as u32);
        let br_cmp2 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_DECIMAL as u32);
        let br_cmp3 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_DATETIME as u32);
        let br_cmp4 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_DURATION as u32);
        let br_cmp5 = self.buf.emit_bcond_placeholder(COND_EQ);
        // Non-payload-comparable same tag (String, Entity, Set, Record, Ext, IpAddr)
        let br_slow1 = self.buf.emit_branch_placeholder();

        // cmp_payload: compare payloads directly
        let cmp_payload = self.buf.current_offset();
        self.buf.patch_branch(br_cmp1, cmp_payload);
        self.buf.patch_branch(br_cmp2, cmp_payload);
        self.buf.patch_branch(br_cmp3, cmp_payload);
        self.buf.patch_branch(br_cmp4, cmp_payload);
        self.buf.patch_branch(br_cmp5, cmp_payload);
        self.buf.cmp_reg(X3, X1);
        self.buf.cset(X1, COND_EQ);
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        let br_done1 = self.buf.emit_branch_placeholder();

        // diff_tags: different tags
        let diff_tags = self.buf.current_offset();
        self.buf.patch_branch(br_diff_tags, diff_tags);
        // If either is error, delegate to runtime
        self.buf.cmp_imm(X2, TAG_ERROR as u32);
        let br_slow2 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X0, TAG_ERROR as u32);
        let br_slow3 = self.buf.emit_bcond_placeholder(COND_EQ);
        // Different non-error tags → false
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        self.buf.movz(X1, 0, 0);
        let br_done2 = self.buf.emit_branch_placeholder();

        // slow_call: delegate to rt_eq
        let slow_call = self.buf.current_offset();
        self.buf.patch_branch(br_slow1, slow_call);
        self.buf.patch_branch(br_slow2, slow_call);
        self.buf.patch_branch(br_slow3, slow_call);
        self.emit_slow_call_with_ctx(rt_eq as u64);
        // Falls through to done

        let done = self.buf.current_offset();
        self.buf.patch_branch(br_done1, done);
        self.buf.patch_branch(br_done2, done);
    }

    /// Inline LESS: fast path for Long and i64-comparable tags, fallback to rt_less.
    fn emit_less_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_less_or_less_eq(left, right, COND_LT, rt_less as u64);
    }

    /// Inline LESS_EQ: fast path for Long and i64-comparable tags, fallback to rt_less_eq.
    fn emit_less_eq_inline(&mut self, left: &ast::Expr, right: &ast::Expr) {
        self.emit_less_or_less_eq(left, right, COND_LE, rt_less_eq as u64);
    }

    /// Shared implementation for Less and LessEq — only the condition code differs.
    fn emit_less_or_less_eq(&mut self, left: &ast::Expr, right: &ast::Expr, cond: u32, fallback: u64) {
        self.emit_binary_operands(left, right);
        // left=(x2,x3), right=(x0,x1)

        // Fast path: both TAG_LONG (most common)
        self.buf.cmp_imm(X2, TAG_LONG as u32);
        let br_check_custom = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.cmp_imm(X0, TAG_LONG as u32);
        let br_check_custom2 = self.buf.emit_bcond_placeholder(COND_NE);
        // Both Long — signed compare payloads
        self.buf.cmp_reg(X3, X1);
        self.buf.cset(X1, cond);
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        let br_done1 = self.buf.emit_branch_placeholder();

        // check_custom: check for other i64-comparable types
        let check_custom = self.buf.current_offset();
        self.buf.patch_branch(br_check_custom, check_custom);
        self.buf.patch_branch(br_check_custom2, check_custom);
        // Tags must match
        self.buf.cmp_reg(X2, X0);
        let br_slow1 = self.buf.emit_bcond_placeholder(COND_NE);
        self.buf.cmp_imm(X2, TAG_DECIMAL as u32);
        let br_i64_cmp1 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_DATETIME as u32);
        let br_i64_cmp2 = self.buf.emit_bcond_placeholder(COND_EQ);
        self.buf.cmp_imm(X2, TAG_DURATION as u32);
        let br_i64_cmp3 = self.buf.emit_bcond_placeholder(COND_EQ);
        let br_slow2 = self.buf.emit_branch_placeholder();

        // do_i64_cmp: compare payloads as signed i64
        let do_i64_cmp = self.buf.current_offset();
        self.buf.patch_branch(br_i64_cmp1, do_i64_cmp);
        self.buf.patch_branch(br_i64_cmp2, do_i64_cmp);
        self.buf.patch_branch(br_i64_cmp3, do_i64_cmp);
        self.buf.cmp_reg(X3, X1);
        self.buf.cset(X1, cond);
        self.buf.movz(X0, TAG_BOOL as u16, 0);
        let br_done2 = self.buf.emit_branch_placeholder();

        // slow_call: delegate to runtime
        let slow_call = self.buf.current_offset();
        self.buf.patch_branch(br_slow1, slow_call);
        self.buf.patch_branch(br_slow2, slow_call);
        self.emit_slow_call_with_ctx(fallback);
        // Falls through to done

        let done = self.buf.current_offset();
        self.buf.patch_branch(br_done1, done);
        self.buf.patch_branch(br_done2, done);
    }

    // ---- Attribute operations ----

    fn emit_get_attr(&mut self, expr: &ast::Expr, attr: &SmolStr) {
        self.emit_expr(expr);
        let attr_idx = self.intern_string_literal(attr.clone());
        let attr_ptr = &*self.string_literals[attr_idx] as *const SmolStr as u64;
        // rt_get_attr(ctx, tag, payload, attr_ptr)
        self.buf.mov_reg(X2, X1); // payload -> x2
        self.buf.mov_reg(X1, X0); // tag -> x1
        self.buf.mov_reg(X0, X19); // ctx -> x0
        self.buf.mov_imm64(X3, attr_ptr);
        self.buf.mov_imm64(X8, rt_get_attr as u64);
        self.buf.blr(X8);
    }

    fn emit_has_attr(&mut self, expr: &ast::Expr, attr: &SmolStr) {
        self.emit_expr(expr);
        let attr_idx = self.intern_string_literal(attr.clone());
        let attr_ptr = &*self.string_literals[attr_idx] as *const SmolStr as u64;
        // rt_has_attr(ctx, tag, payload, attr_ptr)
        self.buf.mov_reg(X2, X1);
        self.buf.mov_reg(X1, X0);
        self.buf.mov_reg(X0, X19);
        self.buf.mov_imm64(X3, attr_ptr);
        self.buf.mov_imm64(X8, rt_has_attr as u64);
        self.buf.blr(X8);
    }

    // ---- Like (pattern matching) ----

    fn emit_like(&mut self, expr: &ast::Expr, pattern: &Pattern) {
        self.emit_expr(expr);
        let pattern_idx = self.patterns.len();
        self.patterns.push(pattern.clone());
        // rt_like(ctx, tag, payload, pattern_idx)
        self.buf.mov_reg(X2, X1);
        self.buf.mov_reg(X1, X0);
        self.buf.mov_reg(X0, X19);
        self.buf.mov_imm64(X3, pattern_idx as u64);
        self.buf.mov_imm64(X8, rt_like as u64);
        self.buf.blr(X8);
    }

    // ---- Is (entity type check) ----

    fn emit_is(&mut self, expr: &ast::Expr, entity_type: &ast::EntityType) {
        self.emit_expr(expr);
        let idx = self.entity_type_literals.len();
        self.entity_type_literals.push(Box::new(entity_type.clone()));
        let type_ptr = &*self.entity_type_literals[idx] as *const ast::EntityType as u64;
        // rt_is_entity_type(tag, payload, type_ptr)
        self.buf.mov_imm64(X2, type_ptr);
        self.buf.mov_imm64(X8, rt_is_entity_type as u64);
        self.buf.blr(X8);
    }

    // ---- Set construction ----

    fn emit_set(&mut self, elements: &[ast::Expr]) {
        let count = elements.len();
        if count == 0 {
            self.buf.mov_reg(X0, X19);
            self.buf.movz(X1, 0, 0);
            self.buf.movz(X2, 0, 0);
            self.buf.movz(X3, 0, 0);
            self.buf.mov_imm64(X8, rt_make_set as u64);
            self.buf.blr(X8);
            return;
        }
        let array_size = (count * 8 + 15) & !15; // 16-byte aligned
        let total_stack = array_size * 2;
        self.buf.sub_imm(SP, SP, total_stack as u32);
        for (i, elem) in elements.iter().enumerate() {
            self.emit_expr(elem);
            self.buf.str_imm(X0, SP, (i * 8) as u32);
            self.buf.str_imm(X1, SP, (array_size + i * 8) as u32);
        }
        // rt_make_set(ctx, tags, payloads, count)
        // Note: mov_reg cannot move SP (register 31 is XZR in ORR).
        // Use add_imm(Xd, SP, 0) instead.
        self.buf.mov_reg(X0, X19);
        self.buf.add_imm(X1, SP, 0);
        self.buf.add_imm(X2, SP, array_size as u32);
        self.buf.mov_imm64(X3, count as u64);
        self.buf.mov_imm64(X8, rt_make_set as u64);
        self.buf.blr(X8);
        self.buf.add_imm(SP, SP, total_stack as u32);
    }

    // ---- Record construction ----

    fn emit_record(&mut self, fields: &BTreeMap<SmolStr, ast::Expr>) {
        let count = fields.len();
        if count == 0 {
            self.buf.mov_reg(X0, X19);
            self.buf.movz(X1, 0, 0);
            self.buf.movz(X2, 0, 0);
            self.buf.movz(X3, 0, 0);
            self.buf.movz(X4, 0, 0);
            self.buf.mov_imm64(X8, rt_make_record as u64);
            self.buf.blr(X8);
            return;
        }
        let array_size = (count * 8 + 15) & !15;
        let total_stack = array_size * 3;
        self.buf.sub_imm(SP, SP, total_stack as u32);
        for (i, (key, val_expr)) in fields.iter().enumerate() {
            let key_idx = self.intern_string_literal(key.clone());
            let key_ptr = &*self.string_literals[key_idx] as *const SmolStr as u64;
            self.buf.mov_imm64(X8, key_ptr);
            self.buf.str_imm(X8, SP, (i * 8) as u32);
            self.emit_expr(val_expr);
            self.buf.str_imm(X0, SP, (array_size + i * 8) as u32);
            self.buf.str_imm(X1, SP, (2 * array_size + i * 8) as u32);
        }
        // rt_make_record(ctx, keys, tags, payloads, count)
        // Note: use add_imm to read SP (mov_reg treats reg 31 as XZR)
        self.buf.mov_reg(X0, X19);
        self.buf.add_imm(X1, SP, 0);
        self.buf.add_imm(X2, SP, array_size as u32);
        self.buf.add_imm(X3, SP, (2 * array_size) as u32);
        self.buf.mov_imm64(X4, count as u64);
        self.buf.mov_imm64(X8, rt_make_record as u64);
        self.buf.blr(X8);
        self.buf.add_imm(SP, SP, total_stack as u32);
    }

    // ---- Extension function calls ----

    fn emit_extension_call(&mut self, fn_name: &ast::Name, args: &[ast::Expr]) {
        let name = fn_name.to_string();
        match (name.as_str(), args.len()) {
            // IP address
            ("ip", 1) => { self.emit_expr(&args[0]); self.emit_call_ctx_tag_payload(rt_ext_ip as u64); }
            ("isIpv4", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_is_ipv4 as u64); }
            ("isIpv6", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_is_ipv6 as u64); }
            ("isLoopback", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_is_loopback as u64); }
            ("isMulticast", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_is_multicast as u64); }
            ("isInRange", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_is_in_range as u64),
            // Decimal
            ("decimal", 1) => { self.emit_expr(&args[0]); self.emit_call_ctx_tag_payload(rt_ext_decimal as u64); }
            ("lessThan", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_less_than as u64),
            ("lessThanOrEqual", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_less_than_or_equal as u64),
            ("greaterThan", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_greater_than as u64),
            ("greaterThanOrEqual", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_greater_than_or_equal as u64),
            // DateTime / Duration
            ("datetime", 1) => { self.emit_expr(&args[0]); self.emit_call_ctx_tag_payload(rt_ext_datetime as u64); }
            ("duration", 1) => { self.emit_expr(&args[0]); self.emit_call_ctx_tag_payload(rt_ext_duration as u64); }
            ("offset", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_offset as u64),
            ("durationSince", 2) => self.emit_binary_4arg(&args[0], &args[1], rt_ext_duration_since as u64),
            ("toDate", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_date as u64); }
            ("toTime", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_time as u64); }
            ("toMilliseconds", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_milliseconds as u64); }
            ("toSeconds", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_seconds as u64); }
            ("toMinutes", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_minutes as u64); }
            ("toHours", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_hours as u64); }
            ("toDays", 1) => { self.emit_expr(&args[0]); self.call_fn2(rt_ext_to_days as u64); }
            // Fallback for unknown extensions
            _ => self.emit_generic_extension_call(fn_name, args),
        }
    }

    /// Call func(ctx, tag, payload) where result is in (x0=tag, x1=payload) and ctx is in x19.
    fn emit_call_ctx_tag_payload(&mut self, func: u64) {
        self.buf.mov_reg(X2, X1); // payload -> x2
        self.buf.mov_reg(X1, X0); // tag -> x1
        self.buf.mov_reg(X0, X19); // ctx -> x0
        self.buf.mov_imm64(X8, func);
        self.buf.blr(X8);
    }

    /// Generic fallback for unknown extension functions — packs args into stack arrays.
    fn emit_generic_extension_call(&mut self, fn_name: &ast::Name, args: &[ast::Expr]) {
        let name_str = fn_name.to_string();
        let fn_name_idx = self.intern_extension_name(name_str);
        let count = args.len();
        if count == 0 {
            self.buf.mov_reg(X0, X19);
            self.buf.mov_imm64(X1, fn_name_idx as u64);
            self.buf.movz(X2, 0, 0);
            self.buf.movz(X3, 0, 0);
            self.buf.movz(X4, 0, 0);
            self.buf.mov_imm64(X8, rt_call_extension as u64);
            self.buf.blr(X8);
            return;
        }
        let array_size = (count * 8 + 15) & !15;
        let total_stack = array_size * 2;
        self.buf.sub_imm(SP, SP, total_stack as u32);
        for (i, arg) in args.iter().enumerate() {
            self.emit_expr(arg);
            self.buf.str_imm(X0, SP, (i * 8) as u32);
            self.buf.str_imm(X1, SP, (array_size + i * 8) as u32);
        }
        // rt_call_extension(ctx, fn_name_idx, args_tags, args_payloads, n_args)
        // Note: use add_imm to read SP (mov_reg treats reg 31 as XZR)
        self.buf.mov_reg(X0, X19);
        self.buf.mov_imm64(X1, fn_name_idx as u64);
        self.buf.add_imm(X2, SP, 0);
        self.buf.add_imm(X3, SP, array_size as u32);
        self.buf.mov_imm64(X4, count as u64);
        self.buf.mov_imm64(X8, rt_call_extension as u64);
        self.buf.blr(X8);
        self.buf.add_imm(SP, SP, total_stack as u32);
    }

    // ---- Error emission ----

    fn emit_error(&mut self) {
        self.buf.movz(X0, TAG_ERROR as u16, 0);
        self.buf.movz(X1, 0, 0);
    }

    // ---- Stack helpers ----

    /// Push current result (x0, x1) onto the stack.
    fn push_result(&mut self) {
        self.buf.sub_imm(SP, SP, 16);
        self.buf.stp_offset(X0, X1, SP, 0);
        self.stack_depth += 16;
    }

    /// Pop from stack into (x2, x3).
    fn pop_to_x2_x3(&mut self) {
        self.buf.ldp_offset(X2, X3, SP, 0);
        self.buf.add_imm(SP, SP, 16);
        self.stack_depth -= 16;
    }

    // ---- Helper to call a fn(tag, payload) -> RuntimeValue ----

    fn call_fn2(&mut self, func: u64) {
        // Args already in x0 (tag), x1 (payload)
        self.buf.mov_imm64(X8, func);
        self.buf.blr(X8);
    }

    // ---- Interning helpers ----

    fn intern_string_literal(&mut self, s: SmolStr) -> usize {
        // Check for existing
        for (i, existing) in self.string_literals.iter().enumerate() {
            if **existing == s {
                return i;
            }
        }
        let idx = self.string_literals.len();
        self.string_literals.push(Box::new(s));
        idx
    }

    fn intern_entity_literal(&mut self, uid: EntityUID) -> usize {
        for (i, existing) in self.entity_literals.iter().enumerate() {
            if **existing == uid {
                return i;
            }
        }
        let idx = self.entity_literals.len();
        self.entity_literals.push(Box::new(uid));
        idx
    }

    fn intern_extension_name(&mut self, name: String) -> usize {
        for (i, existing) in self.interned_strings.iter().enumerate() {
            if *existing == name {
                return i;
            }
        }
        let idx = self.interned_strings.len();
        self.interned_strings.push(name);
        idx
    }
}

/// Compiled code with its associated pinned data.
/// The machine code contains embedded pointers into the pinned data fields,
/// so this struct must be kept alive as long as the code is executable.
pub struct CompiledCode {
    pub code: Vec<u8>,
    pub patterns: Vec<Pattern>,
    pub interned_strings: Vec<String>,
    pub string_pool: Vec<SmolStr>,
    // These hold heap-pinned data whose addresses are embedded in the machine code.
    pub _entity_literals: Vec<Box<EntityUID>>,
    pub _string_literals: Vec<Box<SmolStr>>,
    pub _entity_type_literals: Vec<Box<ast::EntityType>>,
}

// Add STP/LDP with unsigned offset to CodeBuffer
impl CodeBuffer {
    /// STP Xt1, Xt2, [Xn, #offset] (signed offset, 8-byte units)
    pub fn stp_offset(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        debug_assert!(offset % 8 == 0);
        let imm7 = ((offset / 8) as u32) & 0x7F;
        // opc=10, 101, type=0, L=0, signed offset (10), imm7, rt2, rn, rt1
        let inst = (0b10 << 30) | (0b101 << 27) | (0b0 << 26) | (0b010 << 23) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
        self.emit_u32(inst);
    }

    /// LDP Xt1, Xt2, [Xn, #offset] (signed offset, 8-byte units)
    pub fn ldp_offset(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        debug_assert!(offset % 8 == 0);
        let imm7 = ((offset / 8) as u32) & 0x7F;
        // opc=10, 101, type=0, L=1, signed offset (10), imm7, rt2, rn, rt1
        let inst = (0b10 << 30) | (0b101 << 27) | (0b0 << 26) | (0b010 << 23) | (1 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1;
        self.emit_u32(inst);
    }
}
