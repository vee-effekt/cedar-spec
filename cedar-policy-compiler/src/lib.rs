use std::collections::HashMap;
use std::fmt;
use std::process::Command;

use cedar_policy_core::ast::{self, BinaryOp, ExprKind, Literal, UnaryOp, Var};

#[derive(Debug)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<std::io::Error> for CompileError {
    fn from(e: std::io::Error) -> Self {
        CompileError(format!("IO error: {}", e))
    }
}

pub struct CompiledConditions {
    pub wasm_bytes: Vec<u8>,
    pub patterns: Vec<ast::Pattern>,
    pub condition_count: usize,
}

struct CodeGenContext {
    strings: Vec<u8>,
    string_map: HashMap<String, (usize, usize)>,
    patterns: Vec<ast::Pattern>,
    var_counter: usize,
}

impl CodeGenContext {
    fn new() -> Self {
        Self {
            strings: Vec::new(),
            string_map: HashMap::new(),
            patterns: Vec::new(),
            var_counter: 0,
        }
    }

    fn fresh_var(&mut self) -> String {
        let v = format!("v{}", self.var_counter);
        self.var_counter += 1;
        v
    }

    fn intern_string(&mut self, s: &str) -> (usize, usize) {
        if let Some(&pair) = self.string_map.get(s) {
            return pair;
        }
        let offset = self.strings.len();
        self.strings.extend_from_slice(s.as_bytes());
        let len = s.len();
        self.string_map.insert(s.to_string(), (offset, len));
        (offset, len)
    }

    fn register_pattern(&mut self, pattern: &ast::Pattern) -> usize {
        let id = self.patterns.len();
        self.patterns.push(pattern.clone());
        id
    }
}

/// Format a string pool pointer expression: sp(offset)
fn sp(offset: usize) -> String {
    format!("sp({})", offset)
}

fn compile_expr(expr: &ast::Expr, ctx: &mut CodeGenContext) -> String {
    match expr.expr_kind() {
        ExprKind::Lit(lit) => match lit {
            Literal::Bool(b) => {
                let v = if *b { 1 } else { 0 };
                format!("host_lit_bool({})", v)
            }
            Literal::Long(i) => {
                format!("host_lit_long({}i64)", i)
            }
            Literal::String(s) => {
                let (off, len) = ctx.intern_string(s.as_str());
                format!("host_lit_string({}, {})", sp(off), len)
            }
            Literal::EntityUID(uid) => {
                let type_str = uid.entity_type().to_string();
                let id_str = uid.eid().as_ref().to_string();
                let (to, tl) = ctx.intern_string(&type_str);
                let (io, il) = ctx.intern_string(&id_str);
                format!("host_lit_entity({}, {}, {}, {})", sp(to), tl, sp(io), il)
            }
        },

        ExprKind::Var(var) => match var {
            Var::Principal => "host_var_principal()".to_string(),
            Var::Action => "host_var_action()".to_string(),
            Var::Resource => "host_var_resource()".to_string(),
            Var::Context => "host_var_context()".to_string(),
        },

        ExprKind::And { left, right } => {
            let lvar = ctx.fresh_var();
            let rvar = ctx.fresh_var();
            let left_code = compile_expr(left, ctx);
            let right_code = compile_expr(right, ctx);
            format!(
                "{{ let {lv} = {lc}; if host_is_error({lv}) != 0 {{ 0 }} else if host_is_bool({lv}) == 0 {{ 0 }} else if host_get_bool({lv}) == 0 {{ host_lit_bool(0) }} else {{ let {rv} = {rc}; if host_is_error({rv}) != 0 {{ 0 }} else if host_is_bool({rv}) == 0 {{ 0 }} else {{ {rv} }} }} }}",
                lv = lvar, lc = left_code, rv = rvar, rc = right_code,
            )
        }

        ExprKind::Or { left, right } => {
            let lvar = ctx.fresh_var();
            let rvar = ctx.fresh_var();
            let left_code = compile_expr(left, ctx);
            let right_code = compile_expr(right, ctx);
            format!(
                "{{ let {lv} = {lc}; if host_is_error({lv}) != 0 {{ 0 }} else if host_is_bool({lv}) == 0 {{ 0 }} else if host_get_bool({lv}) != 0 {{ host_lit_bool(1) }} else {{ let {rv} = {rc}; if host_is_error({rv}) != 0 {{ 0 }} else if host_is_bool({rv}) == 0 {{ 0 }} else {{ {rv} }} }} }}",
                lv = lvar, lc = left_code, rv = rvar, rc = right_code,
            )
        }

        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            let tvar = ctx.fresh_var();
            let test_code = compile_expr(test_expr, ctx);
            let then_code = compile_expr(then_expr, ctx);
            let else_code = compile_expr(else_expr, ctx);
            format!(
                "{{ let {tv} = {tc}; if host_is_error({tv}) != 0 {{ 0 }} else if host_is_bool({tv}) == 0 {{ 0 }} else if host_get_bool({tv}) != 0 {{ {thenc} }} else {{ {elsec} }} }}",
                tv = tvar, tc = test_code, thenc = then_code, elsec = else_code,
            )
        }

        ExprKind::UnaryApp { op, arg } => {
            let arg_code = compile_expr(arg, ctx);
            let avar = ctx.fresh_var();
            let host_fn = match op {
                UnaryOp::Not => "host_not",
                UnaryOp::Neg => "host_neg",
                UnaryOp::IsEmpty => "host_is_empty_set",
            };
            format!(
                "{{ let {av} = {ac}; if host_is_error({av}) != 0 {{ 0 }} else {{ {hf}({av}) }} }}",
                av = avar, ac = arg_code, hf = host_fn,
            )
        }

        ExprKind::BinaryApp { op, arg1, arg2 } => {
            match op {
                BinaryOp::GetTag | BinaryOp::HasTag => {
                    let a1_code = compile_expr(arg1, ctx);
                    let a2_code = compile_expr(arg2, ctx);
                    let v1 = ctx.fresh_var();
                    let v2 = ctx.fresh_var();
                    let host_fn = match op {
                        BinaryOp::GetTag => "host_get_tag",
                        BinaryOp::HasTag => "host_has_tag",
                        _ => unreachable!(),
                    };
                    format!(
                        "{{ let {v1} = {a1}; if host_is_error({v1}) != 0 {{ 0 }} else {{ let {v2} = {a2}; if host_is_error({v2}) != 0 {{ 0 }} else {{ {hf}({v1}, {v2}) }} }} }}",
                        v1 = v1, a1 = a1_code, v2 = v2, a2 = a2_code, hf = host_fn,
                    )
                }
                _ => {
                    let a1_code = compile_expr(arg1, ctx);
                    let a2_code = compile_expr(arg2, ctx);
                    let v1 = ctx.fresh_var();
                    let v2 = ctx.fresh_var();
                    let host_fn = match op {
                        BinaryOp::Eq => "host_eq",
                        BinaryOp::Less => "host_less",
                        BinaryOp::LessEq => "host_less_eq",
                        BinaryOp::Add => "host_add",
                        BinaryOp::Sub => "host_sub",
                        BinaryOp::Mul => "host_mul",
                        BinaryOp::In => "host_in",
                        BinaryOp::Contains => "host_contains",
                        BinaryOp::ContainsAll => "host_contains_all",
                        BinaryOp::ContainsAny => "host_contains_any",
                        BinaryOp::GetTag | BinaryOp::HasTag => unreachable!(),
                    };
                    format!(
                        "{{ let {v1} = {a1}; if host_is_error({v1}) != 0 {{ 0 }} else {{ let {v2} = {a2}; if host_is_error({v2}) != 0 {{ 0 }} else {{ {hf}({v1}, {v2}) }} }} }}",
                        v1 = v1, a1 = a1_code, v2 = v2, a2 = a2_code, hf = host_fn,
                    )
                }
            }
        }

        ExprKind::GetAttr { expr, attr } => {
            let e_code = compile_expr(expr, ctx);
            let ev = ctx.fresh_var();
            let (off, len) = ctx.intern_string(attr.as_str());
            format!(
                "{{ let {ev} = {ec}; if host_is_error({ev}) != 0 {{ 0 }} else {{ host_get_attr({ev}, {p}, {l}) }} }}",
                ev = ev, ec = e_code, p = sp(off), l = len,
            )
        }

        ExprKind::HasAttr { expr, attr } => {
            let e_code = compile_expr(expr, ctx);
            let ev = ctx.fresh_var();
            let (off, len) = ctx.intern_string(attr.as_str());
            format!(
                "{{ let {ev} = {ec}; if host_is_error({ev}) != 0 {{ 0 }} else {{ host_has_attr({ev}, {p}, {l}) }} }}",
                ev = ev, ec = e_code, p = sp(off), l = len,
            )
        }

        ExprKind::Like { expr, pattern } => {
            let e_code = compile_expr(expr, ctx);
            let ev = ctx.fresh_var();
            let pid = ctx.register_pattern(pattern);
            format!(
                "{{ let {ev} = {ec}; if host_is_error({ev}) != 0 {{ 0 }} else {{ host_like({ev}, {pid}) }} }}",
                ev = ev, ec = e_code, pid = pid,
            )
        }

        ExprKind::Is { expr, entity_type, .. } => {
            let e_code = compile_expr(expr, ctx);
            let ev = ctx.fresh_var();
            let type_str = entity_type.to_string();
            let (off, len) = ctx.intern_string(&type_str);
            format!(
                "{{ let {ev} = {ec}; if host_is_error({ev}) != 0 {{ 0 }} else {{ host_is_entity_type({ev}, {p}, {l}) }} }}",
                ev = ev, ec = e_code, p = sp(off), l = len,
            )
        }

        ExprKind::Set(elements) => {
            let mut code = format!("{{ host_set_begin({}); ", elements.len());
            for elem in elements.iter() {
                let ec = compile_expr(elem, ctx);
                let ev = ctx.fresh_var();
                code.push_str(&format!(
                    "let {ev} = {ec}; if host_is_error({ev}) != 0 {{ return 2; }} host_set_add({ev}); ",
                    ev = ev, ec = ec,
                ));
            }
            code.push_str("host_set_end() }");
            code
        }

        ExprKind::Record(fields) => {
            let mut code = format!("{{ host_record_begin({}); ", fields.len());
            for (key, val_expr) in fields.as_ref().iter() {
                let vc = compile_expr(val_expr, ctx);
                let vv = ctx.fresh_var();
                let (ko, kl) = ctx.intern_string(key.as_str());
                code.push_str(&format!(
                    "let {vv} = {vc}; if host_is_error({vv}) != 0 {{ return 2; }} host_record_add({kp}, {kl}, {vv}); ",
                    vv = vv, vc = vc, kp = sp(ko), kl = kl,
                ));
            }
            code.push_str("host_record_end() }");
            code
        }

        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            let name_str = fn_name.to_string();
            let (no, nl) = ctx.intern_string(&name_str);
            let mut code = format!("{{ host_ext_begin({}, {}); ", sp(no), nl);
            for arg in args.iter() {
                let ac = compile_expr(arg, ctx);
                let av = ctx.fresh_var();
                code.push_str(&format!(
                    "let {av} = {ac}; if host_is_error({av}) != 0 {{ return 2; }} host_ext_push_arg({av}); ",
                    av = av, ac = ac,
                ));
            }
            code.push_str("host_ext_call() }");
            code
        }

        ExprKind::Slot(_) => "host_error()".to_string(),
        ExprKind::Unknown(_) => "host_error()".to_string(),
    }
}

fn generate_wasm_source(conditions: &[ast::Expr]) -> (String, Vec<ast::Pattern>) {
    let mut ctx = CodeGenContext::new();

    let mut compiled_bodies: Vec<String> = Vec::new();
    for condition in conditions {
        let body = compile_expr(condition, &mut ctx);
        compiled_bodies.push(body);
    }

    // Build string pool literal
    let string_bytes = if ctx.strings.is_empty() {
        "static STRINGS: [u8; 1] = [0];".to_string()
    } else {
        let bytes_str = ctx
            .strings
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "static STRINGS: [u8; {}] = [{}];",
            ctx.strings.len(),
            bytes_str
        )
    };

    let mut source = String::new();
    source.push_str("#![no_std]\n#![no_main]\n\n");
    source.push_str(&string_bytes);
    source.push_str("\n\n");

    // Helper to compute actual WASM memory address of string pool entries
    source.push_str("#[inline(always)]\nfn sp(off: i32) -> i32 { STRINGS.as_ptr() as i32 + off }\n\n");

    // Extern declarations
    source.push_str(
        r#"extern "C" {
    fn host_lit_bool(v: i32) -> i32;
    fn host_lit_long(v: i64) -> i32;
    fn host_lit_string(ptr: i32, len: i32) -> i32;
    fn host_lit_entity(tp: i32, tl: i32, ip: i32, il: i32) -> i32;
    fn host_var_principal() -> i32;
    fn host_var_action() -> i32;
    fn host_var_resource() -> i32;
    fn host_var_context() -> i32;
    fn host_error() -> i32;
    fn host_is_error(h: i32) -> i32;
    fn host_is_bool(h: i32) -> i32;
    fn host_get_bool(h: i32) -> i32;
    fn host_not(h: i32) -> i32;
    fn host_neg(h: i32) -> i32;
    fn host_is_empty_set(h: i32) -> i32;
    fn host_eq(a: i32, b: i32) -> i32;
    fn host_less(a: i32, b: i32) -> i32;
    fn host_less_eq(a: i32, b: i32) -> i32;
    fn host_add(a: i32, b: i32) -> i32;
    fn host_sub(a: i32, b: i32) -> i32;
    fn host_mul(a: i32, b: i32) -> i32;
    fn host_in(a: i32, b: i32) -> i32;
    fn host_contains(s: i32, e: i32) -> i32;
    fn host_contains_all(a: i32, b: i32) -> i32;
    fn host_contains_any(a: i32, b: i32) -> i32;
    fn host_get_attr(h: i32, p: i32, l: i32) -> i32;
    fn host_has_attr(h: i32, p: i32, l: i32) -> i32;
    fn host_get_tag(h: i32, t: i32) -> i32;
    fn host_has_tag(h: i32, t: i32) -> i32;
    fn host_like(h: i32, pid: i32) -> i32;
    fn host_is_entity_type(h: i32, p: i32, l: i32) -> i32;
    fn host_set_begin(n: i32);
    fn host_set_add(h: i32);
    fn host_set_end() -> i32;
    fn host_record_begin(n: i32);
    fn host_record_add(kp: i32, kl: i32, v: i32);
    fn host_record_end() -> i32;
    fn host_ext_begin(np: i32, nl: i32);
    fn host_ext_push_arg(h: i32);
    fn host_ext_call() -> i32;
}
"#,
    );

    // Export string pool accessors
    source.push_str(
        r#"
#[no_mangle]
pub extern "C" fn strings_ptr() -> i32 { STRINGS.as_ptr() as i32 }

#[no_mangle]
pub extern "C" fn strings_len() -> i32 { STRINGS.len() as i32 }
"#,
    );

    // Generate evaluate_N functions
    for (i, body) in compiled_bodies.iter().enumerate() {
        source.push_str(&format!(
            r#"
#[no_mangle]
pub extern "C" fn evaluate_{i}() -> i32 {{
    unsafe {{
        let result = {body};
        if host_is_error(result) != 0 {{ return 2; }}
        if host_is_bool(result) == 0 {{ return 2; }}
        if host_get_bool(result) != 0 {{ 1 }} else {{ 0 }}
    }}
}}
"#,
            i = i,
            body = body,
        ));
    }

    // Panic handler
    source.push_str(
        r#"
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
"#,
    );

    (source, ctx.patterns)
}

fn compile_rust_to_wasm(source: &str) -> Result<Vec<u8>, CompileError> {
    let dir = tempfile::tempdir()?;
    let rs_path = dir.path().join("policy.rs");
    let wasm_path = dir.path().join("policy.wasm");
    std::fs::write(&rs_path, source)?;
    let output = Command::new("rustc")
        .args([
            "--target",
            "wasm32-unknown-unknown",
            "--crate-type",
            "cdylib",
            "-O",
        ])
        .arg(&rs_path)
        .arg("-o")
        .arg(&wasm_path)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CompileError(format!("rustc failed: {}", stderr)));
    }
    Ok(std::fs::read(&wasm_path)?)
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
        let (source, patterns) = generate_wasm_source(conditions);
        let wasm_bytes = compile_rust_to_wasm(&source)?;
        Ok(CompiledConditions {
            wasm_bytes,
            patterns,
            condition_count: conditions.len(),
        })
    }

    pub fn compile_conditions_source(
        &self,
        conditions: &[ast::Expr],
    ) -> Result<String, CompileError> {
        let (source, _) = generate_wasm_source(conditions);
        Ok(source)
    }
}
