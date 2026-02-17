use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use cedar_policy_core::ast::{
    self, BinaryOp, EntityUID, ExprKind, Literal, PartialValue, UnaryOp, Value, ValueKind, Var,
};
use cedar_policy_core::entities::{Dereference, Entities};
use cedar_policy_core::extensions::Extensions;
use smol_str::SmolStr;

#[derive(Debug)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
enum EvalError {
    TypeError(String),
    MissingAttr(String),
    MissingEntity(String),
    Overflow(String),
    SlotError,
    UnknownError,
    ExtensionError(String),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::TypeError(msg) => write!(f, "type error: {}", msg),
            EvalError::MissingAttr(msg) => write!(f, "missing attribute: {}", msg),
            EvalError::MissingEntity(msg) => write!(f, "missing entity: {}", msg),
            EvalError::Overflow(msg) => write!(f, "overflow: {}", msg),
            EvalError::SlotError => write!(f, "unexpected slot in expression"),
            EvalError::UnknownError => write!(f, "unexpected unknown in expression"),
            EvalError::ExtensionError(msg) => write!(f, "extension error: {}", msg),
        }
    }
}

struct EvalContext<'a> {
    request: &'a ast::Request,
    entities: &'a Entities,
    extensions: &'a Extensions<'a>,
}

fn get_as_bool(v: &Value) -> Result<bool, EvalError> {
    match &v.value {
        ValueKind::Lit(Literal::Bool(b)) => Ok(*b),
        _ => Err(EvalError::TypeError(format!(
            "expected Bool, got {:?}",
            v
        ))),
    }
}

fn get_as_long(v: &Value) -> Result<i64, EvalError> {
    match &v.value {
        ValueKind::Lit(Literal::Long(i)) => Ok(*i),
        _ => Err(EvalError::TypeError(format!(
            "expected Long, got {:?}",
            v
        ))),
    }
}

fn get_as_string(v: &Value) -> Result<&SmolStr, EvalError> {
    match &v.value {
        ValueKind::Lit(Literal::String(s)) => Ok(s),
        _ => Err(EvalError::TypeError(format!(
            "expected String, got {:?}",
            v
        ))),
    }
}

fn get_as_entity(v: &Value) -> Result<&EntityUID, EvalError> {
    match &v.value {
        ValueKind::Lit(Literal::EntityUID(uid)) => Ok(uid.as_ref()),
        _ => Err(EvalError::TypeError(format!(
            "expected EntityUID, got {:?}",
            v
        ))),
    }
}

fn get_as_set(v: &Value) -> Result<&ast::Set, EvalError> {
    match &v.value {
        ValueKind::Set(set) => Ok(set),
        _ => Err(EvalError::TypeError(format!(
            "expected Set, got {:?}",
            v
        ))),
    }
}

fn eval_expr(expr: &ast::Expr, ctx: &EvalContext<'_>) -> Result<Value, EvalError> {
    match expr.expr_kind() {
        ExprKind::Lit(lit) => Ok(Value::new(lit.clone(), None)),

        ExprKind::Var(var) => match var {
            Var::Principal => {
                let uid = ctx
                    .request
                    .principal()
                    .uid()
                    .ok_or_else(|| EvalError::UnknownError)?;
                Ok(Value::new(uid.clone(), None))
            }
            Var::Action => {
                let uid = ctx
                    .request
                    .action()
                    .uid()
                    .ok_or_else(|| EvalError::UnknownError)?;
                Ok(Value::new(uid.clone(), None))
            }
            Var::Resource => {
                let uid = ctx
                    .request
                    .resource()
                    .uid()
                    .ok_or_else(|| EvalError::UnknownError)?;
                Ok(Value::new(uid.clone(), None))
            }
            Var::Context => match ctx.request.context() {
                Some(context) => {
                    let pv: PartialValue = context.clone().into();
                    match pv {
                        PartialValue::Value(v) => Ok(v),
                        PartialValue::Residual(_) => Err(EvalError::UnknownError),
                    }
                }
                None => Err(EvalError::UnknownError),
            },
        },

        ExprKind::And { left, right } => {
            let lv = eval_expr(left, ctx)?;
            let lb = get_as_bool(&lv)?;
            if !lb {
                Ok(false.into())
            } else {
                let rv = eval_expr(right, ctx)?;
                let rb = get_as_bool(&rv)?;
                Ok(rb.into())
            }
        }

        ExprKind::Or { left, right } => {
            let lv = eval_expr(left, ctx)?;
            let lb = get_as_bool(&lv)?;
            if lb {
                Ok(true.into())
            } else {
                let rv = eval_expr(right, ctx)?;
                let rb = get_as_bool(&rv)?;
                Ok(rb.into())
            }
        }

        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            let tv = eval_expr(test_expr, ctx)?;
            let tb = get_as_bool(&tv)?;
            if tb {
                eval_expr(then_expr, ctx)
            } else {
                eval_expr(else_expr, ctx)
            }
        }

        ExprKind::UnaryApp { op, arg } => {
            let av = eval_expr(arg, ctx)?;
            match op {
                UnaryOp::Not => {
                    let b = get_as_bool(&av)?;
                    Ok((!b).into())
                }
                UnaryOp::Neg => {
                    let i = get_as_long(&av)?;
                    match i.checked_neg() {
                        Some(v) => Ok(v.into()),
                        None => Err(EvalError::Overflow(format!(
                            "integer overflow on negation of {}",
                            i
                        ))),
                    }
                }
                UnaryOp::IsEmpty => {
                    let s = get_as_set(&av)?;
                    Ok(s.is_empty().into())
                }
            }
        }

        ExprKind::BinaryApp { op, arg1, arg2 } => eval_binary_op(*op, arg1, arg2, ctx),

        ExprKind::GetAttr { expr, attr } => {
            let v = eval_expr(expr, ctx)?;
            match &v.value {
                ValueKind::Record(record) => record
                    .get(attr)
                    .cloned()
                    .ok_or_else(|| EvalError::MissingAttr(format!("record has no attribute `{}`", attr))),
                ValueKind::Lit(Literal::EntityUID(uid)) => {
                    match ctx.entities.entity(uid.as_ref()) {
                        Dereference::NoSuchEntity => Err(EvalError::MissingEntity(format!(
                            "entity `{}` does not exist",
                            uid
                        ))),
                        Dereference::Residual(_) => Err(EvalError::UnknownError),
                        Dereference::Data(entity) => match entity.get(attr) {
                            Some(PartialValue::Value(v)) => Ok(v.clone()),
                            Some(PartialValue::Residual(_)) => Err(EvalError::UnknownError),
                            None => Err(EvalError::MissingAttr(format!(
                                "entity `{}` has no attribute `{}`",
                                uid, attr
                            ))),
                        },
                    }
                }
                _ => Err(EvalError::TypeError(format!(
                    "expected Record or Entity for attribute access, got {:?}",
                    v
                ))),
            }
        }

        ExprKind::HasAttr { expr, attr } => {
            let v = eval_expr(expr, ctx)?;
            match &v.value {
                ValueKind::Record(record) => Ok(record.contains_key(attr).into()),
                ValueKind::Lit(Literal::EntityUID(uid)) => {
                    match ctx.entities.entity(uid.as_ref()) {
                        Dereference::NoSuchEntity => Ok(false.into()),
                        Dereference::Residual(_) => Err(EvalError::UnknownError),
                        Dereference::Data(entity) => Ok(entity.get(attr).is_some().into()),
                    }
                }
                _ => Err(EvalError::TypeError(format!(
                    "expected Record or Entity for has-attribute check, got {:?}",
                    v
                ))),
            }
        }

        ExprKind::Like { expr, pattern } => {
            let v = eval_expr(expr, ctx)?;
            let s = get_as_string(&v)?;
            Ok(pattern.wildcard_match(s).into())
        }

        ExprKind::Is {
            expr, entity_type, ..
        } => {
            let v = eval_expr(expr, ctx)?;
            let uid = get_as_entity(&v)?;
            Ok((uid.entity_type() == entity_type).into())
        }

        ExprKind::Set(elements) => {
            let vals: Vec<Value> = elements
                .iter()
                .map(|e| eval_expr(e, ctx))
                .collect::<Result<_, _>>()?;
            Ok(Value::set(vals, None))
        }

        ExprKind::Record(fields) => {
            let map: BTreeMap<SmolStr, Value> = fields
                .as_ref()
                .iter()
                .map(|(k, e)| Ok((k.clone(), eval_expr(e, ctx)?)))
                .collect::<Result<_, EvalError>>()?;
            Ok(Value::record_arc(Arc::new(map), None))
        }

        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            let evaluated_args: Vec<Value> = args
                .iter()
                .map(|a| eval_expr(a, ctx))
                .collect::<Result<_, _>>()?;
            let func = ctx
                .extensions
                .func(fn_name)
                .map_err(|e| EvalError::ExtensionError(format!("{}", e)))?;
            let result = func
                .call(&evaluated_args)
                .map_err(|e| EvalError::ExtensionError(format!("{}", e)))?;
            match result {
                PartialValue::Value(v) => Ok(v),
                PartialValue::Residual(_) => Err(EvalError::UnknownError),
            }
        }

        ExprKind::Slot(_) => Err(EvalError::SlotError),

        ExprKind::Unknown(_) => Err(EvalError::UnknownError),
    }
}

fn eval_binary_op(
    op: BinaryOp,
    arg1: &ast::Expr,
    arg2: &ast::Expr,
    ctx: &EvalContext<'_>,
) -> Result<Value, EvalError> {
    match op {
        BinaryOp::Eq => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            Ok((v1 == v2).into())
        }

        BinaryOp::Less => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let i1 = get_as_long(&v1)?;
            let i2 = get_as_long(&v2)?;
            Ok((i1 < i2).into())
        }

        BinaryOp::LessEq => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let i1 = get_as_long(&v1)?;
            let i2 = get_as_long(&v2)?;
            Ok((i1 <= i2).into())
        }

        BinaryOp::Add => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let i1 = get_as_long(&v1)?;
            let i2 = get_as_long(&v2)?;
            match i1.checked_add(i2) {
                Some(r) => Ok(r.into()),
                None => Err(EvalError::Overflow(format!(
                    "integer overflow on {} + {}",
                    i1, i2
                ))),
            }
        }

        BinaryOp::Sub => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let i1 = get_as_long(&v1)?;
            let i2 = get_as_long(&v2)?;
            match i1.checked_sub(i2) {
                Some(r) => Ok(r.into()),
                None => Err(EvalError::Overflow(format!(
                    "integer overflow on {} - {}",
                    i1, i2
                ))),
            }
        }

        BinaryOp::Mul => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let i1 = get_as_long(&v1)?;
            let i2 = get_as_long(&v2)?;
            match i1.checked_mul(i2) {
                Some(r) => Ok(r.into()),
                None => Err(EvalError::Overflow(format!(
                    "integer overflow on {} * {}",
                    i1, i2
                ))),
            }
        }

        BinaryOp::In => {
            let v1 = eval_expr(arg1, ctx)?;
            let uid1 = get_as_entity(&v1)?;
            let entity1 = match ctx.entities.entity(uid1) {
                Dereference::Data(e) => Some(e),
                Dereference::NoSuchEntity => None,
                Dereference::Residual(_) => return Err(EvalError::UnknownError),
            };

            let v2 = eval_expr(arg2, ctx)?;
            let rhs_uids: Vec<&EntityUID> = match &v2.value {
                ValueKind::Lit(Literal::EntityUID(uid)) => vec![uid.as_ref()],
                ValueKind::Set(set) => {
                    let mut uids = Vec::new();
                    for val in set.iter() {
                        uids.push(get_as_entity(val)?);
                    }
                    uids
                }
                _ => {
                    return Err(EvalError::TypeError(format!(
                        "expected Entity or Set for `in` operator, got {:?}",
                        v2
                    )));
                }
            };

            for uid2 in rhs_uids {
                if uid1 == uid2
                    || entity1
                        .map(|e| e.is_descendant_of(uid2))
                        .unwrap_or(false)
                {
                    return Ok(true.into());
                }
            }
            Ok(false.into())
        }

        BinaryOp::Contains => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let set = get_as_set(&v1)?;
            Ok(set.contains(&v2).into())
        }

        BinaryOp::ContainsAll => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let set1 = get_as_set(&v1)?;
            let set2 = get_as_set(&v2)?;
            Ok(set2.is_subset(set1).into())
        }

        BinaryOp::ContainsAny => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let set1 = get_as_set(&v1)?;
            let set2 = get_as_set(&v2)?;
            let result = set2.iter().any(|v| set1.contains(v));
            Ok(result.into())
        }

        BinaryOp::GetTag => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let uid = get_as_entity(&v1)?;
            let tag = get_as_string(&v2)?;
            match ctx.entities.entity(uid) {
                Dereference::NoSuchEntity => Err(EvalError::MissingEntity(format!(
                    "entity `{}` does not exist",
                    uid
                ))),
                Dereference::Residual(_) => Err(EvalError::UnknownError),
                Dereference::Data(entity) => match entity.get_tag(tag) {
                    Some(PartialValue::Value(v)) => Ok(v.clone()),
                    Some(PartialValue::Residual(_)) => Err(EvalError::UnknownError),
                    None => Err(EvalError::MissingAttr(format!(
                        "entity `{}` has no tag `{}`",
                        uid, tag
                    ))),
                },
            }
        }

        BinaryOp::HasTag => {
            let v1 = eval_expr(arg1, ctx)?;
            let v2 = eval_expr(arg2, ctx)?;
            let uid = get_as_entity(&v1)?;
            let tag = get_as_string(&v2)?;
            match ctx.entities.entity(uid) {
                Dereference::NoSuchEntity => Ok(false.into()),
                Dereference::Residual(_) => Err(EvalError::UnknownError),
                Dereference::Data(entity) => Ok(entity.get_tag(tag).is_some().into()),
            }
        }
    }
}

pub struct Compiler;

impl Compiler {
    pub fn new() -> Self {
        Compiler
    }

    pub fn compile_str(&self, _policy_text: &str) -> Result<Vec<u8>, CompileError> {
        Err(CompileError("not yet implemented".to_string()))
    }

    /// Evaluate a condition expression against a request and entities.
    /// Returns: 1 = satisfied, 0 = not satisfied, 2 = evaluation error
    pub fn evaluate_condition(
        &self,
        condition: &ast::Expr,
        request: &cedar_policy::Request,
        entities: &cedar_policy::Entities,
    ) -> i64 {
        let core_request: &ast::Request = request.as_ref();
        let core_entities: &Entities = entities.as_ref();
        let extensions = Extensions::all_available();

        let ctx = EvalContext {
            request: core_request,
            entities: core_entities,
            extensions,
        };

        match eval_expr(condition, &ctx) {
            Ok(val) => match get_as_bool(&val) {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(_) => 2,
            },
            Err(_) => 2,
        }
    }
}
