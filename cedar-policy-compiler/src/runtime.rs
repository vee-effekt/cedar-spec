/// Runtime value representation and extern "C" helper functions called by compiled code.

use crate::helpers::RuntimeCtx;
use cedar_policy_core::ast::{self, Literal, EntityUID, PartialValue, Value};
use cedar_policy_core::entities::Dereference;
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};

// Tag constants for RuntimeValue
pub const TAG_ERROR: u64 = 0;
pub const TAG_BOOL: u64 = 1;
pub const TAG_LONG: u64 = 2;
pub const TAG_STRING: u64 = 3;
pub const TAG_ENTITY: u64 = 4;
pub const TAG_SET: u64 = 5;
pub const TAG_RECORD: u64 = 6;
pub const TAG_EXT: u64 = 7;

/// A runtime value passed between compiled code and helper functions.
/// Returned in (x0, x1) on AArch64 per the C calling convention for 2-word structs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeValue {
    pub tag: u64,
    pub payload: u64,
}

impl RuntimeValue {
    pub fn error() -> Self {
        Self { tag: TAG_ERROR, payload: 0 }
    }

    pub fn bool_val(b: bool) -> Self {
        Self { tag: TAG_BOOL, payload: b as u64 }
    }

    pub fn long_val(n: i64) -> Self {
        Self { tag: TAG_LONG, payload: n as u64 }
    }

    pub fn string_ptr(s: *const SmolStr) -> Self {
        Self { tag: TAG_STRING, payload: s as u64 }
    }

    pub fn entity_ptr(e: *const EntityUID) -> Self {
        Self { tag: TAG_ENTITY, payload: e as u64 }
    }

    pub fn set_ptr(s: *const BTreeSet<ast::Value>) -> Self {
        Self { tag: TAG_SET, payload: s as u64 }
    }

    pub fn record_ptr(r: *const BTreeMap<SmolStr, ast::Value>) -> Self {
        Self { tag: TAG_RECORD, payload: r as u64 }
    }

    pub fn ext_ptr(e: *const ast::Value) -> Self {
        Self { tag: TAG_EXT, payload: e as u64 }
    }
}

// ---- Request variable accessors ----

#[no_mangle]
pub extern "C" fn rt_get_principal(ctx: *const RuntimeCtx) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    match ctx.request.principal().uid() {
        Some(uid) => RuntimeValue::entity_ptr(uid as *const EntityUID),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_get_action(ctx: *const RuntimeCtx) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    match ctx.request.action().uid() {
        Some(uid) => RuntimeValue::entity_ptr(uid as *const EntityUID),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_get_resource(ctx: *const RuntimeCtx) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    match ctx.request.resource().uid() {
        Some(uid) => RuntimeValue::entity_ptr(uid as *const EntityUID),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_get_context(ctx: *const RuntimeCtx) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    match ctx.context_record.as_ref() {
        Some(rec) => RuntimeValue::record_ptr(rec.as_ref() as *const BTreeMap<SmolStr, ast::Value>),
        None => RuntimeValue::error(),
    }
}

// ---- Unary operations ----

#[no_mangle]
pub extern "C" fn rt_not(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_BOOL {
        return RuntimeValue::error();
    }
    RuntimeValue::bool_val(payload == 0)
}

#[no_mangle]
pub extern "C" fn rt_neg(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_LONG {
        return RuntimeValue::error();
    }
    let val = payload as i64;
    match val.checked_neg() {
        Some(r) => RuntimeValue::long_val(r),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_is_empty(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_SET {
        return RuntimeValue::error();
    }
    let set = unsafe { &*(payload as *const BTreeSet<ast::Value>) };
    RuntimeValue::bool_val(set.is_empty())
}

// ---- Binary equality ----

#[no_mangle]
pub extern "C" fn rt_eq(ctx: *const RuntimeCtx, lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    let left = to_cedar_value(ctx, lt, lp);
    let right = to_cedar_value(ctx, rt, rp);
    match (left, right) {
        (Some(l), Some(r)) => RuntimeValue::bool_val(l == r),
        _ => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_neq(ctx: *const RuntimeCtx, lt: u64, lp: u64, rt_tag: u64, rp: u64) -> RuntimeValue {
    let result = rt_eq(ctx, lt, lp, rt_tag, rp);
    if result.tag == TAG_BOOL {
        RuntimeValue::bool_val(result.payload == 0)
    } else {
        result
    }
}

// ---- Arithmetic ----

#[no_mangle]
pub extern "C" fn rt_add(lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    if lt != TAG_LONG || rt != TAG_LONG {
        return RuntimeValue::error();
    }
    match (lp as i64).checked_add(rp as i64) {
        Some(r) => RuntimeValue::long_val(r),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_sub(lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    if lt != TAG_LONG || rt != TAG_LONG {
        return RuntimeValue::error();
    }
    match (lp as i64).checked_sub(rp as i64) {
        Some(r) => RuntimeValue::long_val(r),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_mul(lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    if lt != TAG_LONG || rt != TAG_LONG {
        return RuntimeValue::error();
    }
    match (lp as i64).checked_mul(rp as i64) {
        Some(r) => RuntimeValue::long_val(r),
        None => RuntimeValue::error(),
    }
}

// ---- Comparison ----

#[no_mangle]
pub extern "C" fn rt_less(ctx: *const RuntimeCtx, lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    // Cedar `<` works on Long and also on extension types (decimal, datetime)
    if lt == TAG_LONG && rt == TAG_LONG {
        return RuntimeValue::bool_val((lp as i64) < (rp as i64));
    }
    // Extension type comparison
    let left = to_cedar_value(ctx, lt, lp);
    let right = to_cedar_value(ctx, rt, rp);
    match (left, right) {
        (Some(l), Some(r)) => {
            match cedar_compare(&l, &r) {
                Some(std::cmp::Ordering::Less) => RuntimeValue::bool_val(true),
                Some(_) => RuntimeValue::bool_val(false),
                None => RuntimeValue::error(),
            }
        }
        _ => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_less_eq(ctx: *const RuntimeCtx, lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    if lt == TAG_LONG && rt == TAG_LONG {
        return RuntimeValue::bool_val((lp as i64) <= (rp as i64));
    }
    let left = to_cedar_value(ctx, lt, lp);
    let right = to_cedar_value(ctx, rt, rp);
    match (left, right) {
        (Some(l), Some(r)) => {
            match cedar_compare(&l, &r) {
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) => RuntimeValue::bool_val(true),
                Some(_) => RuntimeValue::bool_val(false),
                None => RuntimeValue::error(),
            }
        }
        _ => RuntimeValue::error(),
    }
}

fn cedar_compare(l: &ast::Value, r: &ast::Value) -> Option<std::cmp::Ordering> {
    use cedar_policy_core::ast::ValueKind;
    match (&l.value, &r.value) {
        (ValueKind::Lit(Literal::Long(a)), ValueKind::Lit(Literal::Long(b))) => Some(a.cmp(b)),
        (ValueKind::ExtensionValue(a), ValueKind::ExtensionValue(b)) => a.partial_cmp(b),
        _ => None,
    }
}

// ---- Entity operations ----

#[no_mangle]
pub extern "C" fn rt_in(ctx: *const RuntimeCtx, lt: u64, lp: u64, rt: u64, rp: u64) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    // `in` checks if entity is an ancestor-or-equal of target(s)
    if lt != TAG_ENTITY {
        return RuntimeValue::error();
    }
    let entity_uid = unsafe { &*(lp as *const EntityUID) };

    match rt {
        TAG_ENTITY => {
            let target_uid = unsafe { &*(rp as *const EntityUID) };
            let result = entity_in_uid(ctx, entity_uid, target_uid);
            RuntimeValue::bool_val(result)
        }
        TAG_SET => {
            let set = unsafe { &*(rp as *const BTreeSet<ast::Value>) };
            for val in set.iter() {
                if let ast::ValueKind::Lit(Literal::EntityUID(ref uid)) = val.value {
                    if entity_in_uid(ctx, entity_uid, uid) {
                        return RuntimeValue::bool_val(true);
                    }
                }
            }
            RuntimeValue::bool_val(false)
        }
        _ => RuntimeValue::error(),
    }
}

fn entity_in_uid(ctx: &RuntimeCtx, entity: &EntityUID, target: &EntityUID) -> bool {
    if entity == target {
        return true;
    }
    // Walk ancestors
    let mut to_visit = vec![entity.clone()];
    let mut visited = std::collections::HashSet::new();
    while let Some(uid) = to_visit.pop() {
        if !visited.insert(uid.clone()) {
            continue;
        }
        if uid == *target {
            return true;
        }
        if let Dereference::Data(e) = ctx.entities.entity(&uid) {
            for parent in e.ancestors() {
                to_visit.push(parent.clone());
            }
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rt_has_attr(ctx: *const RuntimeCtx, tag: u64, payload: u64, attr_ptr: *const SmolStr) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    let attr = unsafe { &*attr_ptr };

    match tag {
        TAG_ENTITY => {
            let uid = unsafe { &*(payload as *const EntityUID) };
            match ctx.entities.entity(uid) {
                Dereference::Data(entity) => {
                    RuntimeValue::bool_val(entity.get(attr).is_some())
                }
                _ => RuntimeValue::bool_val(false),
            }
        }
        TAG_RECORD => {
            let record = unsafe { &*(payload as *const BTreeMap<SmolStr, ast::Value>) };
            RuntimeValue::bool_val(record.contains_key(attr))
        }
        _ => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_get_attr(ctx: *const RuntimeCtx, tag: u64, payload: u64, attr_ptr: *const SmolStr) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    let attr = unsafe { &*attr_ptr };

    match tag {
        TAG_ENTITY => {
            let uid = unsafe { &*(payload as *const EntityUID) };
            match ctx.entities.entity(uid) {
                Dereference::Data(entity) => {
                    match entity.get(attr) {
                        Some(PartialValue::Value(val)) => value_to_runtime(ctx, val),
                        _ => RuntimeValue::error(),
                    }
                }
                _ => RuntimeValue::error(),
            }
        }
        TAG_RECORD => {
            let record = unsafe { &*(payload as *const BTreeMap<SmolStr, ast::Value>) };
            match record.get(attr) {
                Some(val) => value_to_runtime(ctx, val),
                None => RuntimeValue::error(),
            }
        }
        _ => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_has_tag(ctx: *const RuntimeCtx, entity_tag: u64, entity_payload: u64, name_tag: u64, name_payload: u64) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    if entity_tag != TAG_ENTITY || name_tag != TAG_STRING {
        return RuntimeValue::error();
    }
    let uid = unsafe { &*(entity_payload as *const EntityUID) };
    let tag_name = unsafe { &*(name_payload as *const SmolStr) };
    match ctx.entities.entity(uid) {
        Dereference::Data(entity) => {
            RuntimeValue::bool_val(entity.get_tag(tag_name).is_some())
        }
        // hasTag on non-existent entity returns false (not error), matching the Rust evaluator
        Dereference::NoSuchEntity => RuntimeValue::bool_val(false),
        _ => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_get_tag(ctx: *const RuntimeCtx, entity_tag: u64, entity_payload: u64, name_tag: u64, name_payload: u64) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    if entity_tag != TAG_ENTITY || name_tag != TAG_STRING {
        return RuntimeValue::error();
    }
    let uid = unsafe { &*(entity_payload as *const EntityUID) };
    let tag_name = unsafe { &*(name_payload as *const SmolStr) };
    match ctx.entities.entity(uid) {
        Dereference::Data(entity) => {
            match entity.get_tag(tag_name) {
                Some(pval) => {
                    match pval {
                        PartialValue::Value(val) => value_to_runtime(ctx, val),
                        PartialValue::Residual(_) => RuntimeValue::error(),
                    }
                }
                None => RuntimeValue::error(),
            }
        }
        _ => RuntimeValue::error(),
    }
}

// ---- Set operations ----

#[no_mangle]
pub extern "C" fn rt_contains(ctx: *const RuntimeCtx, set_tag: u64, set_payload: u64, elem_tag: u64, elem_payload: u64) -> RuntimeValue {
    if set_tag != TAG_SET {
        return RuntimeValue::error();
    }
    let set = unsafe { &*(set_payload as *const BTreeSet<ast::Value>) };
    match to_cedar_value(ctx, elem_tag, elem_payload) {
        Some(val) => RuntimeValue::bool_val(set.contains(&val)),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_contains_all(set1_tag: u64, set1_payload: u64, set2_tag: u64, set2_payload: u64) -> RuntimeValue {
    if set1_tag != TAG_SET || set2_tag != TAG_SET {
        return RuntimeValue::error();
    }
    let set1 = unsafe { &*(set1_payload as *const BTreeSet<ast::Value>) };
    let set2 = unsafe { &*(set2_payload as *const BTreeSet<ast::Value>) };
    RuntimeValue::bool_val(set2.is_subset(set1))
}

#[no_mangle]
pub extern "C" fn rt_contains_any(set1_tag: u64, set1_payload: u64, set2_tag: u64, set2_payload: u64) -> RuntimeValue {
    if set1_tag != TAG_SET || set2_tag != TAG_SET {
        return RuntimeValue::error();
    }
    let set1 = unsafe { &*(set1_payload as *const BTreeSet<ast::Value>) };
    let set2 = unsafe { &*(set2_payload as *const BTreeSet<ast::Value>) };
    RuntimeValue::bool_val(!set1.is_disjoint(set2))
}

// ---- Like pattern matching ----

#[no_mangle]
pub extern "C" fn rt_like(ctx: *const RuntimeCtx, tag: u64, payload: u64, pattern_idx: u64) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    if tag != TAG_STRING {
        return RuntimeValue::error();
    }
    let s = unsafe { &*(payload as *const SmolStr) };
    match ctx.patterns.get(pattern_idx as usize) {
        Some(pattern) => RuntimeValue::bool_val(pattern.wildcard_match(s)),
        None => RuntimeValue::error(),
    }
}

// ---- Entity type check (is) ----

#[no_mangle]
pub extern "C" fn rt_is_entity_type(tag: u64, payload: u64, type_ptr: *const ast::EntityType) -> RuntimeValue {
    if tag != TAG_ENTITY {
        return RuntimeValue::error();
    }
    let uid = unsafe { &*(payload as *const EntityUID) };
    let expected_type = unsafe { &*type_ptr };
    RuntimeValue::bool_val(uid.entity_type() == expected_type)
}

// ---- Set/Record construction ----

#[no_mangle]
pub extern "C" fn rt_make_set(ctx: *const RuntimeCtx, tags: *const u64, payloads: *const u64, count: u64) -> RuntimeValue {
    let n = count as usize;
    if n == 0 {
        let ctx = unsafe { &*ctx };
        let idx = ctx.push_temp_set(BTreeSet::new());
        let ptr = ctx.get_temp_set(idx);
        return RuntimeValue::set_ptr(ptr);
    }
    let tags_slice = unsafe { std::slice::from_raw_parts(tags, n) };
    let payloads_slice = unsafe { std::slice::from_raw_parts(payloads, n) };
    let mut set = BTreeSet::new();
    for i in 0..n {
        match to_cedar_value(ctx, tags_slice[i], payloads_slice[i]) {
            Some(v) => { set.insert(v); }
            None => return RuntimeValue::error(),
        }
    }
    let ctx = unsafe { &*ctx };
    let idx = ctx.push_temp_set(set);
    let ptr = ctx.get_temp_set(idx);
    RuntimeValue::set_ptr(ptr)
}

#[no_mangle]
pub extern "C" fn rt_make_record(ctx: *const RuntimeCtx, keys: *const *const SmolStr, tags: *const u64, payloads: *const u64, count: u64) -> RuntimeValue {
    let n = count as usize;
    if n == 0 {
        let ctx = unsafe { &*ctx };
        let idx = ctx.push_temp_record(BTreeMap::new());
        let ptr = ctx.get_temp_record(idx);
        return RuntimeValue::record_ptr(ptr);
    }
    let keys_slice = unsafe { std::slice::from_raw_parts(keys, n) };
    let tags_slice = unsafe { std::slice::from_raw_parts(tags, n) };
    let payloads_slice = unsafe { std::slice::from_raw_parts(payloads, n) };
    let mut record = BTreeMap::new();
    for i in 0..n {
        let key = unsafe { &*keys_slice[i] };
        match to_cedar_value(ctx, tags_slice[i], payloads_slice[i]) {
            Some(v) => { record.insert(key.clone(), v); }
            None => return RuntimeValue::error(),
        }
    }
    let ctx = unsafe { &*ctx };
    let idx = ctx.push_temp_record(record);
    let ptr = ctx.get_temp_record(idx);
    RuntimeValue::record_ptr(ptr)
}

// ---- Extension function dispatch ----

#[no_mangle]
pub extern "C" fn rt_call_extension(ctx: *const RuntimeCtx, fn_name_idx: u64, args_tags: *const u64, args_payloads: *const u64, n_args: u64) -> RuntimeValue {
    let ctx = unsafe { &*ctx };
    let fn_name = match ctx.interned_strings.get(fn_name_idx as usize) {
        Some(name) => name,
        None => return RuntimeValue::error(),
    };

    let n = n_args as usize;
    let mut args = Vec::with_capacity(n);
    if n > 0 {
        let tags = unsafe { std::slice::from_raw_parts(args_tags, n) };
        let payloads = unsafe { std::slice::from_raw_parts(args_payloads, n) };
        for i in 0..n {
            match to_cedar_value(ctx as *const RuntimeCtx, tags[i], payloads[i]) {
                Some(v) => args.push(v),
                None => return RuntimeValue::error(),
            }
        }
    }

    // Use the Cedar extension evaluator
    match eval_extension_fn(ctx, fn_name, &args) {
        Ok(val) => value_to_runtime(ctx, &val),
        Err(_) => RuntimeValue::error(),
    }
}

fn eval_extension_fn(_ctx: &RuntimeCtx, fn_name: &str, args: &[Value]) -> Result<Value, ()> {
    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::ast::Name;
    use std::str::FromStr;

    let exts = Extensions::all_available();
    // Parse function name as a Cedar Name
    let name = Name::from_str(fn_name).map_err(|_| ())?;
    let func = exts.func(&name).map_err(|_| ())?;
    match func.call(args) {
        Ok(PartialValue::Value(v)) => Ok(v),
        Ok(PartialValue::Residual(_)) => Err(()),
        Err(_) => Err(()),
    }
}

// ---- Value conversion helpers ----

/// Convert a RuntimeValue (tag, payload) back to a Cedar Value.
fn to_cedar_value(_ctx: *const RuntimeCtx, tag: u64, payload: u64) -> Option<ast::Value> {
    match tag {
        TAG_BOOL => Some(ast::Value::from(payload != 0)),
        TAG_LONG => Some(ast::Value::from(payload as i64)),
        TAG_STRING => {
            let s = unsafe { &*(payload as *const SmolStr) };
            Some(ast::Value::from(s.clone()))
        }
        TAG_ENTITY => {
            let uid = unsafe { &*(payload as *const EntityUID) };
            Some(ast::Value::from(uid.clone()))
        }
        TAG_SET => {
            let set = unsafe { &*(payload as *const BTreeSet<ast::Value>) };
            Some(ast::Value::set(set.iter().cloned(), None))
        }
        TAG_RECORD => {
            let record = unsafe { &*(payload as *const BTreeMap<SmolStr, ast::Value>) };
            Some(ast::Value::record(record.clone(), None))
        }
        TAG_EXT => {
            let val = unsafe { &*(payload as *const ast::Value) };
            Some(val.clone())
        }
        _ => None,
    }
}

/// Convert a Cedar Value to a RuntimeValue, storing heap-allocated values in the RuntimeCtx.
pub fn value_to_runtime(ctx: &RuntimeCtx, val: &ast::Value) -> RuntimeValue {
    use cedar_policy_core::ast::ValueKind;
    match &val.value {
        ValueKind::Lit(Literal::Bool(b)) => RuntimeValue::bool_val(*b),
        ValueKind::Lit(Literal::Long(n)) => RuntimeValue::long_val(*n),
        ValueKind::Lit(Literal::String(s)) => {
            let idx = ctx.push_temp_string(s.clone());
            let ptr = ctx.get_temp_string(idx);
            RuntimeValue::string_ptr(ptr)
        }
        ValueKind::Lit(Literal::EntityUID(uid)) => {
            let idx = ctx.push_temp_entity((**uid).clone());
            let ptr = ctx.get_temp_entity(idx);
            RuntimeValue::entity_ptr(ptr)
        }
        ValueKind::Set(s) => {
            let set: BTreeSet<ast::Value> = s.iter().cloned().collect();
            let idx = ctx.push_temp_set(set);
            let ptr = ctx.get_temp_set(idx);
            RuntimeValue::set_ptr(ptr)
        }
        ValueKind::Record(r) => {
            let idx = ctx.push_temp_record((**r).clone());
            let ptr = ctx.get_temp_record(idx);
            RuntimeValue::record_ptr(ptr)
        }
        ValueKind::ExtensionValue(_) => {
            let idx = ctx.push_temp_ext(val.clone());
            let ptr = ctx.get_temp_ext(idx);
            RuntimeValue::ext_ptr(ptr)
        }
    }
}

