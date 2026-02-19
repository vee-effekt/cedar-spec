//! Runtime helper functions called by JIT-compiled Cedar policies.
//!
//! These are `extern "C"` functions that Cranelift-generated native code calls
//! directly via the JIT linker. They operate on `TaggedValue` pointers and
//! interact with Cedar `Value`, `Request`, and `Entities` types.

use cedar_policy_core::ast::{self, EntityUID, Literal, PartialValue, Value, ValueKind};
use cedar_policy_core::entities::{Dereference, Entities};
use cedar_policy_core::extensions::Extensions;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::TaggedValue;

// Tag constants — must match the constants in lib.rs
const TAG_ERROR: u32 = 0;
const TAG_BOOL: u32 = 1;
const TAG_LONG: u32 = 2;
const TAG_VALUE: u32 = 3; // complex value (String, EntityUID, Set, Record, Extension)

/// Runtime context passed to helper functions via a pointer.
/// The JIT-compiled code receives this as its first argument.
#[repr(C)]
pub struct RuntimeCtx {
    pub request: ast::Request,
    pub entities: Entities,
    pub extensions: &'static Extensions<'static>,
    pub patterns: Vec<ast::Pattern>,
    pub interned_strings: Vec<(SmolStr, usize)>, // (string, offset) pairs for interned strings
    pub string_pool: Vec<u8>,                     // raw bytes of interned strings
}

impl RuntimeCtx {
    pub fn new(
        request: &ast::Request,
        entities: &Entities,
        patterns: Vec<ast::Pattern>,
        interned_strings: Vec<(SmolStr, usize)>,
        string_pool: Vec<u8>,
    ) -> Self {
        Self {
            request: request.clone(),
            entities: entities.clone(),
            extensions: Extensions::all_available(),
            patterns,
            interned_strings,
            string_pool,
        }
    }

    fn lookup_string(&self, ptr: u64, len: u64) -> SmolStr {
        let offset = ptr as usize;
        let length = len as usize;
        let bytes = &self.string_pool[offset..offset + length];
        SmolStr::from(std::str::from_utf8(bytes).expect("invalid UTF-8 in string pool"))
    }
}

// ========== TaggedValue allocation helpers ==========

fn alloc_error() -> *mut TaggedValue {
    let tv = Box::new(TaggedValue {
        tag: TAG_ERROR,
        _pad: 0,
        payload: 0,
    });
    Box::into_raw(tv)
}

fn alloc_bool(b: bool) -> *mut TaggedValue {
    let tv = Box::new(TaggedValue {
        tag: TAG_BOOL,
        _pad: 0,
        payload: if b { 1 } else { 0 },
    });
    Box::into_raw(tv)
}

fn alloc_long(i: i64) -> *mut TaggedValue {
    let tv = Box::new(TaggedValue {
        tag: TAG_LONG,
        _pad: 0,
        payload: i as u64,
    });
    Box::into_raw(tv)
}

fn alloc_value(v: Value) -> *mut TaggedValue {
    let boxed = Box::new(v);
    let ptr = Box::into_raw(boxed);
    let tv = Box::new(TaggedValue {
        tag: TAG_VALUE,
        _pad: 0,
        payload: ptr as u64,
    });
    Box::into_raw(tv)
}

/// Extract a Cedar Value from a TaggedValue pointer. For Bool/Long, constructs
/// a Value on the fly. For TAG_VALUE, clones the pointed-to Value.
unsafe fn extract_value(tv: *const TaggedValue) -> Option<Value> {
    if tv.is_null() {
        return None;
    }
    let tag = (*tv).tag;
    let payload = (*tv).payload;
    match tag {
        TAG_ERROR => None,
        TAG_BOOL => Some(Value::from(payload != 0)),
        TAG_LONG => Some(Value::from(payload as i64)),
        TAG_VALUE => {
            let vptr = payload as *const Value;
            if vptr.is_null() {
                None
            } else {
                Some((*vptr).clone())
            }
        }
        _ => None,
    }
}

fn get_as_bool(v: &Value) -> Option<bool> {
    match &v.value {
        ValueKind::Lit(Literal::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn get_as_long(v: &Value) -> Option<i64> {
    match &v.value {
        ValueKind::Lit(Literal::Long(i)) => Some(*i),
        _ => None,
    }
}

fn get_as_string(v: &Value) -> Option<&SmolStr> {
    match &v.value {
        ValueKind::Lit(Literal::String(s)) => Some(s),
        _ => None,
    }
}

fn get_as_entity(v: &Value) -> Option<&EntityUID> {
    match &v.value {
        ValueKind::Lit(Literal::EntityUID(uid)) => Some(uid.as_ref()),
        _ => None,
    }
}

fn get_as_set(v: &Value) -> Option<&ast::Set> {
    match &v.value {
        ValueKind::Set(set) => Some(set),
        _ => None,
    }
}

// ========== Helper functions callable from JIT code ==========

/// Get the principal entity UID from the request.
/// Returns a TaggedValue pointer (TAG_VALUE with EntityUID or TAG_ERROR).
pub extern "C" fn helper_var_principal(ctx: *const RuntimeCtx) -> *mut TaggedValue {
    unsafe {
        let uid = match (*ctx).request.principal().uid() {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        let val = Value::new(uid, None);
        alloc_value(val)
    }
}

pub extern "C" fn helper_var_action(ctx: *const RuntimeCtx) -> *mut TaggedValue {
    unsafe {
        let uid = match (*ctx).request.action().uid() {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        let val = Value::new(uid, None);
        alloc_value(val)
    }
}

pub extern "C" fn helper_var_resource(ctx: *const RuntimeCtx) -> *mut TaggedValue {
    unsafe {
        let uid = match (*ctx).request.resource().uid() {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        let val = Value::new(uid, None);
        alloc_value(val)
    }
}

pub extern "C" fn helper_var_context(ctx: *const RuntimeCtx) -> *mut TaggedValue {
    unsafe {
        let ctx_val = match (*ctx).request.context() {
            Some(context) => {
                let pv: PartialValue = context.clone().into();
                match pv {
                    PartialValue::Value(v) => v,
                    PartialValue::Residual(_) => return alloc_error(),
                }
            }
            None => return alloc_error(),
        };
        alloc_value(ctx_val)
    }
}

pub extern "C" fn helper_error() -> *mut TaggedValue {
    alloc_error()
}

pub extern "C" fn helper_lit_bool(v: u64) -> *mut TaggedValue {
    alloc_bool(v != 0)
}

pub extern "C" fn helper_lit_long(v: i64) -> *mut TaggedValue {
    alloc_long(v)
}

pub extern "C" fn helper_lit_string(ctx: *const RuntimeCtx, ptr: u64, len: u64) -> *mut TaggedValue {
    unsafe {
        let s = (*ctx).lookup_string(ptr, len);
        let val = Value::new(Literal::String(s), None);
        alloc_value(val)
    }
}

pub extern "C" fn helper_lit_entity(
    ctx: *const RuntimeCtx,
    type_ptr: u64, type_len: u64,
    id_ptr: u64, id_len: u64,
) -> *mut TaggedValue {
    unsafe {
        let type_str = (*ctx).lookup_string(type_ptr, type_len);
        let id_str = (*ctx).lookup_string(id_ptr, id_len);
        let entity_type: ast::EntityType = type_str.parse().expect("invalid entity type");
        let uid = EntityUID::from_components(entity_type, ast::Eid::new(id_str), None);
        let val = Value::new(Literal::EntityUID(Arc::new(uid)), None);
        alloc_value(val)
    }
}

/// Check if a TaggedValue represents an error (tag == 0).
pub extern "C" fn helper_is_error(tv: *const TaggedValue) -> u64 {
    unsafe {
        if tv.is_null() || (*tv).tag == TAG_ERROR {
            1
        } else {
            0
        }
    }
}

/// Check if a TaggedValue is a boolean.
pub extern "C" fn helper_is_bool(tv: *const TaggedValue) -> u64 {
    unsafe {
        if tv.is_null() {
            return 0;
        }
        match (*tv).tag {
            TAG_BOOL => 1,
            TAG_VALUE => {
                let vptr = (*tv).payload as *const Value;
                if vptr.is_null() { return 0; }
                match get_as_bool(&*vptr) {
                    Some(_) => 1,
                    None => 0,
                }
            }
            _ => 0,
        }
    }
}

/// Get boolean value (0 or 1) from a TaggedValue known to be bool.
pub extern "C" fn helper_get_bool(tv: *const TaggedValue) -> u64 {
    unsafe {
        if tv.is_null() {
            return 0;
        }
        match (*tv).tag {
            TAG_BOOL => (*tv).payload,
            TAG_VALUE => {
                let vptr = (*tv).payload as *const Value;
                if vptr.is_null() { return 0; }
                match get_as_bool(&*vptr) {
                    Some(true) => 1,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }
}

pub extern "C" fn helper_not(tv: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let val = match extract_value(tv) {
            Some(v) => v,
            None => return alloc_error(),
        };
        match get_as_bool(&val) {
            Some(b) => alloc_bool(!b),
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_neg(tv: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let val = match extract_value(tv) {
            Some(v) => v,
            None => return alloc_error(),
        };
        match get_as_long(&val) {
            Some(i) => match i.checked_neg() {
                Some(r) => alloc_long(r),
                None => alloc_error(),
            },
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_is_empty_set(tv: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let val = match extract_value(tv) {
            Some(v) => v,
            None => return alloc_error(),
        };
        match get_as_set(&val) {
            Some(s) => alloc_bool(s.is_empty()),
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_eq(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let va = match extract_value(a) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let vb = match extract_value(b) {
            Some(v) => v,
            None => return alloc_error(),
        };
        alloc_bool(va == vb)
    }
}

pub extern "C" fn helper_less(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let i1 = match extract_value(a).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        let i2 = match extract_value(b).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        alloc_bool(i1 < i2)
    }
}

pub extern "C" fn helper_less_eq(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let i1 = match extract_value(a).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        let i2 = match extract_value(b).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        alloc_bool(i1 <= i2)
    }
}

pub extern "C" fn helper_add(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let i1 = match extract_value(a).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        let i2 = match extract_value(b).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        match i1.checked_add(i2) {
            Some(r) => alloc_long(r),
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_sub(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let i1 = match extract_value(a).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        let i2 = match extract_value(b).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        match i1.checked_sub(i2) {
            Some(r) => alloc_long(r),
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_mul(a: *const TaggedValue, b: *const TaggedValue) -> *mut TaggedValue {
    unsafe {
        let i1 = match extract_value(a).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        let i2 = match extract_value(b).and_then(|v| get_as_long(&v).map(|i| i)) {
            Some(i) => i,
            None => return alloc_error(),
        };
        match i1.checked_mul(i2) {
            Some(r) => alloc_long(r),
            None => alloc_error(),
        }
    }
}

pub extern "C" fn helper_in(
    a: *const TaggedValue,
    b: *const TaggedValue,
    ctx: *const RuntimeCtx,
) -> *mut TaggedValue {
    unsafe {
        let va = match extract_value(a) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let vb = match extract_value(b) {
            Some(v) => v,
            None => return alloc_error(),
        };

        let uid1 = match get_as_entity(&va) {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };

        let entity1 = match (*ctx).entities.entity(&uid1) {
            Dereference::Data(e) => Some(e.clone()),
            Dereference::NoSuchEntity => None,
            Dereference::Residual(_) => return alloc_error(),
        };

        let rhs_uids: Vec<EntityUID> = match &vb.value {
            ValueKind::Lit(Literal::EntityUID(uid)) => vec![uid.as_ref().clone()],
            ValueKind::Set(set) => {
                let mut uids = Vec::new();
                for val in set.iter() {
                    match get_as_entity(val) {
                        Some(uid) => uids.push(uid.clone()),
                        None => return alloc_error(),
                    }
                }
                uids
            }
            _ => return alloc_error(),
        };

        for uid2 in &rhs_uids {
            if uid1 == *uid2
                || entity1
                    .as_ref()
                    .map(|e| e.is_descendant_of(uid2))
                    .unwrap_or(false)
            {
                return alloc_bool(true);
            }
        }
        alloc_bool(false)
    }
}

pub extern "C" fn helper_contains(
    s: *const TaggedValue,
    e: *const TaggedValue,
) -> *mut TaggedValue {
    unsafe {
        let vs = match extract_value(s) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let ve = match extract_value(e) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let set = match get_as_set(&vs) {
            Some(set) => set.clone(),
            None => return alloc_error(),
        };
        alloc_bool(set.contains(&ve))
    }
}

pub extern "C" fn helper_contains_all(
    a: *const TaggedValue,
    b: *const TaggedValue,
) -> *mut TaggedValue {
    unsafe {
        let va = match extract_value(a) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let vb = match extract_value(b) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let set1 = match get_as_set(&va) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let set2 = match get_as_set(&vb) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        alloc_bool(set2.is_subset(&set1))
    }
}

pub extern "C" fn helper_contains_any(
    a: *const TaggedValue,
    b: *const TaggedValue,
) -> *mut TaggedValue {
    unsafe {
        let va = match extract_value(a) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let vb = match extract_value(b) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let set1 = match get_as_set(&va) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let set2 = match get_as_set(&vb) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let result = set2.iter().any(|v| set1.contains(v));
        alloc_bool(result)
    }
}

pub extern "C" fn helper_get_attr(
    h: *const TaggedValue,
    ctx: *const RuntimeCtx,
    attr_ptr: u64,
    attr_len: u64,
) -> *mut TaggedValue {
    unsafe {
        let attr = (*ctx).lookup_string(attr_ptr, attr_len);
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        match &v.value {
            ValueKind::Record(record) => match record.get(attr.as_str()) {
                Some(val) => alloc_value(val.clone()),
                None => alloc_error(),
            },
            ValueKind::Lit(Literal::EntityUID(uid)) => {
                let uid = uid.as_ref().clone();
                match (*ctx).entities.entity(&uid) {
                    Dereference::NoSuchEntity => alloc_error(),
                    Dereference::Residual(_) => alloc_error(),
                    Dereference::Data(entity) => match entity.get(attr.as_str()) {
                        Some(PartialValue::Value(val)) => alloc_value(val.clone()),
                        _ => alloc_error(),
                    },
                }
            }
            _ => alloc_error(),
        }
    }
}

pub extern "C" fn helper_has_attr(
    h: *const TaggedValue,
    ctx: *const RuntimeCtx,
    attr_ptr: u64,
    attr_len: u64,
) -> *mut TaggedValue {
    unsafe {
        let attr = (*ctx).lookup_string(attr_ptr, attr_len);
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let result = match &v.value {
            ValueKind::Record(record) => record.contains_key(attr.as_str()),
            ValueKind::Lit(Literal::EntityUID(uid)) => {
                let uid = uid.as_ref().clone();
                match (*ctx).entities.entity(&uid) {
                    Dereference::NoSuchEntity => false,
                    Dereference::Residual(_) => return alloc_error(),
                    Dereference::Data(entity) => entity.get(attr.as_str()).is_some(),
                }
            }
            _ => return alloc_error(),
        };
        alloc_bool(result)
    }
}

pub extern "C" fn helper_get_tag(
    h: *const TaggedValue,
    t: *const TaggedValue,
    ctx: *const RuntimeCtx,
) -> *mut TaggedValue {
    unsafe {
        let tag_val = match extract_value(t) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let tag = match get_as_string(&tag_val) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let uid = match get_as_entity(&v) {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        match (*ctx).entities.entity(&uid) {
            Dereference::NoSuchEntity => alloc_error(),
            Dereference::Residual(_) => alloc_error(),
            Dereference::Data(entity) => match entity.get_tag(tag.as_str()) {
                Some(PartialValue::Value(val)) => alloc_value(val.clone()),
                _ => alloc_error(),
            },
        }
    }
}

pub extern "C" fn helper_has_tag(
    h: *const TaggedValue,
    t: *const TaggedValue,
    ctx: *const RuntimeCtx,
) -> *mut TaggedValue {
    unsafe {
        let tag_val = match extract_value(t) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let tag = match get_as_string(&tag_val) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let uid = match get_as_entity(&v) {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        match (*ctx).entities.entity(&uid) {
            Dereference::NoSuchEntity => alloc_bool(false),
            Dereference::Residual(_) => alloc_error(),
            Dereference::Data(entity) => alloc_bool(entity.get_tag(tag.as_str()).is_some()),
        }
    }
}

pub extern "C" fn helper_like(
    h: *const TaggedValue,
    ctx: *const RuntimeCtx,
    pattern_id: u64,
) -> *mut TaggedValue {
    unsafe {
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let s = match get_as_string(&v) {
            Some(s) => s.clone(),
            None => return alloc_error(),
        };
        let patterns = &(*ctx).patterns;
        let pattern = match patterns.get(pattern_id as usize) {
            Some(p) => p.clone(),
            None => return alloc_error(),
        };
        alloc_bool(pattern.wildcard_match(&s))
    }
}

pub extern "C" fn helper_is_entity_type(
    h: *const TaggedValue,
    ctx: *const RuntimeCtx,
    type_ptr: u64,
    type_len: u64,
) -> *mut TaggedValue {
    unsafe {
        let type_str = (*ctx).lookup_string(type_ptr, type_len);
        let v = match extract_value(h) {
            Some(v) => v,
            None => return alloc_error(),
        };
        let uid = match get_as_entity(&v) {
            Some(uid) => uid.clone(),
            None => return alloc_error(),
        };
        alloc_bool(uid.entity_type().to_string() == type_str.as_str())
    }
}

/// Build a set from an array of TaggedValue pointers.
/// Called as: helper_set_build(ctx, count, tv0, tv1, ...)
/// But since we can't do varargs in C easily, we pass a pointer to an array.
pub extern "C" fn helper_set_build(
    elems: *const *const TaggedValue,
    count: u64,
) -> *mut TaggedValue {
    unsafe {
        let mut vals = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let tv = *elems.add(i);
            match extract_value(tv) {
                Some(v) => vals.push(v),
                None => return alloc_error(),
            }
        }
        let val = Value::set(vals, None);
        alloc_value(val)
    }
}

/// Build a record from parallel arrays of (key_ptr, key_len, value_tv).
pub extern "C" fn helper_record_build(
    ctx: *const RuntimeCtx,
    keys: *const u64,   // pairs of (ptr, len) so keys[2*i], keys[2*i+1]
    vals: *const *const TaggedValue,
    count: u64,
) -> *mut TaggedValue {
    unsafe {
        let mut map: BTreeMap<SmolStr, Value> = BTreeMap::new();
        for i in 0..count as usize {
            let kptr = *keys.add(2 * i);
            let klen = *keys.add(2 * i + 1);
            let key = (*ctx).lookup_string(kptr, klen);
            let tv = *vals.add(i);
            match extract_value(tv) {
                Some(v) => { map.insert(key, v); }
                None => return alloc_error(),
            }
        }
        let val = Value::record_arc(Arc::new(map), None);
        alloc_value(val)
    }
}

/// Call a Cedar extension function by name with the given arguments.
pub extern "C" fn helper_ext_call(
    ctx: *const RuntimeCtx,
    name_ptr: u64,
    name_len: u64,
    args: *const *const TaggedValue,
    arg_count: u64,
) -> *mut TaggedValue {
    unsafe {
        let fn_name_str = (*ctx).lookup_string(name_ptr, name_len);
        let fn_name: ast::Name = match fn_name_str.parse() {
            Ok(n) => n,
            Err(_) => return alloc_error(),
        };

        let mut arg_vals = Vec::with_capacity(arg_count as usize);
        for i in 0..arg_count as usize {
            let tv = *args.add(i);
            match extract_value(tv) {
                Some(v) => arg_vals.push(v),
                None => return alloc_error(),
            }
        }

        let func = match (*ctx).extensions.func(&fn_name) {
            Ok(f) => f,
            Err(_) => return alloc_error(),
        };

        match func.call(&arg_vals) {
            Ok(PartialValue::Value(v)) => alloc_value(v),
            _ => alloc_error(),
        }
    }
}
