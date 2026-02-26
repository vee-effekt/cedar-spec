/// Runtime value representation and extern "C" helper functions called by compiled code.

use crate::helpers::{CompilerIpAddr, RuntimeCtx};
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
pub const TAG_DECIMAL: u64 = 8;
pub const TAG_IPADDR: u64 = 9;
pub const TAG_DATETIME: u64 = 10;
pub const TAG_DURATION: u64 = 11;

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

    pub fn decimal_val(v: i64) -> Self {
        Self { tag: TAG_DECIMAL, payload: v as u64 }
    }

    pub fn ipaddr_ptr(p: *const CompilerIpAddr) -> Self {
        Self { tag: TAG_IPADDR, payload: p as u64 }
    }

    pub fn datetime_val(v: i64) -> Self {
        Self { tag: TAG_DATETIME, payload: v as u64 }
    }

    pub fn duration_val(v: i64) -> Self {
        Self { tag: TAG_DURATION, payload: v as u64 }
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
    // Fast paths for custom extension tags
    if lt != rt {
        // Different tags: check if both are value-carrying tags (not error)
        // Different types can't be equal in Cedar
        if lt != TAG_ERROR && rt != TAG_ERROR {
            return RuntimeValue::bool_val(false);
        }
        return RuntimeValue::error();
    }
    match lt {
        TAG_DECIMAL | TAG_DATETIME | TAG_DURATION => {
            return RuntimeValue::bool_val(lp == rp);
        }
        TAG_IPADDR => {
            let a = unsafe { &*(lp as *const CompilerIpAddr) };
            let b = unsafe { &*(rp as *const CompilerIpAddr) };
            return RuntimeValue::bool_val(a.addr == b.addr && a.prefix == b.prefix);
        }
        _ => {}
    }
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
    if lt == TAG_LONG && rt == TAG_LONG {
        return RuntimeValue::bool_val((lp as i64) < (rp as i64));
    }
    // Fast paths for custom tags (all i64 comparisons)
    if lt == rt {
        match lt {
            TAG_DECIMAL | TAG_DATETIME | TAG_DURATION => {
                return RuntimeValue::bool_val((lp as i64) < (rp as i64));
            }
            _ => {}
        }
    }
    // Extension type comparison fallback
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
    if lt == rt {
        match lt {
            TAG_DECIMAL | TAG_DATETIME | TAG_DURATION => {
                return RuntimeValue::bool_val((lp as i64) <= (rp as i64));
            }
            _ => {}
        }
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

// ---- Extension function helpers ----
//
// Custom tags: TAG_DECIMAL, TAG_IPADDR, TAG_DATETIME, TAG_DURATION
// These use inline representations (i64 or pointer) instead of Cedar's private types.
// Constructors parse strings directly; operations work on raw data.

/// Call a Cedar extension function by name. Used only for to_cedar_value reconstruction
/// and the generic rt_call_extension fallback.
fn call_ext(fn_name: &str, args: &[Value]) -> Result<Value, ()> {
    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::ast::Name;
    use std::str::FromStr;

    let exts = Extensions::all_available();
    let name = Name::from_str(fn_name).map_err(|_| ())?;
    let func = exts.func(&name).map_err(|_| ())?;
    match func.call(args) {
        Ok(PartialValue::Value(v)) => Ok(v),
        _ => Err(()),
    }
}

// ---- Decimal parsing ----
// Format: ^(-?\d+)\.(\d+)$, 1-4 fractional digits, stored as i64 * 10^4

fn parse_decimal(s: &str) -> Option<i64> {
    let dot = s.find('.')?;
    if dot == 0 || (dot == 1 && s.starts_with('-')) {
        // Nothing before dot (or just "-")
        // Actually, "-0.5" is valid, "-.5" is not, ".5" is not
        if dot == 0 { return None; }
        // dot==1 && starts_with('-') means just "-." which is invalid if dot+1 has no digits
    }
    let int_part_str = &s[..dot];
    let frac_part_str = &s[dot + 1..];

    // Fractional part must be 1-4 digits, all ASCII digits
    if frac_part_str.is_empty() || frac_part_str.len() > 4 {
        return None;
    }
    if !frac_part_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    // Integer part must be digits with optional leading '-'
    let (negative, digits) = if let Some(rest) = int_part_str.strip_prefix('-') {
        (true, rest)
    } else {
        (false, int_part_str)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let int_val: i64 = int_part_str.parse().ok()?;
    let scaled_int = int_val.checked_mul(10_000)?;

    // Parse fractional digits, right-pad to 4 digits
    let mut frac_val: i64 = frac_part_str.parse().ok()?;
    for _ in 0..(4 - frac_part_str.len()) {
        frac_val *= 10;
    }

    if negative {
        scaled_int.checked_sub(frac_val)
    } else {
        scaled_int.checked_add(frac_val)
    }
}

// ---- IP address parsing ----
// Parse CIDR notation, reject IPv4-in-IPv6, validate prefix ranges

const IP_STR_REP_MAX_LEN: usize = 43;

fn parse_ip(s: &str) -> Option<CompilerIpAddr> {
    if s.len() > IP_STR_REP_MAX_LEN {
        return None;
    }
    // Reject IPv4-in-IPv6 notation: >= 2 colons AND >= 2 dots
    let colon_count = s.bytes().filter(|&b| b == b':').count();
    let dot_count = s.bytes().filter(|&b| b == b'.').count();
    if colon_count >= 2 && dot_count >= 2 {
        return None;
    }

    if let Some(slash_pos) = s.find('/') {
        let addr_str = &s[..slash_pos];
        let prefix_str = &s[slash_pos + 1..];

        let addr: std::net::IpAddr = addr_str.parse().ok()?;

        // Validate prefix string: all ASCII digits, no leading zeros (unless "0")
        if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if prefix_str.len() > 1 && prefix_str.starts_with('0') {
            return None;
        }

        let max_prefix_len = if addr.is_ipv4() { 2 } else { 3 };
        if prefix_str.len() > max_prefix_len {
            return None;
        }

        let prefix: u8 = prefix_str.parse().ok()?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return None;
        }

        Some(CompilerIpAddr { addr, prefix })
    } else {
        let addr: std::net::IpAddr = s.parse().ok()?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Some(CompilerIpAddr { addr, prefix })
    }
}

// ---- DateTime parsing ----
// Format: YYYY-MM-DDThh:mm:ss[.SSS](Z|+/-HHMM), stored as i64 epoch milliseconds

fn parse_datetime(s: &str) -> Option<i64> {
    use chrono::NaiveDate;

    let bytes = s.as_bytes();
    // Must start with YYYY-MM-DD (at least 10 chars)
    if bytes.len() < 10 {
        return None;
    }

    // Parse date: YYYY-MM-DD
    let year_str = &s[0..4];
    if bytes[4] != b'-' { return None; }
    let month_str = &s[5..7];
    if bytes[7] != b'-' { return None; }
    let day_str = &s[8..10];

    if !year_str.bytes().all(|b| b.is_ascii_digit())
        || !month_str.bytes().all(|b| b.is_ascii_digit())
        || !day_str.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let year: i32 = year_str.parse().ok()?;
    let month: u32 = month_str.parse().ok()?;
    let day: u32 = day_str.parse().ok()?;

    let date = NaiveDate::from_ymd_opt(year, month, day)?;

    if bytes.len() == 10 {
        // Date only: time defaults to 00:00:00 UTC
        let dt = date.and_hms_opt(0, 0, 0)?;
        return Some(dt.and_utc().timestamp_millis());
    }

    // Must have 'T' followed by HH:MM:SS
    if bytes.len() < 19 || bytes[10] != b'T' {
        return None;
    }

    let hour_str = &s[11..13];
    if bytes[13] != b':' { return None; }
    let min_str = &s[14..16];
    if bytes[16] != b':' { return None; }
    let sec_str = &s[17..19];

    if !hour_str.bytes().all(|b| b.is_ascii_digit())
        || !min_str.bytes().all(|b| b.is_ascii_digit())
        || !sec_str.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let hour: u32 = hour_str.parse().ok()?;
    let min: u32 = min_str.parse().ok()?;
    let sec: u32 = sec_str.parse().ok()?;

    let dt = date.and_hms_opt(hour, min, sec)?;
    let rest = &s[19..];

    // Parse optional milliseconds and timezone
    let (millis, tz_rest) = if let Some(after_dot) = rest.strip_prefix('.') {
        if after_dot.len() < 3 {
            return None;
        }
        let ms_str = &after_dot[..3];
        if !ms_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let ms: i64 = ms_str.parse().ok()?;
        (ms, &after_dot[3..])
    } else {
        (0i64, rest)
    };

    // Parse timezone: Z or +HHMM or -HHMM
    let offset_ms: i64 = if tz_rest == "Z" {
        0
    } else if tz_rest.len() == 5 {
        let sign = match tz_rest.as_bytes()[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return None,
        };
        let off_str = &tz_rest[1..];
        if !off_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let off_h: i64 = off_str[0..2].parse().ok()?;
        let off_m: i64 = off_str[2..4].parse().ok()?;
        if off_h > 23 || off_m > 59 {
            return None;
        }
        sign * (off_h * 3_600_000 + off_m * 60_000)
    } else {
        return None;
    };

    let epoch_ms = dt.and_utc().timestamp_millis();
    Some(epoch_ms.checked_add(millis)?.checked_sub(offset_ms)?)
}

// ---- Duration parsing ----
// Format: [-](Xd)(Xh)(Xm)(Xs)(Xms), stored as i64 milliseconds

fn parse_duration(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }

    let (negative, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else {
        (false, s)
    };

    if rest.is_empty() {
        return None;
    }

    let mut pos = 0;
    let bytes = rest.as_bytes();
    let mut total_ms: i64 = 0;
    let mut matched_any = false;

    // Parse each unit in order: d, h, m, s, ms
    // Days
    if let Some((val, new_pos)) = parse_duration_unit(bytes, pos, b'd') {
        total_ms = total_ms.checked_add((val as i64).checked_mul(86_400_000)?)?;
        pos = new_pos;
        matched_any = true;
    }
    // Hours
    if let Some((val, new_pos)) = parse_duration_unit(bytes, pos, b'h') {
        total_ms = total_ms.checked_add((val as i64).checked_mul(3_600_000)?)?;
        pos = new_pos;
        matched_any = true;
    }
    // Minutes — but don't consume 'ms' prefix
    if pos < bytes.len() && bytes[pos].is_ascii_digit() {
        // Check if this is minutes (m) not milliseconds (ms)
        // Find end of digits
        let digit_end = bytes[pos..].iter().position(|b| !b.is_ascii_digit()).map(|p| pos + p).unwrap_or(bytes.len());
        if digit_end < bytes.len() && bytes[digit_end] == b'm' && (digit_end + 1 >= bytes.len() || bytes[digit_end + 1] != b's') {
            let val: u64 = rest[pos..digit_end].parse().ok()?;
            total_ms = total_ms.checked_add((val as i64).checked_mul(60_000)?)?;
            pos = digit_end + 1;
            matched_any = true;
        }
    }
    // Seconds — but don't consume if no digit before 's'
    if let Some((val, new_pos)) = parse_duration_unit(bytes, pos, b's') {
        // Make sure we don't accidentally match 'ms' — check the char before 's' was a digit
        total_ms = total_ms.checked_add((val as i64).checked_mul(1_000)?)?;
        pos = new_pos;
        matched_any = true;
    }
    // Milliseconds
    if pos < bytes.len() && bytes[pos].is_ascii_digit() {
        let digit_end = bytes[pos..].iter().position(|b| !b.is_ascii_digit()).map(|p| pos + p).unwrap_or(bytes.len());
        if digit_end + 1 < bytes.len() && bytes[digit_end] == b'm' && bytes[digit_end + 1] == b's' {
            let val: u64 = rest[pos..digit_end].parse().ok()?;
            total_ms = total_ms.checked_add(val as i64)?;
            pos = digit_end + 2;
            matched_any = true;
        }
    }

    if !matched_any || pos != bytes.len() {
        return None;
    }

    if negative {
        Some(total_ms.checked_neg()?)
    } else {
        Some(total_ms)
    }
}

fn parse_duration_unit(bytes: &[u8], pos: usize, unit: u8) -> Option<(u64, usize)> {
    if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
        return None;
    }
    let digit_end = bytes[pos..].iter().position(|b| !b.is_ascii_digit()).map(|p| pos + p).unwrap_or(bytes.len());
    if digit_end >= bytes.len() || bytes[digit_end] != unit {
        return None;
    }
    let val: u64 = std::str::from_utf8(&bytes[pos..digit_end]).ok()?.parse().ok()?;
    Some((val, digit_end + 1))
}

// ---- IP address extension ----

#[no_mangle]
pub extern "C" fn rt_ext_ip(ctx: *const RuntimeCtx, tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_STRING { return RuntimeValue::error(); }
    let s = unsafe { &*(payload as *const SmolStr) };
    match parse_ip(s.as_str()) {
        Some(ip) => {
            let ctx = unsafe { &*ctx };
            let idx = ctx.push_temp_ipaddr(ip);
            let ptr = ctx.get_temp_ipaddr(idx);
            RuntimeValue::ipaddr_ptr(ptr)
        }
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_is_ipv4(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_IPADDR { return RuntimeValue::error(); }
    let ip = unsafe { &*(payload as *const CompilerIpAddr) };
    RuntimeValue::bool_val(ip.addr.is_ipv4())
}

#[no_mangle]
pub extern "C" fn rt_ext_is_ipv6(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_IPADDR { return RuntimeValue::error(); }
    let ip = unsafe { &*(payload as *const CompilerIpAddr) };
    RuntimeValue::bool_val(ip.addr.is_ipv6())
}

#[no_mangle]
pub extern "C" fn rt_ext_is_loopback(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_IPADDR { return RuntimeValue::error(); }
    let ip = unsafe { &*(payload as *const CompilerIpAddr) };
    RuntimeValue::bool_val(ip.addr.is_loopback())
}

#[no_mangle]
pub extern "C" fn rt_ext_is_multicast(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_IPADDR { return RuntimeValue::error(); }
    let ip = unsafe { &*(payload as *const CompilerIpAddr) };
    RuntimeValue::bool_val(ip.addr.is_multicast())
}

#[no_mangle]
pub extern "C" fn rt_ext_is_in_range(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_IPADDR || t2 != TAG_IPADDR { return RuntimeValue::error(); }
    let ip1 = unsafe { &*(p1 as *const CompilerIpAddr) };
    let ip2 = unsafe { &*(p2 as *const CompilerIpAddr) };
    RuntimeValue::bool_val(ip_in_range(ip1.addr, ip1.prefix, ip2.addr, ip2.prefix))
}

fn ip_in_range(addr: std::net::IpAddr, self_prefix: u8, network: std::net::IpAddr, net_prefix: u8) -> bool {
    // self must have equal or more specific prefix than the network
    if self_prefix < net_prefix {
        return false;
    }
    match (addr, network) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            if net_prefix > 32 { return false; }
            let mask = if net_prefix == 0 { 0u32 } else { u32::MAX << (32 - net_prefix) };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            if net_prefix > 128 { return false; }
            let mask = if net_prefix == 0 { 0u128 } else { u128::MAX << (128 - net_prefix) };
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

// ---- Decimal extension ----

#[no_mangle]
pub extern "C" fn rt_ext_decimal(_ctx: *const RuntimeCtx, tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_STRING { return RuntimeValue::error(); }
    let s = unsafe { &*(payload as *const SmolStr) };
    match parse_decimal(s.as_str()) {
        Some(v) => RuntimeValue::decimal_val(v),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_less_than(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DECIMAL || t2 != TAG_DECIMAL { return RuntimeValue::error(); }
    RuntimeValue::bool_val((p1 as i64) < (p2 as i64))
}

#[no_mangle]
pub extern "C" fn rt_ext_less_than_or_equal(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DECIMAL || t2 != TAG_DECIMAL { return RuntimeValue::error(); }
    RuntimeValue::bool_val((p1 as i64) <= (p2 as i64))
}

#[no_mangle]
pub extern "C" fn rt_ext_greater_than(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DECIMAL || t2 != TAG_DECIMAL { return RuntimeValue::error(); }
    RuntimeValue::bool_val((p1 as i64) > (p2 as i64))
}

#[no_mangle]
pub extern "C" fn rt_ext_greater_than_or_equal(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DECIMAL || t2 != TAG_DECIMAL { return RuntimeValue::error(); }
    RuntimeValue::bool_val((p1 as i64) >= (p2 as i64))
}

// ---- DateTime/Duration extension ----

#[no_mangle]
pub extern "C" fn rt_ext_datetime(_ctx: *const RuntimeCtx, tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_STRING { return RuntimeValue::error(); }
    let s = unsafe { &*(payload as *const SmolStr) };
    match parse_datetime(s.as_str()) {
        Some(ms) => RuntimeValue::datetime_val(ms),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_duration(_ctx: *const RuntimeCtx, tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_STRING { return RuntimeValue::error(); }
    let s = unsafe { &*(payload as *const SmolStr) };
    match parse_duration(s.as_str()) {
        Some(ms) => RuntimeValue::duration_val(ms),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_offset(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DATETIME || t2 != TAG_DURATION { return RuntimeValue::error(); }
    match (p1 as i64).checked_add(p2 as i64) {
        Some(r) => RuntimeValue::datetime_val(r),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_duration_since(t1: u64, p1: u64, t2: u64, p2: u64) -> RuntimeValue {
    if t1 != TAG_DATETIME || t2 != TAG_DATETIME { return RuntimeValue::error(); }
    match (p1 as i64).checked_sub(p2 as i64) {
        Some(r) => RuntimeValue::duration_val(r),
        None => RuntimeValue::error(),
    }
}

#[no_mangle]
pub extern "C" fn rt_ext_to_date(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DATETIME { return RuntimeValue::error(); }
    let ms = payload as i64;
    // Floor divide by 86400000 (ms per day), multiply back
    let day_ms: i64 = 86_400_000;
    let date_ms = ms.div_euclid(day_ms) * day_ms;
    RuntimeValue::datetime_val(date_ms)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_time(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DATETIME { return RuntimeValue::error(); }
    let ms = payload as i64;
    let day_ms: i64 = 86_400_000;
    let time_ms = ms.rem_euclid(day_ms);
    RuntimeValue::duration_val(time_ms)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_milliseconds(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DURATION { return RuntimeValue::error(); }
    RuntimeValue::long_val(payload as i64)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_seconds(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DURATION { return RuntimeValue::error(); }
    RuntimeValue::long_val((payload as i64) / 1000)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_minutes(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DURATION { return RuntimeValue::error(); }
    RuntimeValue::long_val((payload as i64) / 60_000)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_hours(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DURATION { return RuntimeValue::error(); }
    RuntimeValue::long_val((payload as i64) / 3_600_000)
}

#[no_mangle]
pub extern "C" fn rt_ext_to_days(tag: u64, payload: u64) -> RuntimeValue {
    if tag != TAG_DURATION { return RuntimeValue::error(); }
    RuntimeValue::long_val((payload as i64) / 86_400_000)
}

// ---- Generic extension function fallback ----

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

    match call_ext(fn_name, &args) {
        Ok(val) => value_to_runtime(ctx, &val),
        Err(_) => RuntimeValue::error(),
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
        TAG_DECIMAL => {
            let v = payload as i64;
            let display = decimal_to_string(v);
            call_ext("decimal", &[ast::Value::from(SmolStr::from(display))]).ok()
        }
        TAG_IPADDR => {
            let ip = unsafe { &*(payload as *const CompilerIpAddr) };
            let display = format!("{}/{}", ip.addr, ip.prefix);
            call_ext("ip", &[ast::Value::from(SmolStr::from(display.as_str()))]).ok()
        }
        TAG_DATETIME => {
            let ms = payload as i64;
            let display = epoch_to_rfc3339(ms);
            call_ext("datetime", &[ast::Value::from(SmolStr::from(display.as_str()))]).ok()
        }
        TAG_DURATION => {
            let ms = payload as i64;
            let display = ms_to_duration_string(ms);
            call_ext("duration", &[ast::Value::from(SmolStr::from(display.as_str()))]).ok()
        }
        _ => None,
    }
}

/// Format a decimal i64 (scaled by 10^4) to string like "1.2300"
fn decimal_to_string(v: i64) -> String {
    let negative = v < 0;
    let abs = if v == i64::MIN {
        // Handle i64::MIN carefully
        (v as i128).unsigned_abs() as u64
    } else {
        v.unsigned_abs()
    };
    let int_part = abs / 10_000;
    let frac_part = abs % 10_000;
    if negative {
        format!("-{}.{:04}", int_part, frac_part)
    } else {
        format!("{}.{:04}", int_part, frac_part)
    }
}

/// Format epoch milliseconds to RFC3339-like string for Cedar datetime constructor
fn epoch_to_rfc3339(ms: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ms.div_euclid(1000);
    let nsecs = (ms.rem_euclid(1000) * 1_000_000) as u32;
    match DateTime::<Utc>::from_timestamp(secs, nsecs) {
        Some(dt) => {
            if nsecs == 0 {
                dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
            }
        }
        None => format!("1970-01-01T00:00:00Z"),
    }
}

/// Format milliseconds to Cedar duration string (e.g., "5000ms")
fn ms_to_duration_string(ms: i64) -> String {
    // Cedar's Display for Duration just outputs "<N>ms"
    format!("{}ms", ms)
}

/// Parse a named i64 field from a Debug format string like "Decimal { value: 12300 }"
fn parse_debug_field_i64(dbg: &str, field: &str) -> Option<i64> {
    let needle = format!("{}: ", field);
    let start = dbg.find(&needle)? + needle.len();
    let end = dbg[start..].find([' ', ',', '}'])? + start;
    dbg[start..end].trim().parse::<i64>().ok()
}

/// Parse an IPAddr from Debug format: "IPAddr { addr: 1.2.3.4, prefix: 32 }"
fn parse_debug_ipaddr(dbg: &str) -> Option<CompilerIpAddr> {
    let addr_start = dbg.find("addr: ")? + 6;
    let addr_end = dbg[addr_start..].find(',')? + addr_start;
    let addr_str = dbg[addr_start..addr_end].trim();
    let addr: std::net::IpAddr = addr_str.parse().ok()?;

    let prefix_start = dbg.find("prefix: ")? + 8;
    let prefix_end = dbg[prefix_start..].find([' ', '}'])? + prefix_start;
    let prefix: u8 = dbg[prefix_start..prefix_end].trim().parse().ok()?;
    Some(CompilerIpAddr { addr, prefix })
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
        ValueKind::ExtensionValue(ext) => {
            let type_name = ext.value().typename().to_string();
            match type_name.as_str() {
                "decimal" => {
                    // Debug format: Decimal { value: N }
                    let dbg = format!("{:?}", ext.value());
                    if let Some(n) = parse_debug_field_i64(&dbg, "value") {
                        return RuntimeValue::decimal_val(n);
                    }
                }
                "ipaddr" => {
                    // Debug format: IPAddr { addr: <IpAddr>, prefix: N }
                    let dbg = format!("{:?}", ext.value());
                    if let Some(ip) = parse_debug_ipaddr(&dbg) {
                        let idx = ctx.push_temp_ipaddr(ip);
                        let ptr = ctx.get_temp_ipaddr(idx);
                        return RuntimeValue::ipaddr_ptr(ptr);
                    }
                }
                "datetime" => {
                    // Debug format: DateTime { epoch: N }
                    let dbg = format!("{:?}", ext.value());
                    if let Some(n) = parse_debug_field_i64(&dbg, "epoch") {
                        return RuntimeValue::datetime_val(n);
                    }
                }
                "duration" => {
                    // Debug format: Duration { ms: N }
                    let dbg = format!("{:?}", ext.value());
                    if let Some(n) = parse_debug_field_i64(&dbg, "ms") {
                        return RuntimeValue::duration_val(n);
                    }
                }
                _ => {}
            }
            // Fallback: keep as TAG_EXT
            let idx = ctx.push_temp_ext(val.clone());
            let ptr = ctx.get_temp_ext(idx);
            RuntimeValue::ext_ptr(ptr)
        }
    }
}

