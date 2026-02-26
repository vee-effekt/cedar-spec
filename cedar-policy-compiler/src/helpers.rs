/// RuntimeCtx holds the request, entities, and temporary storage for compiled code execution.

use cedar_policy_core::ast::{self, EntityUID, Pattern, Value};
use cedar_policy_core::entities::Entities;
use smol_str::SmolStr;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Our own IP address representation, matching Cedar's private IPAddr struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerIpAddr {
    pub addr: std::net::IpAddr,
    pub prefix: u8,
}

pub struct RuntimeCtx<'a> {
    pub request: &'a ast::Request,
    pub entities: &'a Entities,
    /// Pre-extracted context record (if available)
    pub context_record: Option<Arc<BTreeMap<SmolStr, Value>>>,
    /// Interned patterns used by `like` expressions
    pub patterns: Arc<Vec<Pattern>>,
    /// Interned string keys for extension function names, attribute names, etc.
    pub interned_strings: Arc<Vec<String>>,
    /// String pool for string literals referenced by compiled code
    pub string_pool: Arc<Vec<SmolStr>>,
    /// Temporary storage for heap-allocated values produced during evaluation.
    /// These are pinned for pointer stability during a single call.
    temp_strings: RefCell<Vec<Box<SmolStr>>>,
    temp_entities: RefCell<Vec<Box<EntityUID>>>,
    temp_sets: RefCell<Vec<Box<BTreeSet<Value>>>>,
    temp_records: RefCell<Vec<Box<BTreeMap<SmolStr, Value>>>>,
    temp_exts: RefCell<Vec<Box<Value>>>,
    temp_ipaddrs: RefCell<Vec<Box<CompilerIpAddr>>>,
}

impl<'a> RuntimeCtx<'a> {
    pub fn new(
        request: &'a ast::Request,
        entities: &'a Entities,
        patterns: Arc<Vec<Pattern>>,
        interned_strings: Arc<Vec<String>>,
        string_pool: Arc<Vec<SmolStr>>,
    ) -> Self {
        let context_record = extract_context(request);
        Self {
            request,
            entities,
            context_record,
            patterns,
            interned_strings,
            string_pool,
            temp_strings: RefCell::new(Vec::new()),
            temp_entities: RefCell::new(Vec::new()),
            temp_sets: RefCell::new(Vec::new()),
            temp_records: RefCell::new(Vec::new()),
            temp_exts: RefCell::new(Vec::new()),
            temp_ipaddrs: RefCell::new(Vec::new()),
        }
    }

    pub fn new_with_flat_data(
        request: &'a ast::Request,
        entities: &'a Entities,
        _principal_data: *const u8,
        _resource_data: *const u8,
        patterns: Arc<Vec<Pattern>>,
        interned_strings: Arc<Vec<String>>,
        string_pool: Arc<Vec<SmolStr>>,
    ) -> Self {
        // For now, flat data pointers are unused (schema-directed layout optimization).
        // We fall back to the standard entity store lookup.
        Self::new(request, entities, patterns, interned_strings, string_pool)
    }

    // Temporary storage methods — return index, then get stable pointer by index.

    pub fn push_temp_string(&self, s: SmolStr) -> usize {
        let mut v = self.temp_strings.borrow_mut();
        let idx = v.len();
        v.push(Box::new(s));
        idx
    }

    pub fn get_temp_string(&self, idx: usize) -> *const SmolStr {
        let v = self.temp_strings.borrow();
        &**v.get(idx).unwrap() as *const SmolStr
    }

    pub fn push_temp_entity(&self, uid: EntityUID) -> usize {
        let mut v = self.temp_entities.borrow_mut();
        let idx = v.len();
        v.push(Box::new(uid));
        idx
    }

    pub fn get_temp_entity(&self, idx: usize) -> *const EntityUID {
        let v = self.temp_entities.borrow();
        &**v.get(idx).unwrap() as *const EntityUID
    }

    pub fn push_temp_set(&self, set: BTreeSet<Value>) -> usize {
        let mut v = self.temp_sets.borrow_mut();
        let idx = v.len();
        v.push(Box::new(set));
        idx
    }

    pub fn get_temp_set(&self, idx: usize) -> *const BTreeSet<Value> {
        let v = self.temp_sets.borrow();
        &**v.get(idx).unwrap() as *const BTreeSet<Value>
    }

    pub fn push_temp_record(&self, rec: BTreeMap<SmolStr, Value>) -> usize {
        let mut v = self.temp_records.borrow_mut();
        let idx = v.len();
        v.push(Box::new(rec));
        idx
    }

    pub fn get_temp_record(&self, idx: usize) -> *const BTreeMap<SmolStr, Value> {
        let v = self.temp_records.borrow();
        &**v.get(idx).unwrap() as *const BTreeMap<SmolStr, Value>
    }

    pub fn push_temp_ext(&self, val: Value) -> usize {
        let mut v = self.temp_exts.borrow_mut();
        let idx = v.len();
        v.push(Box::new(val));
        idx
    }

    pub fn get_temp_ext(&self, idx: usize) -> *const Value {
        let v = self.temp_exts.borrow();
        &**v.get(idx).unwrap() as *const Value
    }

    pub fn push_temp_ipaddr(&self, ip: CompilerIpAddr) -> usize {
        let mut v = self.temp_ipaddrs.borrow_mut();
        let idx = v.len();
        v.push(Box::new(ip));
        idx
    }

    pub fn get_temp_ipaddr(&self, idx: usize) -> *const CompilerIpAddr {
        let v = self.temp_ipaddrs.borrow();
        &**v.get(idx).unwrap() as *const CompilerIpAddr
    }
}

fn extract_context(request: &ast::Request) -> Option<Arc<BTreeMap<SmolStr, Value>>> {
    use ast::Context;
    request.context().and_then(|ctx| {
        match ctx {
            Context::Value(map) => {
                Some(Arc::clone(map))
            }
            Context::RestrictedResidual(_) => {
                // Cannot extract concrete values from residuals
                None
            }
        }
    })
}
