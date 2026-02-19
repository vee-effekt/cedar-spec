use cedar_policy_core::ast::{self, EntityType, EntityUID, Literal, PartialValue, Value, ValueKind};
use cedar_policy_core::entities::{Dereference, Entities};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::types::{AttributeType, Primitive, Type, EntityRecordKind, OpenTag};
use cedar_policy_core::validator::ValidatorSchema;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// How a single attribute slot is stored in flat memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    /// Raw i64 (8 bytes)
    Long,
    /// 0 or 1 as u64 (8 bytes)
    Bool,
    /// Pointer to a Cedar Value on the heap (8 bytes)
    Value,
}

/// One attribute slot in a flat entity layout.
#[derive(Debug, Clone)]
pub struct AttrSlot {
    pub name: SmolStr,
    pub offset: usize,
    pub slot_type: SlotType,
    pub required: bool,
}

/// Flat memory layout for one entity type.
///
/// Layout in memory:
/// ```text
/// [presence_bitmap: u64]    byte 0..8   — bit i = 1 if slot i is present
/// [slot_0: 8 bytes]         byte 8..16  — first attribute
/// [slot_1: 8 bytes]         byte 16..24
/// ...
/// [slot_n: 8 bytes]
/// [ancestors: *const ()]    last 8 bytes — pointer to ancestor set
/// ```
#[derive(Debug, Clone)]
pub struct EntityLayout {
    pub attrs: Vec<AttrSlot>,
    pub ancestors_offset: usize,
    pub total_size: usize,
    pub open: bool,
}

/// Precomputed layouts for all entity types in a schema.
#[derive(Debug, Clone)]
pub struct SchemaLayout {
    pub entity_layouts: HashMap<EntityType, EntityLayout>,
    /// Fast lookup: (entity_type, attr_name) -> (slot_index, slot_type, required)
    pub attr_indices: HashMap<(EntityType, SmolStr), (usize, SlotType, bool)>,
}

fn classify_type(ty: &Type) -> SlotType {
    match ty {
        Type::Primitive { primitive_type: Primitive::Long } => SlotType::Long,
        Type::Primitive { primitive_type: Primitive::Bool } => SlotType::Bool,
        Type::True | Type::False => SlotType::Bool,
        _ => SlotType::Value,
    }
}

impl SchemaLayout {
    /// Build entity layouts from a ValidatorSchema.
    pub fn from_schema(schema: &ValidatorSchema) -> Self {
        let mut entity_layouts = HashMap::new();
        let mut attr_indices = HashMap::new();

        for ety in schema.entity_types() {
            let entity_type = ety.name().clone();
            let is_open = ety.open_attributes() == OpenTag::OpenAttributes;

            // Collect and sort attributes alphabetically for deterministic layout
            let mut attr_entries: Vec<(SmolStr, &AttributeType)> = ety
                .attributes()
                .iter()
                .map(|(name, attr)| (name.clone(), attr))
                .collect();
            attr_entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut slots = Vec::with_capacity(attr_entries.len());
            for (i, (name, attr)) in attr_entries.iter().enumerate() {
                let slot_type = classify_type(&attr.attr_type);
                let offset = 8 + i * 8; // skip bitmap
                let required = attr.is_required();

                slots.push(AttrSlot {
                    name: name.clone(),
                    offset,
                    slot_type,
                    required,
                });

                attr_indices.insert(
                    (entity_type.clone(), name.clone()),
                    (i, slot_type, required),
                );
            }

            let ancestors_offset = 8 + slots.len() * 8;
            let total_size = ancestors_offset + 8;

            entity_layouts.insert(
                entity_type,
                EntityLayout {
                    attrs: slots,
                    ancestors_offset,
                    total_size,
                    open: is_open,
                },
            );
        }

        SchemaLayout {
            entity_layouts,
            attr_indices,
        }
    }
}

// ==================== Compiled Entity Store ====================

/// Flat entity data for all entities, indexed by EntityUID.
pub struct CompiledEntityStore {
    pub layout: Arc<SchemaLayout>,
    /// UID -> pointer to flat entity data
    entities: HashMap<EntityUID, *const u8>,
    /// Owns the allocated flat data buffers
    _backing: Vec<Vec<u8>>,
    /// Owns the boxed ancestor sets (to drop them properly)
    _ancestor_sets: Vec<Box<HashSet<EntityUID>>>,
    /// Owns the boxed Values for complex-type slots
    _values: Vec<Box<Value>>,
}

unsafe impl Send for CompiledEntityStore {}
unsafe impl Sync for CompiledEntityStore {}

fn set_presence_bit(data: &mut [u8], bit: usize) {
    let bitmap = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let new_bitmap = bitmap | (1u64 << bit);
    data[0..8].copy_from_slice(&new_bitmap.to_ne_bytes());
}

impl CompiledEntityStore {
    /// Build a compiled entity store from Cedar entities using the schema layout.
    pub fn new(layout: Arc<SchemaLayout>, entities: &Entities) -> Self {
        let mut entity_map = HashMap::new();
        let mut backing = Vec::new();
        let mut ancestor_sets = Vec::new();
        let mut values = Vec::new();

        for entity in entities.iter() {
            let entity_type = entity.uid().entity_type();
            let Some(entity_layout) = layout.entity_layouts.get(entity_type) else {
                // Entity type not in schema (e.g., Action entities) — skip
                continue;
            };

            let mut data = vec![0u8; entity_layout.total_size];

            // Fill attribute slots
            for (i, slot) in entity_layout.attrs.iter().enumerate() {
                if let Some(pv) = entity.get(&slot.name) {
                    if let PartialValue::Value(val) = pv {
                        set_presence_bit(&mut data, i);
                        match slot.slot_type {
                            SlotType::Long => {
                                if let ValueKind::Lit(Literal::Long(n)) = val.value_kind() {
                                    data[slot.offset..slot.offset + 8]
                                        .copy_from_slice(&(*n).to_ne_bytes());
                                }
                            }
                            SlotType::Bool => {
                                if let ValueKind::Lit(Literal::Bool(b)) = val.value_kind() {
                                    let v = *b as u64;
                                    data[slot.offset..slot.offset + 8]
                                        .copy_from_slice(&v.to_ne_bytes());
                                }
                            }
                            SlotType::Value => {
                                let boxed = Box::new(val.clone());
                                let ptr = &*boxed as *const Value as u64;
                                data[slot.offset..slot.offset + 8]
                                    .copy_from_slice(&ptr.to_ne_bytes());
                                values.push(boxed);
                            }
                        }
                    }
                }
            }

            // Store ancestor set
            let ancestors: HashSet<EntityUID> = entity.ancestors().cloned().collect();
            let anc_box = Box::new(ancestors);
            let anc_ptr = &*anc_box as *const HashSet<EntityUID> as u64;
            data[entity_layout.ancestors_offset..entity_layout.ancestors_offset + 8]
                .copy_from_slice(&anc_ptr.to_ne_bytes());
            ancestor_sets.push(anc_box);

            let ptr = data.as_ptr();
            entity_map.insert(entity.uid().clone(), ptr);
            backing.push(data);
        }

        CompiledEntityStore {
            layout,
            entities: entity_map,
            _backing: backing,
            _ancestor_sets: ancestor_sets,
            _values: values,
        }
    }

    /// Look up flat entity data by UID. Returns null pointer if not found.
    pub fn get(&self, uid: &EntityUID) -> *const u8 {
        self.entities.get(uid).copied().unwrap_or(std::ptr::null())
    }
}

/// Runtime context for schema-directed compiled code.
/// Principal and resource entity data are pre-resolved.
#[repr(C)]
pub struct CompiledRuntimeCtx {
    /// Pointer to flat principal entity data (null if not found)
    pub principal_data: *const u8,
    /// Pointer to flat resource entity data (null if not found)
    pub resource_data: *const u8,
    /// The compiled entity store (for `in` checks and chained entity lookups)
    pub entity_store: *const CompiledEntityStore,
    /// The original request (for context and fallback)
    pub request: ast::Request,
    /// The original entities (for fallback when schema info is unavailable)
    pub entities: Entities,
    pub extensions: &'static Extensions<'static>,
    pub patterns: Vec<ast::Pattern>,
    pub interned_strings: Vec<(SmolStr, usize)>,
    pub string_pool: Vec<u8>,
}

impl CompiledRuntimeCtx {
    pub fn new(
        request: &ast::Request,
        entities: &Entities,
        entity_store: &CompiledEntityStore,
        patterns: Vec<ast::Pattern>,
        interned_strings: Vec<(SmolStr, usize)>,
        string_pool: Vec<u8>,
    ) -> Self {
        // Pre-resolve principal and resource
        let principal_data = request
            .principal()
            .uid()
            .map(|uid| entity_store.get(uid))
            .unwrap_or(std::ptr::null());
        let resource_data = request
            .resource()
            .uid()
            .map(|uid| entity_store.get(uid))
            .unwrap_or(std::ptr::null());

        Self {
            principal_data,
            resource_data,
            entity_store: entity_store as *const CompiledEntityStore,
            request: request.clone(),
            entities: entities.clone(),
            extensions: Extensions::all_available(),
            patterns,
            interned_strings,
            string_pool,
        }
    }
}
