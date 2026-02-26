/// Schema-directed entity layout (stub for future optimization).

use cedar_policy_core::ast::EntityUID;
use cedar_policy_core::entities::Entities;
use std::sync::Arc;

/// Schema layout information for optimized entity attribute access.
/// Currently a stub — will be populated with per-type attribute offset tables.
pub struct SchemaLayout {
    // Placeholder for future schema-directed compilation
}

/// Pre-compiled entity store with flattened attribute layout.
/// Currently delegates to standard entity lookups.
pub struct CompiledEntityStore {
    _layout: Arc<SchemaLayout>,
}

impl CompiledEntityStore {
    pub fn new(layout: Arc<SchemaLayout>, _entities: &Entities) -> Self {
        Self { _layout: layout }
    }

    /// Look up the flat data pointer for an entity.
    /// Currently returns null (no optimization).
    pub fn get(&self, _uid: &EntityUID) -> *const u8 {
        std::ptr::null()
    }
}
