//! CommonJS cache algebra and ESM adapter rules for the experimental graph.
//! @ref LLP 0026#7-commonjs-interop

use std::collections::{btree_map::Entry, BTreeMap};

use thiserror::Error;

use super::identity::ImportAttributes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommonJsLifecycle {
    Evaluating,
    Evaluated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommonJsRecord<V> {
    lifecycle: CommonJsLifecycle,
    exports: V,
}

/// Native-graph model of Node's early-publication CommonJS cache.
///
/// `publish` happens before body execution, so a cycle observes the mutable
/// partial exports. Successful completion preserves replacement identity;
/// failure evicts the record instead of caching an ESM-style sticky error.
#[derive(Clone, Debug, Default)]
pub struct CommonJsCache<K, V> {
    records: BTreeMap<K, CommonJsRecord<V>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommonJsLookup<V> {
    Published,
    Existing {
        lifecycle: CommonJsLifecycle,
        exports: V,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommonJsError {
    #[error("ERR_MODULE_NOT_FOUND: CommonJS record is absent")]
    Absent,
    #[error("ERR_MODULE_STATE: CommonJS record already completed")]
    AlreadyCompleted,
    #[error("ERR_IMPORT_ATTRIBUTE_MISSING: ESM JSON import requires type=json")]
    JsonAttributeMissing,
    #[error("ERR_IMPORT_ATTRIBUTE_UNSUPPORTED: CommonJS JSON require takes no import attributes")]
    JsonRequireAttributes,
}

impl<K: Ord + Clone, V: Clone> CommonJsCache<K, V> {
    pub fn publish(&mut self, key: K, initial_exports: V) -> CommonJsLookup<V> {
        match self.records.entry(key) {
            Entry::Vacant(vacant) => {
                vacant.insert(CommonJsRecord {
                    lifecycle: CommonJsLifecycle::Evaluating,
                    exports: initial_exports,
                });
                CommonJsLookup::Published
            }
            Entry::Occupied(occupied) => CommonJsLookup::Existing {
                lifecycle: occupied.get().lifecycle,
                exports: occupied.get().exports.clone(),
            },
        }
    }

    pub fn replace_exports(&mut self, key: &K, exports: V) -> Result<(), CommonJsError> {
        let record = self.records.get_mut(key).ok_or(CommonJsError::Absent)?;
        if record.lifecycle != CommonJsLifecycle::Evaluating {
            return Err(CommonJsError::AlreadyCompleted);
        }
        record.exports = exports;
        Ok(())
    }

    pub fn complete(&mut self, key: &K) -> Result<V, CommonJsError> {
        let record = self.records.get_mut(key).ok_or(CommonJsError::Absent)?;
        if record.lifecycle != CommonJsLifecycle::Evaluating {
            return Err(CommonJsError::AlreadyCompleted);
        }
        record.lifecycle = CommonJsLifecycle::Evaluated;
        Ok(record.exports.clone())
    }

    pub fn fail_and_evict(&mut self, key: &K) -> Result<V, CommonJsError> {
        self.records
            .remove(key)
            .map(|record| record.exports)
            .ok_or(CommonJsError::Absent)
    }

    pub fn get(&self, key: &K) -> Option<(CommonJsLifecycle, &V)> {
        self.records
            .get(key)
            .map(|record| (record.lifecycle, &record.exports))
    }
}

/// Frozen ESM view of one completed CommonJS record. Named detector results
/// are snapshots; later CommonJS mutation does not update this map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonJsNamespace<V> {
    pub bindings: BTreeMap<String, V>,
}

pub fn commonjs_namespace_snapshot<V: Clone>(
    final_exports: V,
    detected_names: impl IntoIterator<Item = String>,
    read_property: impl Fn(&V, &str) -> Option<V>,
) -> CommonJsNamespace<V> {
    let mut bindings = BTreeMap::new();
    for name in detected_names {
        if name == "default" || name == "module.exports" {
            continue;
        }
        if let Some(value) = read_property(&final_exports, &name) {
            bindings.insert(name, value);
        }
    }
    bindings.insert("default".into(), final_exports.clone());
    bindings.insert("module.exports".into(), final_exports);
    CommonJsNamespace { bindings }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequireEsmResult<V> {
    /// An explicit export named `module.exports` wins by key presence, even
    /// when its value is false, zero, null, or undefined-equivalent.
    Direct(V),
    Namespace {
        bindings: BTreeMap<String, V>,
        has_es_module_marker: bool,
    },
}

pub fn select_require_esm_result<V: Clone>(namespace: &BTreeMap<String, V>) -> RequireEsmResult<V> {
    if let Some(value) = namespace.get("module.exports") {
        return RequireEsmResult::Direct(value.clone());
    }
    RequireEsmResult::Namespace {
        bindings: namespace.clone(),
        has_es_module_marker: namespace.contains_key("default"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonConsumer {
    EsmImport,
    CommonJsRequire,
}

pub fn validate_json_attributes(
    consumer: JsonConsumer,
    attributes: &ImportAttributes,
) -> Result<(), CommonJsError> {
    match consumer {
        JsonConsumer::EsmImport if attributes.asserts_json() => Ok(()),
        JsonConsumer::EsmImport => Err(CommonJsError::JsonAttributeMissing),
        JsonConsumer::CommonJsRequire if attributes.is_empty() => Ok(()),
        JsonConsumer::CommonJsRequire => Err(CommonJsError::JsonRequireAttributes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cycles_see_early_exports_and_throwing_records_are_evicted() {
        let mut cache = CommonJsCache::default();
        assert_eq!(
            cache.publish("a", json!({"partial": 1})),
            CommonJsLookup::Published
        );
        assert_eq!(
            cache.publish("a", json!({"ignored": true})),
            CommonJsLookup::Existing {
                lifecycle: CommonJsLifecycle::Evaluating,
                exports: json!({"partial": 1}),
            }
        );
        cache.replace_exports(&"a", json!(false)).unwrap();
        assert_eq!(cache.fail_and_evict(&"a").unwrap(), json!(false));
        assert!(cache.get(&"a").is_none());
        assert_eq!(
            cache.publish("a", json!({"retry": true})),
            CommonJsLookup::Published
        );
    }

    #[test]
    fn commonjs_namespace_is_a_static_snapshot_with_node_markers() {
        let mut exports = json!({"named": 1});
        let namespace = commonjs_namespace_snapshot(
            exports.clone(),
            ["named".into(), "missing".into()],
            |value, name| value.get(name).cloned(),
        );
        exports["named"] = json!(2);
        assert_eq!(namespace.bindings["named"], json!(1));
        assert_eq!(namespace.bindings["default"], json!({"named": 1}));
        assert_eq!(namespace.bindings["module.exports"], json!({"named": 1}));
    }

    #[test]
    fn require_esm_uses_presence_not_truthiness_and_json_attributes_are_exact() {
        let direct = BTreeMap::from([("module.exports".into(), json!(false))]);
        assert_eq!(
            select_require_esm_result(&direct),
            RequireEsmResult::Direct(json!(false))
        );
        let namespace = BTreeMap::from([("default".into(), json!(0))]);
        assert_eq!(
            select_require_esm_result(&namespace),
            RequireEsmResult::Namespace {
                bindings: namespace,
                has_es_module_marker: true,
            }
        );

        let json_attribute = ImportAttributes::new([("type".into(), "json".into())]).unwrap();
        assert!(validate_json_attributes(JsonConsumer::EsmImport, &json_attribute).is_ok());
        assert_eq!(
            validate_json_attributes(JsonConsumer::EsmImport, &ImportAttributes::default()),
            Err(CommonJsError::JsonAttributeMissing)
        );
        assert_eq!(
            validate_json_attributes(JsonConsumer::CommonJsRequire, &json_attribute),
            Err(CommonJsError::JsonRequireAttributes)
        );
    }
}
