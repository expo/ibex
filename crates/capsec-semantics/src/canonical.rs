//! RFC 8785 serialization and schema-declared semantic-set normalization.

use crate::error::{Error, Result};
use crate::strict_json::validate_i_json;
use serde::Deserialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// The decision-affecting portion of `digestContract` consumed by the neutral
/// canonicalizer and digest implementation. Additional product metadata in a
/// registry is intentionally ignored during deserialization.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestContract {
    pub serialization: String,
    pub duplicate_keys: String,
    pub unicode: String,
    pub safe_integers: String,
    pub sets: String,
    pub framing: String,
    pub separator_byte: u8,
    pub text_encoding: String,
    pub output_encoding: String,
    pub bundle_schema: String,
    pub set_keys: Vec<String>,
    pub keyed_sets: Vec<KeyedSetSpec>,
    pub domains: DigestDomains,
    pub projections: DigestProjections,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyedSetSpec {
    pub schema: String,
    pub path: String,
    pub order_by: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestDomains {
    pub vocabulary: String,
    pub registry: String,
    pub policy: String,
    pub armed_snapshot: String,
    pub conformance: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestProjections {
    pub vocabulary: DigestProjection,
    pub registry: DigestProjection,
    pub policy: DigestProjection,
    pub armed_snapshot: DigestProjection,
    pub conformance: DigestProjection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestProjection {
    pub status: String,
    pub input_schema: String,
    pub member_order: String,
    pub members: Vec<String>,
    pub omit_fields: Vec<String>,
}

impl DigestContract {
    /// Validate contract tables without first collecting them into sets, which
    /// would silently erase malformed duplicate rows.
    pub fn validate(&self) -> Result<()> {
        let scalar_contract = [
            (
                "serialization",
                self.serialization.as_str(),
                "RFC8785-JCS-over-I-JSON",
            ),
            (
                "duplicateKeys",
                self.duplicate_keys.as_str(),
                "reject-before-canonicalization",
            ),
            (
                "unicode",
                self.unicode.as_str(),
                "valid-UTF8-and-Unicode-scalars-only",
            ),
            (
                "safeIntegers",
                self.safe_integers.as_str(),
                "I-JSON-safe-range-or-tagged-string",
            ),
            (
                "sets",
                self.sets.as_str(),
                "schema-declared-sets-canonical-key-sorted-and-deduplicated",
            ),
            ("framing", self.framing.as_str(), "utf8-domain-nul-payload"),
            ("textEncoding", self.text_encoding.as_str(), "utf8"),
            (
                "outputEncoding",
                self.output_encoding.as_str(),
                "sha256-lowercase-tag-unpadded-base64url",
            ),
            (
                "bundleSchema",
                self.bundle_schema.as_str(),
                "ibex/capsec-digest-bundle/1",
            ),
        ];
        for (field, actual, expected) in scalar_contract {
            if actual != expected {
                return Err(invalid_contract(
                    &format!("digestContract.{field}"),
                    "value differs from the frozen semantic contract",
                ));
            }
        }
        if self.separator_byte != 0 {
            return Err(invalid_contract(
                "digestContract.separatorByte",
                "digest separator must be one NUL byte",
            ));
        }
        self.validate_domains_and_projections()?;
        validate_sorted_unique_strings(&self.set_keys, "digestContract.setKeys")?;

        let mut previous: Option<Vec<u8>> = None;
        for (index, specification) in self.keyed_sets.iter().enumerate() {
            if specification.schema.is_empty() {
                return Err(invalid_contract(
                    &format!("digestContract.keyedSets[{index}].schema"),
                    "keyed-set schema is empty",
                ));
            }
            pointer_tokens(&specification.path)?;
            if specification.order_by.is_empty() {
                return Err(invalid_contract(
                    &format!("digestContract.keyedSets[{index}].orderBy"),
                    "keyed set has no orderBy fields",
                ));
            }
            let mut order_by = BTreeSet::new();
            for pointer in &specification.order_by {
                pointer_tokens(pointer)?;
                if !order_by.insert(pointer) {
                    return Err(invalid_contract(
                        &format!("digestContract.keyedSets[{index}].orderBy"),
                        "duplicate orderBy pointer",
                    ));
                }
            }
            let key = to_jcs_bytes(&Value::Array(vec![
                Value::String(specification.schema.clone()),
                Value::String(specification.path.clone()),
            ]))?;
            if let Some(previous) = &previous {
                match previous.cmp(&key) {
                    Ordering::Less => {}
                    Ordering::Equal => {
                        return Err(invalid_contract(
                            "digestContract.keyedSets",
                            "duplicate schema/path keyed-set specification",
                        ));
                    }
                    Ordering::Greater => {
                        return Err(invalid_contract(
                            "digestContract.keyedSets",
                            "keyed-set specifications are not in canonical UTF-8 order",
                        ));
                    }
                }
            }
            previous = Some(key);
        }
        Ok(())
    }

    fn validate_domains_and_projections(&self) -> Result<()> {
        let vocabulary_members = [
            "coverage-edges",
            "examples/authority-containment",
            "registry/capability-definitions",
            "registry/policy-rules",
            "schema/armed-snapshot",
            "schema/authority-containment",
            "schema/authority-selector",
            "schema/canonical-policy",
            "schema/capability-definitions",
            "schema/common",
            "schema/coverage-edge",
            "schema/digest-bundle",
            "schema/digest-vectors",
            "schema/effect",
            "schema/effect-occurrence",
            "schema/ingress-obligations",
            "schema/output-disposition-evidence",
            "schema/output-disposition-policy",
            "schema/output-dispositions",
            "schema/output-shape-catalog",
            "schema/policy-rules",
        ];
        let registry_members = [
            "coverage-edges",
            "fixture-manifest",
            "implementation-manifest",
            "ingress-obligations",
            "legacy-reconciliation",
            "network-classifier-snapshot",
            "output-disposition-evidence",
            "output-disposition-policy",
            "output-dispositions",
            "output-shape-catalog",
            "schema/contract-manifest",
            "schema/coverage-edge",
            "schema/implementation-manifest",
            "schema/ingress-obligations",
            "schema/legacy-reconciliation",
            "schema/output-disposition-evidence",
            "schema/output-disposition-policy",
            "schema/output-dispositions",
            "schema/output-shape-catalog",
            "schema/target-cell",
            "vocab-digest",
        ];
        let rows = [
            (
                "vocabulary",
                self.domains.vocabulary.as_str(),
                "ibex:capsec:vocab:1",
                &self.projections.vocabulary,
                "ibex/capsec-digest-bundle/1",
                "available",
                "logical-name-lexical",
                vocabulary_members.as_slice(),
                &[][..],
            ),
            (
                "registry",
                self.domains.registry.as_str(),
                "ibex:capsec:registry:1",
                &self.projections.registry,
                "ibex/capsec-digest-bundle/1",
                "available",
                "logical-name-lexical",
                registry_members.as_slice(),
                &[][..],
            ),
            (
                "policy",
                self.domains.policy.as_str(),
                "ibex:capsec:policy:2",
                &self.projections.policy,
                "ibex/capsec-policy/2",
                "available",
                "not-applicable",
                &["canonical-policy-object"][..],
                &["policyDigest"][..],
            ),
            (
                "armedSnapshot",
                self.domains.armed_snapshot.as_str(),
                "ibex:capsec:armed:1",
                &self.projections.armed_snapshot,
                "ibex/capsec-armed/1",
                "contract-fixture",
                "not-applicable",
                &["armed-snapshot-object"][..],
                &["armedSnapshotDigest"][..],
            ),
            (
                "conformance",
                self.domains.conformance.as_str(),
                "ibex:capsec:conformance:1",
                &self.projections.conformance,
                // @ref LLP 0021#a9-appendix--the-scope-digest-join-matrix —
                // M30 revs the rich report schema while preserving its digest domain.
                "ibex/capsec-conformance/3",
                "unavailable-until-wp10",
                "not-applicable",
                &["conformance-report-object"][..],
                &["conformanceDigest"][..],
            ),
        ];
        for (
            name,
            domain,
            expected_domain,
            projection,
            input_schema,
            status,
            member_order,
            members,
            omissions,
        ) in rows
        {
            if domain != expected_domain
                || projection.input_schema != input_schema
                || projection.status != status
                || projection.member_order != member_order
                || projection
                    .members
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    != members
                || projection
                    .omit_fields
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    != omissions
            {
                return Err(invalid_contract(
                    &format!("digestContract.projections.{name}"),
                    "domain, input schema, or omission differs from the frozen contract",
                ));
            }
        }
        Ok(())
    }
}

/// Return RFC 8785 JCS text for an I-JSON value.
pub fn to_jcs(value: &Value) -> Result<String> {
    validate_i_json(value)?;
    let mut output = String::new();
    write_jcs(value, &mut output)?;
    Ok(output)
}

/// Return RFC 8785 JCS bytes for an I-JSON value.
pub fn to_jcs_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(to_jcs(value)?.into_bytes())
}

/// Clone and normalize every generic semantic set, then any composite keyed
/// sets declared for `schema` by the supplied contract.
pub fn canonicalize(
    value: &Value,
    schema: Option<&str>,
    contract: &DigestContract,
) -> Result<Value> {
    let mut canonical = value.clone();
    canonicalize_in_place(&mut canonical, schema, contract)?;
    Ok(canonical)
}

/// In-place form of [`canonicalize`]. Generic set membership is selected only
/// by `setKeys`; composite rows are selected only by the passed keyed-set rows.
pub fn canonicalize_in_place(
    value: &mut Value,
    schema: Option<&str>,
    contract: &DigestContract,
) -> Result<()> {
    contract.validate()?;
    validate_i_json(value)?;
    let set_keys = contract.set_keys.iter().cloned().collect::<BTreeSet<_>>();
    normalize_generic_sets(value, &set_keys, "$")?;
    if let Some(schema) = schema {
        for specification in contract
            .keyed_sets
            .iter()
            .filter(|specification| specification.schema == schema)
        {
            normalize_keyed_set(value, specification)?;
        }
    }
    Ok(())
}

fn validate_sorted_unique_strings(values: &[String], path: &str) -> Result<()> {
    if values.is_empty() {
        return Err(invalid_contract(path, "set catalog is empty"));
    }
    if values.iter().any(String::is_empty) {
        return Err(invalid_contract(path, "set catalog contains an empty key"));
    }
    for pair in values.windows(2) {
        match pair[0].as_bytes().cmp(pair[1].as_bytes()) {
            Ordering::Less => {}
            Ordering::Equal => return Err(invalid_contract(path, "duplicate set entry")),
            Ordering::Greater => {
                return Err(invalid_contract(
                    path,
                    "entries are not in canonical UTF-8 order",
                ));
            }
        }
    }
    Ok(())
}

fn write_jcs(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(|error| {
                Error::InvalidCanonicalData {
                    path: "$".into(),
                    message: error.to_string(),
                }
            })?)
        }
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                output.push_str(&value.to_string());
            } else if let Some(value) = number.as_u64() {
                output.push_str(&value.to_string());
            } else {
                let value = number.as_f64().ok_or_else(|| Error::InvalidCanonicalData {
                    path: "$".into(),
                    message: "number cannot be represented as IEEE-754".into(),
                })?;
                output.push_str(&ecmascript_number(value));
            }
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_jcs(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|error| {
                    Error::InvalidCanonicalData {
                        path: "$".into(),
                        message: error.to_string(),
                    }
                })?);
                output.push(':');
                write_jcs(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Render the shortest round-tripping decimal using ECMAScript's specified
/// tie-breaking and fixed/exponential thresholds. Rust's standard formatter
/// chooses a different shortest representation for some halfway cases, so it
/// cannot be used for RFC 8785 bytes shared with JavaScript.
fn ecmascript_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    ryu_js::Buffer::new().format_finite(value).to_owned()
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn normalize_generic_sets(
    value: &mut Value,
    set_keys: &BTreeSet<String>,
    path: &str,
) -> Result<()> {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                normalize_generic_sets(value, set_keys, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values.iter_mut() {
                let child_path = format!("{path}/{key}");
                normalize_generic_sets(value, set_keys, &child_path)?;
                if set_keys.contains(key) {
                    if let Value::Array(rows) = value {
                        sort_and_deduplicate(rows)?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn sort_and_deduplicate(values: &mut Vec<Value>) -> Result<()> {
    let mut encoded = values
        .drain(..)
        .map(|value| to_jcs_bytes(&value).map(|bytes| (bytes, value)))
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by(|(left, _), (right, _)| left.cmp(right));
    encoded.dedup_by(|(left, _), (right, _)| left == right);
    values.extend(encoded.into_iter().map(|(_, value)| value));
    Ok(())
}

fn normalize_keyed_set(document: &mut Value, specification: &KeyedSetSpec) -> Result<()> {
    if specification.order_by.is_empty() {
        return Err(invalid_contract(
            &specification.path,
            "keyed set has no orderBy fields",
        ));
    }
    let tokens = pointer_tokens(&specification.path)?;
    let rows = pointer_mut(document, &tokens, &specification.path)?
        .as_array_mut()
        .ok_or_else(|| invalid_contract(&specification.path, "keyed set target is not an array"))?;

    let mut keyed = rows
        .drain(..)
        .enumerate()
        .map(|(index, row)| {
            let fields = specification
                .order_by
                .iter()
                .map(|pointer| pointer_value(&row, pointer, index).cloned())
                .collect::<Result<Vec<_>>>()?;
            Ok((to_jcs_bytes(&Value::Array(fields))?, row))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
    if let Some((duplicate, _)) = keyed
        .windows(2)
        .find(|pair| pair[0].0 == pair[1].0)
        .map(|pair| &pair[0])
    {
        return Err(invalid_contract(
            &specification.path,
            &format!(
                "duplicate composite key {}",
                String::from_utf8_lossy(duplicate)
            ),
        ));
    }
    rows.extend(keyed.into_iter().map(|(_, row)| row));
    Ok(())
}

fn pointer_value<'a>(row: &'a Value, pointer: &str, index: usize) -> Result<&'a Value> {
    let tokens = pointer_tokens(pointer)?;
    let mut current = row;
    for token in tokens {
        current = match current {
            Value::Object(values) => values.get(&token),
            Value::Array(values) => token
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index)),
            _ => None,
        }
        .ok_or_else(|| {
            invalid_contract(
                pointer,
                &format!("orderBy pointer does not resolve in row {index}"),
            )
        })?;
    }
    Ok(current)
}

fn pointer_mut<'a>(
    value: &'a mut Value,
    tokens: &[String],
    pointer: &str,
) -> Result<&'a mut Value> {
    let Some((first, rest)) = tokens.split_first() else {
        return Ok(value);
    };
    let child = match value {
        Value::Object(values) => values.get_mut(first),
        Value::Array(values) => first
            .parse::<usize>()
            .ok()
            .and_then(|index| values.get_mut(index)),
        _ => None,
    }
    .ok_or_else(|| invalid_contract(pointer, "JSON pointer does not resolve"))?;
    pointer_mut(child, rest, pointer)
}

fn pointer_tokens(pointer: &str) -> Result<Vec<String>> {
    if !pointer.starts_with('/') || pointer == "/" {
        return Err(invalid_contract(pointer, "invalid JSON pointer"));
    }
    pointer[1..]
        .split('/')
        .map(|token| {
            if token.is_empty() {
                Err(invalid_contract(
                    pointer,
                    "invalid empty JSON pointer token",
                ))
            } else {
                decode_pointer_token(token, pointer)
            }
        })
        .collect()
}

fn decode_pointer_token(token: &str, pointer: &str) -> Result<String> {
    let mut decoded = String::new();
    let mut chars = token.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err(invalid_contract(pointer, "invalid JSON pointer escape")),
        }
    }
    Ok(decoded)
}

fn invalid_contract(path: &str, message: &str) -> Error {
    Error::InvalidCanonicalData {
        path: path.into(),
        message: message.into(),
    }
}
