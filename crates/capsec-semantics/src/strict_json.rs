//! Strict I-JSON parsing used before any semantic deserialization.
//!
//! `serde_json::Value` normally accepts duplicate object members using
//! last-write-wins semantics.  Capability policy cannot safely do that, so the
//! value visitor below rejects a repeated *decoded* key before returning a
//! value to its caller.

use crate::error::{Error, Result};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

/// Largest integer exactly representable by an I-JSON/ECMAScript number.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone)]
struct StrictSeed {
    path: String,
    refusal: Rc<RefCell<Option<Error>>>,
}

impl StrictSeed {
    fn child_key(&self, key: &str) -> Self {
        Self {
            path: format!("{}[{}]", self.path, json_path_string(key)),
            refusal: Rc::clone(&self.refusal),
        }
    }

    fn child_index(&self, index: usize) -> Self {
        Self {
            path: format!("{}[{index}]", self.path),
            refusal: Rc::clone(&self.refusal),
        }
    }

    fn refuse<E>(&self, error: Error) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        let message = error.to_string();
        *self.refusal.borrow_mut() = Some(error);
        Err(E::custom(message))
    }
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor { seed: self })
    }
}

struct StrictVisitor {
    seed: StrictSeed,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict I-JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return self.seed.refuse(Error::InvalidIJson {
                path: self.seed.path.clone(),
                message: "integer is outside the I-JSON safe range".into(),
            });
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value > MAX_SAFE_INTEGER {
            return self.seed.refuse(Error::InvalidIJson {
                path: self.seed.path.clone(),
                message: "integer is outside the I-JSON safe range".into(),
            });
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if !value.is_finite() {
            return self.seed.refuse(Error::InvalidIJson {
                path: self.seed.path.clone(),
                message: "non-finite JSON number".into(),
            });
        }
        if value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64 {
            return self.seed.refuse(Error::InvalidIJson {
                path: self.seed.path.clone(),
                message: "integer is outside the I-JSON safe range".into(),
            });
        }
        let number = Number::from_f64(value)
            .ok_or_else(|| E::custom(format!("{}: non-finite JSON number", self.seed.path)))?;
        Ok(Value::Number(number))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.seed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        let mut index = 0;
        while let Some(value) = sequence.next_element_seed(self.seed.child_index(index))? {
            values.push(value);
            index += 1;
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut seen = HashSet::with_capacity(object.size_hint().unwrap_or(0));
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return self.seed.refuse(Error::DuplicateKey {
                    path: self.seed.path.clone(),
                    key,
                });
            }
            let value = object.next_value_seed(self.seed.child_key(&key))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

/// Parse a JSON string while rejecting duplicate decoded keys and I-JSON
/// violations before returning a `Value`.
pub fn parse_strict(text: &str) -> Result<Value> {
    let refusal = Rc::new(RefCell::new(None));
    let seed = StrictSeed {
        path: "$".into(),
        refusal: Rc::clone(&refusal),
    };
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = match seed.deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => {
            if let Some(refusal) = refusal.borrow_mut().take() {
                return Err(refusal);
            }
            return Err(Error::InvalidJson(error.to_string()));
        }
    };
    deserializer
        .end()
        .map_err(|error| Error::InvalidJson(error.to_string()))?;
    validate_i_json(&value)?;
    Ok(value)
}

/// Parse UTF-8 JSON bytes with the same strict guarantees as [`parse_strict`].
pub fn parse_slice_strict(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Error::InvalidJson(format!("input is not valid UTF-8: {error}")))?;
    parse_strict(text)
}

/// Deserialize a typed value only after strict parsing has rejected ambiguous
/// JSON representation.
pub fn from_str_strict<T>(text: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(parse_strict(text)?)
        .map_err(|error| Error::InvalidJson(error.to_string()))
}

/// Validate a programmatically constructed JSON value against I-JSON.
pub fn validate_i_json(value: &Value) -> Result<()> {
    validate_i_json_at(value, "$")
}

fn validate_i_json_at(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(unsafe_integer(path));
                }
                return Ok(());
            }
            if let Some(value) = number.as_u64() {
                if value > MAX_SAFE_INTEGER {
                    return Err(unsafe_integer(path));
                }
                return Ok(());
            }
            let value = number.as_f64().ok_or_else(|| Error::InvalidIJson {
                path: path.into(),
                message: "number cannot be represented as an IEEE-754 value".into(),
            })?;
            if !value.is_finite() {
                return Err(Error::InvalidIJson {
                    path: path.into(),
                    message: "non-finite JSON number".into(),
                });
            }
            if value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64 {
                return Err(unsafe_integer(path));
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_i_json_at(value, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                validate_i_json_at(value, &format!("{path}[{}]", json_path_string(key)))?;
            }
            Ok(())
        }
    }
}

fn unsafe_integer(path: &str) -> Error {
    Error::InvalidIJson {
        path: path.into(),
        message: "integer is outside the I-JSON safe range".into(),
    }
}

fn json_path_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid>\"".into())
}
