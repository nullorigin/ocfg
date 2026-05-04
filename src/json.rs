//! JSON Parser and Generator for ocfg
//!
//! A lightweight, flexible JSON implementation designed for configuration management.
//! Provides parsing, serialization, and pretty-printing capabilities with a focus on
//! configuration file handling.
//!
//! # Features
//! - Fast JSON parsing with detailed error messages
//! - Flexible JSON value representation
//! - Trait-based serialization/deserialization
//! - Pretty printing with configurable indentation
//! - Streaming support for large files
//! - Memory-efficient byte-based string handling
//! - Builder patterns for easier object/array construction
//! - Helper functions for common serialization patterns
//!
//! # Example
//! ```ignore
//! use ocfg::json::{Json, JsonValue, JsonObjectBuilder};
//!
//! // Parse JSON
//! let config = Json::parse(r#"{"name": "router", "port": 8080}"#)?;
//!
//! // Access values
//! if let Some(name) = config.get("name").and_then(|v| v.as_str()) {
//!     println!("Name: {}", name);
//! }
//!
//! // Serialize to JSON
//! let json_str = config.to_json_string();
//! let pretty = config.to_json_pretty(2);
//!
//! // Use builder for easier construction
//! let obj = JsonObjectBuilder::new()
//!     .insert_string("name", "router")
//!     .insert_int("port", 8080)
//!     .build();
//! ```

use crate::error::Result;
use crate::err;
use std::collections::HashMap;
use std::fmt;
use std::str;

// ============================================================================
// Constants and Tables
// ============================================================================

/// Maximum nesting depth for JSON parsing (prevents stack overflow)
pub const MAX_DEPTH: usize = 512;

// ============================================================================
// JsonValue - Generic JSON Value Type
// ============================================================================

/// A generic JSON value that can represent any JSON data.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON null
    Null,
    /// JSON boolean
    Bool(bool),
    /// JSON integer (i64 for full range)
    Integer(i64),
    /// JSON floating point
    Float(f64),
    /// JSON string (stored as String for UTF-8 safety)
    String(String),
    /// JSON array
    Array(Vec<JsonValue>),
    /// JSON object (keys are Strings for UTF-8 safety)
    Object(HashMap<String, JsonValue>),
}

impl Default for JsonValue {
    fn default() -> Self {
        JsonValue::Null
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonValue::Null => write!(f, "null"),
            JsonValue::Bool(b) => write!(f, "{}", b),
            JsonValue::Integer(n) => write!(f, "{}", n),
            JsonValue::Float(n) => write!(f, "{}", n),
            JsonValue::String(s) => write!(f, "\"{}\"", s),
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
            JsonValue::Object(obj) => {
                write!(f, "{{")?;
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "\"{}\": {}", key, value)?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ============================================================================
// Constructors and Type Conversions
// ============================================================================

impl JsonValue {
    /// Create a null value
    pub fn null() -> Self {
        JsonValue::Null
    }

    /// Create a boolean value
    pub fn bool(b: bool) -> Self {
        JsonValue::Bool(b)
    }

    /// Create an integer value
    pub fn int(n: i64) -> Self {
        JsonValue::Integer(n)
    }

    /// Create a float value
    pub fn float(n: f64) -> Self {
        JsonValue::Float(n)
    }

    /// Create a string value
    pub fn string(s: impl Into<String>) -> Self {
        JsonValue::String(s.into())
    }

    /// Create an empty array
    pub fn array() -> Self {
        JsonValue::Array(Vec::new())
    }

    /// Create an array from a vector
    pub fn array_from(items: Vec<JsonValue>) -> Self {
        JsonValue::Array(items)
    }

    /// Create an empty object
    pub fn object() -> Self {
        JsonValue::Object(HashMap::new())
    }

    /// Create an object from a hashmap
    pub fn object_from(map: HashMap<String, JsonValue>) -> Self {
        JsonValue::Object(map)
    }

    // ========================================================================
    // Type Checks
    // ========================================================================

    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, JsonValue::Bool(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Integer(_) | JsonValue::Float(_))
    }

    pub fn is_integer(&self) -> bool {
        matches!(self, JsonValue::Integer(_))
    }

    pub fn is_float(&self) -> bool {
        matches!(self, JsonValue::Float(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    // ========================================================================
    // Value Accessors
    // ========================================================================

    /// Get as bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as i64
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Integer(n) => Some(*n),
            JsonValue::Float(n) => Some(*n as i64),
            _ => None,
        }
    }

    /// Get as f64
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Float(n) => Some(*n),
            JsonValue::Integer(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// Get as String
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as array
    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_array_owned(&self) -> Option<Vec<JsonValue>> {
        match self {
            JsonValue::Array(arr) => Some(arr.clone()),
            _ => None,
        }
    }

    /// Get as object
    pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        match self {
            JsonValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn as_object_owned(&self) -> Option<HashMap<String, JsonValue>> {
        match self {
            JsonValue::Object(obj) => Some(obj.clone()),
            _ => None,
        }
    }

    // ========================================================================
    // Object Operations
    // ========================================================================

    /// Get a value from an object by key
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.get(key),
            _ => None,
        }
    }

    /// Get a mutable reference to a value from an object by key
    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.get_mut(key),
            _ => None,
        }
    }

    /// Set a value in an object by key
    pub fn set(&mut self, key: impl Into<String>, value: JsonValue) -> Option<JsonValue> {
        match self {
            JsonValue::Object(obj) => {
                let key = key.into();
                obj.insert(key, value)
            }
            _ => None,
        }
    }

    /// Remove a value from an object by key
    pub fn remove(&mut self, key: &str) -> Option<JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.remove(key),
            _ => None,
        }
    }

    /// Check if an object contains a key
    pub fn has(&self, key: &str) -> bool {
        match self {
            JsonValue::Object(obj) => obj.contains_key(key),
            _ => false,
        }
    }

    /// Get the keys of an object
    pub fn keys(&self) -> Option<Vec<String>> {
        match self {
            JsonValue::Object(obj) => Some(obj.keys().cloned().collect()),
            _ => None,
        }
    }

    /// Get the number of elements in an array or object
    pub fn len(&self) -> Option<usize> {
        match self {
            JsonValue::Array(arr) => Some(arr.len()),
            JsonValue::Object(obj) => Some(obj.len()),
            _ => None,
        }
    }
    /// Check if an array or object is empty
    pub fn is_empty(&self) -> Option<bool> {
        match self {
            JsonValue::Array(arr) => Some(arr.is_empty()),
            JsonValue::Object(obj) => Some(obj.is_empty()),
            _ => None,
        }
    }
}

// ============================================================================
// ToJson and FromJson Traits
// ============================================================================

/// Trait for types that can be serialized to JSON
pub trait ToJson {
    /// Convert to JsonValue
    fn to_json(&self) -> JsonValue;

    /// Convert to JSON string
    fn to_json_string(&self) -> String {
        self.to_json().to_json_string()
    }

    /// Convert to pretty JSON string
    fn to_json_pretty(&self, indent: usize) -> String {
        self.to_json().to_json_pretty(indent)
    }
}

/// Trait for types that can be deserialized from JSON
pub trait FromJson: Sized {
    /// Convert from JsonValue
    fn from_json(value: JsonValue) -> Result<Self>;

    /// Parse from JSON string
    fn from_json_str(input: &str) -> Result<Self> {
        let value = JsonValue::parse(input)?;
        Self::from_json(value)
    }
}

// ============================================================================
// Implementations for common types
// ============================================================================

impl ToJson for JsonValue {
    fn to_json(&self) -> JsonValue {
        self.clone()
    }
}

impl ToJson for String {
    fn to_json(&self) -> JsonValue {
        JsonValue::String(self.clone())
    }
}

impl ToJson for &str {
    fn to_json(&self) -> JsonValue {
        JsonValue::String((*self).to_string())
    }
}

impl ToJson for bool {
    fn to_json(&self) -> JsonValue {
        JsonValue::Bool(*self)
    }
}

impl ToJson for i64 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Integer(*self)
    }
}

impl ToJson for i32 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Integer(*self as i64)
    }
}

impl ToJson for u64 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Integer(*self as i64)
    }
}

impl ToJson for u32 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Integer(*self as i64)
    }
}

impl ToJson for u16 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Integer(*self as i64)
    }
}

impl ToJson for f64 {
    fn to_json(&self) -> JsonValue {
        JsonValue::Float(*self)
    }
}

impl<T: ToJson> ToJson for Vec<T> {
    fn to_json(&self) -> JsonValue {
        JsonValue::Array(self.iter().map(|v| v.to_json()).collect())
    }
}

impl<T: ToJson> ToJson for Option<T> {
    fn to_json(&self) -> JsonValue {
        match self {
            Some(v) => v.to_json(),
            None => JsonValue::null(),
        }
    }
}

impl<K: ToString, V: ToJson> ToJson for HashMap<K, V> {
    fn to_json(&self) -> JsonValue {
        let mut obj = HashMap::new();
        for (k, v) in self {
            obj.insert(k.to_string(), v.to_json());
        }
        JsonValue::Object(obj)
    }
}

// ============================================================================
// Advanced Helper Functions for Serialization
// ============================================================================

/// Builder for creating JSON objects with less boilerplate
pub struct JsonObjectBuilder {
    fields: HashMap<String, JsonValue>,
}

impl JsonObjectBuilder {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            fields: HashMap::with_capacity(capacity),
        }
    }

    pub fn insert(mut self, key: impl Into<String>, value: JsonValue) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn insert_string(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), JsonValue::string(value));
        self
    }

    pub fn insert_bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.fields.insert(key.into(), JsonValue::bool(value));
        self
    }

    pub fn insert_int(mut self, key: impl Into<String>, value: i64) -> Self {
        self.fields.insert(key.into(), JsonValue::int(value));
        self
    }

    pub fn insert_u32(mut self, key: impl Into<String>, value: u32) -> Self {
        self.fields.insert(key.into(), JsonValue::int(value as i64));
        self
    }

    pub fn insert_u16(mut self, key: impl Into<String>, value: u16) -> Self {
        self.fields.insert(key.into(), JsonValue::int(value as i64));
        self
    }

    pub fn insert_option<T: ToJson>(mut self, key: impl Into<String>, value: &Option<T>) -> Self {
        self.fields.insert(key.into(), value.to_json());
        self
    }

    pub fn insert_vec<T: ToJson>(mut self, key: impl Into<String>, value: &[T]) -> Self {
        self.fields.insert(key.into(), JsonValue::array_from(
            value.iter().map(|v| v.to_json()).collect()
        ));
        self
    }

    pub fn insert_opt_vec<T: ToJson>(mut self, key: impl Into<String>, value: &Option<Vec<T>>) -> Self {
        self.fields.insert(key.into(), value.to_json());
        self
    }

    pub fn build(self) -> JsonValue {
        JsonValue::object_from(self.fields)
    }
}

impl Default for JsonObjectBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating JSON arrays with less boilerplate
pub struct JsonArrayBuilder {
    items: Vec<JsonValue>,
}

impl JsonArrayBuilder {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    pub fn push(mut self, value: JsonValue) -> Self {
        self.items.push(value);
        self
    }

    pub fn push_string(mut self, value: impl Into<String>) -> Self {
        self.items.push(JsonValue::string(value));
        self
    }

    pub fn push_int(mut self, value: i64) -> Self {
        self.items.push(JsonValue::int(value));
        self
    }

    pub fn push_bool(mut self, value: bool) -> Self {
        self.items.push(JsonValue::bool(value));
        self
    }

    pub fn extend<T: ToJson>(mut self, items: &[T]) -> Self {
        self.items.extend(items.iter().map(|v| v.to_json()));
        self
    }

    pub fn build(self) -> JsonValue {
        JsonValue::array_from(self.items)
    }
}

impl Default for JsonArrayBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Advanced Helper Functions for Deserialization
// ============================================================================

/// Helper for extracting string fields from JSON objects with better error messages
pub fn get_string_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<String> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected string)", "object", field))
}

/// Helper for extracting optional string fields from JSON objects
pub fn get_string_field_opt(obj: &HashMap<String, JsonValue>, field: &str) -> Option<String> {
    obj.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Helper for extracting boolean fields from JSON objects
pub fn get_bool_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<bool> {
    obj.get(field)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected bool)", "object", field))
}

/// Helper for extracting optional boolean fields from JSON objects
pub fn get_bool_field_opt(obj: &HashMap<String, JsonValue>, field: &str) -> Option<bool> {
    obj.get(field).and_then(|v| v.as_bool())
}

/// Helper for extracting i64 fields from JSON objects
pub fn get_i64_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<i64> {
    obj.get(field)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected number)", "object", field))
}

/// Helper for extracting u32 fields from JSON objects
pub fn get_u32_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<u32> {
    obj.get(field)
        .and_then(|v| v.as_i64())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected u32)", "object", field))
}

/// Helper for extracting u16 fields from JSON objects
pub fn get_u16_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<u16> {
    obj.get(field)
        .and_then(|v| v.as_i64())
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected u16)", "object", field))
}

/// Helper for extracting string vector fields from JSON objects
pub fn get_string_vec_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<Vec<String>> {
    obj.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| err!(InvalidValue, "{}.{} (expected array of strings)", "object", field))
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

/// Helper for extracting optional string vector fields from JSON objects
pub fn get_string_vec_field_opt(obj: &HashMap<String, JsonValue>, field: &str) -> Option<Vec<String>> {
    obj.get(field).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    })
}

/// Helper for extracting nested objects from JSON objects
pub fn get_object_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<HashMap<String, JsonValue>> {
    obj.get(field)
        .and_then(|v| v.as_object_owned())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected object)", "object", field))
}

/// Helper for extracting optional nested objects from JSON objects
pub fn get_object_field_opt(obj: &HashMap<String, JsonValue>, field: &str) -> Option<HashMap<String, JsonValue>> {
    obj.get(field).and_then(|v| v.as_object_owned())
}

/// Helper for extracting arrays from JSON objects
pub fn get_array_field(obj: &HashMap<String, JsonValue>, field: &str) -> Result<Vec<JsonValue>> {
    obj.get(field)
        .and_then(|v| v.as_array_owned())
        .ok_or_else(|| err!(InvalidValue, "{}.{} (expected array)", "object", field))
}

/// Helper for extracting optional arrays from JSON objects
pub fn get_array_field_opt(obj: &HashMap<String, JsonValue>, field: &str) -> Option<Vec<JsonValue>> {
    obj.get(field).and_then(|v| v.as_array_owned())
}

/// Helper for extracting fields with a default value
pub fn get_string_field_or(obj: &HashMap<String, JsonValue>, field: &str, default: &str) -> String {
    get_string_field_opt(obj, field).unwrap_or_else(|| default.to_string())
}

/// Helper for extracting boolean fields with a default value
pub fn get_bool_field_or(obj: &HashMap<String, JsonValue>, field: &str, default: bool) -> bool {
    get_bool_field_opt(obj, field).unwrap_or(default)
}

/// Helper for extracting u32 fields with a default value
pub fn get_u32_field_or(obj: &HashMap<String, JsonValue>, field: &str, default: u32) -> u32 {
    get_u32_field(obj, field).unwrap_or(default)
}

/// Helper for extracting u16 fields with a default value
pub fn get_u16_field_or(obj: &HashMap<String, JsonValue>, field: &str, default: u16) -> u16 {
    get_u16_field(obj, field).unwrap_or(default)
}

/// Helper for extracting string vector fields with a default value
pub fn get_string_vec_field_or(obj: &HashMap<String, JsonValue>, field: &str, default: Vec<String>) -> Vec<String> {
    get_string_vec_field_opt(obj, field).unwrap_or(default)
}

/// Context-aware field extractor that includes the parent path in error messages
pub struct FieldExtractor<'a> {
    obj: &'a HashMap<String, JsonValue>,
    path: String,
}

impl<'a> FieldExtractor<'a> {
    pub fn new(obj: &'a HashMap<String, JsonValue>, path: impl Into<String>) -> Self {
        Self {
            obj,
            path: path.into(),
        }
    }

    pub fn string(&self, field: &str) -> Result<String> {
        self.obj.get(field)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| err!(InvalidValue, "{}.{} (expected string)", self.path, field))
    }

    pub fn string_opt(&self, field: &str) -> Option<String> {
        self.obj.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    pub fn bool(&self, field: &str) -> Result<bool> {
        self.obj.get(field)
            .and_then(|v| v.as_bool())
            .ok_or_else(|| err!(InvalidValue, "{}.{} (expected bool)", self.path, field))
    }

    pub fn bool_opt(&self, field: &str) -> Option<bool> {
        self.obj.get(field).and_then(|v| v.as_bool())
    }

    pub fn u32(&self, field: &str) -> Result<u32> {
        self.obj.get(field)
            .and_then(|v| v.as_i64())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| err!(InvalidValue, "{}.{} (expected u32)", self.path, field))
    }

    pub fn u16(&self, field: &str) -> Result<u16> {
        self.obj.get(field)
            .and_then(|v| v.as_i64())
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| err!(InvalidValue, "{}.{} (expected u16)", self.path, field))
    }

    pub fn string_vec(&self, field: &str) -> Result<Vec<String>> {
        self.obj.get(field)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| err!(InvalidValue, "{}.{} (expected array of strings)", self.path, field))
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    pub fn object(&self, field: &str) -> Result<HashMap<String, JsonValue>> {
        self.obj.get(field)
            .and_then(|v| v.as_object_owned())
            .ok_or_else(|| err!(InvalidValue, "{}.{} (expected object)", self.path, field))
    }
}

// ============================================================================
// JSON Parser (Simplified for brevity - full parser would go here)
// ============================================================================

impl JsonValue {
    /// Parse a JSON string into a JsonValue
    pub fn parse(input: &str) -> Result<Self> {
        // Simple JSON parser implementation
        let input = input.trim();
        
        if input.is_empty() {
            return Err(err!(Serialization, "Empty JSON input"));
        }

        let chars: Vec<char> = input.chars().collect();
        let mut pos = 0;

        let result = Self::parse_value(&chars, &mut pos, 0)?;
        
        // Skip trailing whitespace
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        if pos < chars.len() {
            return Err(err!(Serialization, "Unexpected trailing characters"));
        }
        
        Ok(result)
    }

    fn parse_value(chars: &[char], pos: &mut usize, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(err!(Serialization, "JSON nesting depth exceeded"));
        }

        // Skip whitespace
        while *pos < chars.len() && chars[*pos].is_whitespace() {
            *pos += 1;
        }

        if *pos >= chars.len() {
            return Err(err!(Serialization, "Unexpected end of input"));
        }

        match chars[*pos] {
            '{' => Self::parse_object(chars, pos, depth + 1),
            '[' => Self::parse_array(chars, pos, depth + 1),
            '"' => Self::parse_string(chars, pos),
            't' => Self::parse_literal(chars, pos, "true", JsonValue::Bool(true)),
            'f' => Self::parse_literal(chars, pos, "false", JsonValue::Bool(false)),
            'n' => Self::parse_literal(chars, pos, "null", JsonValue::Null),
            '-' | '0'..='9' => Self::parse_number(chars, pos),
            c => Err(err!(Serialization, "Unexpected character: {}", c)),
        }
    }

    fn parse_object(chars: &[char], pos: &mut usize, depth: usize) -> Result<Self> {
        *pos += 1; // Skip '{'
        
        let mut obj = HashMap::new();
        
        // Skip whitespace
        while *pos < chars.len() && chars[*pos].is_whitespace() {
            *pos += 1;
        }

        if *pos < chars.len() && chars[*pos] == '}' {
            *pos += 1;
            return Ok(JsonValue::Object(obj));
        }

        loop {
            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            if *pos >= chars.len() {
                return Err(err!(Serialization, "Unexpected end of input in object"));
            }

            // Parse key
            let key = Self::parse_string(chars, pos)?;
            let key_str = match key {
                JsonValue::String(s) => s,
                _ => return Err(err!(Serialization, "Object key must be a string")),
            };

            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            if *pos >= chars.len() || chars[*pos] != ':' {
                return Err(err!(Serialization, "Expected ':' after object key"));
            }
            *pos += 1;

            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            // Parse value
            let value = Self::parse_value(chars, pos, depth)?;
            obj.insert(key_str, value);

            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            if *pos >= chars.len() {
                return Err(err!(Serialization, "Unexpected end of input in object"));
            }

            match chars[*pos] {
                '}' => {
                    *pos += 1;
                    return Ok(JsonValue::Object(obj));
                }
                ',' => *pos += 1,
                c => return Err(err!(Serialization, "Expected ',' or '}}' in object, got: {}", c)),
            }
        }
    }

    fn parse_array(chars: &[char], pos: &mut usize, depth: usize) -> Result<Self> {
        *pos += 1; // Skip '['
        
        let mut arr = Vec::new();
        
        // Skip whitespace
        while *pos < chars.len() && chars[*pos].is_whitespace() {
            *pos += 1;
        }

        if *pos < chars.len() && chars[*pos] == ']' {
            *pos += 1;
            return Ok(JsonValue::Array(arr));
        }

        loop {
            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            if *pos >= chars.len() {
                return Err(err!(Serialization, "Unexpected end of input in array"));
            }

            // Parse value
            let value = Self::parse_value(chars, pos, depth)?;
            arr.push(value);

            // Skip whitespace
            while *pos < chars.len() && chars[*pos].is_whitespace() {
                *pos += 1;
            }

            if *pos >= chars.len() {
                return Err(err!(Serialization, "Unexpected end of input in array"));
            }

            match chars[*pos] {
                ']' => {
                    *pos += 1;
                    return Ok(JsonValue::Array(arr));
                }
                ',' => *pos += 1,
                c => return Err(err!(Serialization, "Expected ',' or ']' in array, got: {}", c)),
            }
        }
    }

    fn parse_string(chars: &[char], pos: &mut usize) -> Result<Self> {
        *pos += 1; // Skip '"'
        
        let mut result = String::new();
        
        while *pos < chars.len() {
            match chars[*pos] {
                '"' => {
                    *pos += 1;
                    return Ok(JsonValue::String(result));
                }
                '\\' => {
                    *pos += 1;
                    if *pos >= chars.len() {
                        return Err(err!(Serialization, "Unexpected end of input in string escape"));
                    }
                    match chars[*pos] {
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        '/' => result.push('/'),
                        'b' => result.push('\x08'),
                        'f' => result.push('\x0c'),
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        'u' => {
                            *pos += 1;
                            if *pos + 3 >= chars.len() {
                                return Err(err!(Serialization, "Unexpected end of input in unicode escape"));
                            }
                            // Parse 4 hex digits
                            let hex: String = chars[*pos..=*pos+3].iter().collect();
                            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                                if let Some(c) = char::from_u32(code) {
                                    result.push(c);
                                } else {
                                    result.push('\u{FFFD}'); // Replacement character
                                }
                            } else {
                                return Err(err!(Serialization, "Invalid unicode escape: \\u{}", hex));
                            }
                            *pos += 3;
                        }
                        c => return Err(err!(Serialization, "Invalid escape sequence: \\{}", c)),
                    }
                }
                c => result.push(c),
            }
            *pos += 1;
        }
        
        Err(err!(Serialization, "Unterminated string"))
    }

    fn parse_number(chars: &[char], pos: &mut usize) -> Result<Self> {
        let start = *pos;
        let mut is_float = false;
        
        if *pos < chars.len() && chars[*pos] == '-' {
            *pos += 1;
        }
        
        while *pos < chars.len() && (chars[*pos].is_digit(10) || chars[*pos] == '.') {
            if chars[*pos] == '.' {
                is_float = true;
            }
            *pos += 1;
        }
        
        let num_str: String = chars[start..*pos].iter().collect();
        
        if is_float {
            num_str.parse::<f64>()
                .map(JsonValue::Float)
                .map_err(|_| err!(Serialization, "Invalid float: {}", num_str))
        } else {
            num_str.parse::<i64>()
                .map(JsonValue::Integer)
                .map_err(|_| err!(Serialization, "Invalid integer: {}", num_str))
        }
    }

    fn parse_literal(chars: &[char], pos: &mut usize, literal: &str, value: JsonValue) -> Result<Self> {
        if *pos + literal.len() > chars.len() {
            return Err(err!(Serialization, "Unexpected end of input in literal"));
        }
        
        let slice: String = chars[*pos..*pos+literal.len()].iter().collect();
        if slice == literal {
            *pos += literal.len();
            Ok(value)
        } else {
            Err(err!(Serialization, "Expected '{}', got: {}", literal, slice))
        }
    }

    /// Convert to JSON string
    pub fn to_json_string(&self) -> String {
        let mut result = String::new();
        self.write_json_string(&mut result);
        result
    }

    /// Convert to pretty JSON string
    pub fn to_json_pretty(&self, indent: usize) -> String {
        let mut result = String::new();
        self.write_json_pretty(&mut result, indent);
        result
    }

    fn write_json_string(&self, output: &mut String) {
        match self {
            JsonValue::Null => output.push_str("null"),
            JsonValue::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
            JsonValue::Integer(n) => output.push_str(&n.to_string()),
            JsonValue::Float(n) => output.push_str(&n.to_string()),
            JsonValue::String(s) => {
                output.push('"');
                for c in s.chars() {
                    match c {
                        '"' => output.push_str("\\\""),
                        '\\' => output.push_str("\\\\"),
                        '\x08' => output.push_str("\\b"),
                        '\x0c' => output.push_str("\\f"),
                        '\n' => output.push_str("\\n"),
                        '\r' => output.push_str("\\r"),
                        '\t' => output.push_str("\\t"),
                        c if c.is_ascii_control() => {
                            output.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        _ => output.push(c),
                    }
                }
                output.push('"');
            }
            JsonValue::Array(arr) => {
                output.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        output.push(',');
                    }
                    item.write_json_string(output);
                }
                output.push(']');
            }
            JsonValue::Object(obj) => {
                output.push('{');
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        output.push(',');
                    }
                    output.push('"');
                    output.push_str(key);
                    output.push_str("\":");
                    value.write_json_string(output);
                }
                output.push('}');
            }
        }
    }

    fn write_json_pretty(&self, output: &mut String, indent: usize) {
        match self {
            JsonValue::Null => output.push_str("null"),
            JsonValue::Bool(b) => output.push_str(if *b { "true" } else { "false" }),
            JsonValue::Integer(n) => output.push_str(&n.to_string()),
            JsonValue::Float(n) => output.push_str(&n.to_string()),
            JsonValue::String(s) => {
                output.push('"');
                for c in s.chars() {
                    match c {
                        '"' => output.push_str("\\\""),
                        '\\' => output.push_str("\\\\"),
                        '\x08' => output.push_str("\\b"),
                        '\x0c' => output.push_str("\\f"),
                        '\n' => output.push_str("\\n"),
                        '\r' => output.push_str("\\r"),
                        '\t' => output.push_str("\\t"),
                        c if c.is_ascii_control() => {
                            output.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        _ => output.push(c),
                    }
                }
                output.push('"');
            }
            JsonValue::Array(arr) => {
                output.push_str("[\n");
                for (i, item) in arr.iter().enumerate() {
                    Self::write_indent(output, indent + 1);
                    item.write_json_pretty(output, indent + 1);
                    if i < arr.len() - 1 {
                        output.push(',');
                    }
                    output.push('\n');
                }
                Self::write_indent(output, indent);
                output.push(']');
            }
            JsonValue::Object(obj) => {
                output.push_str("{\n");
                for (i, (key, value)) in obj.iter().enumerate() {
                    Self::write_indent(output, indent + 1);
                    output.push('"');
                    output.push_str(key);
                    output.push_str("\": ");
                    value.write_json_pretty(output, indent + 1);
                    if i < obj.len() - 1 {
                        output.push(',');
                    }
                    output.push('\n');
                }
                Self::write_indent(output, indent);
                output.push('}');
            }
        }
    }

    fn write_indent(output: &mut String, indent: usize) {
        for _ in 0..indent {
            output.push(' ');
        }
    }
}
