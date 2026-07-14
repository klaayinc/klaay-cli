/// One-word name of a JSON value's type, for error messages like
/// "expected a string, got a {json_type_name}". Lives in its own module
/// (not `main.rs`, the crate root) so a non-CLI-dispatch helper module
/// (`upload.rs`) doesn't have to import a formatting utility from the
/// binary entry point - `main.rs` and `upload.rs` both import it from here
/// instead.
pub(crate) fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
