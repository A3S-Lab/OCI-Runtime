use serde::Serialize;
use serde_json::{Map, Value};

/// Encode a serializable value as JSON with every object key sorted.
///
/// This is intended for durable request fingerprints that must remain stable
/// when a request is reconstructed in another process. Array order and scalar
/// values are preserved; only JSON object key order is normalized.
pub fn canonical_json_bytes<T>(value: &T) -> serde_json::Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&sort_object_keys(value))
}

fn sort_object_keys(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_object_keys).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_object_keys(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::Serialize;

    use super::canonical_json_bytes;

    #[derive(Serialize)]
    struct Fixture {
        nested: HashMap<String, HashMap<String, u64>>,
        order: Vec<u64>,
    }

    #[test]
    fn canonical_json_sorts_nested_unordered_maps_and_preserves_arrays() {
        let first = Fixture {
            nested: HashMap::from([
                (
                    "second".to_string(),
                    HashMap::from([("z".to_string(), 3), ("a".to_string(), 2)]),
                ),
                ("first".to_string(), HashMap::from([("b".to_string(), 1)])),
            ]),
            order: vec![3, 1, 2],
        };
        let second = Fixture {
            nested: HashMap::from([
                ("first".to_string(), HashMap::from([("b".to_string(), 1)])),
                (
                    "second".to_string(),
                    HashMap::from([("a".to_string(), 2), ("z".to_string(), 3)]),
                ),
            ]),
            order: vec![3, 1, 2],
        };

        let first = canonical_json_bytes(&first).expect("canonical first fixture");
        let second = canonical_json_bytes(&second).expect("canonical second fixture");

        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).expect("canonical JSON is UTF-8"),
            r#"{"nested":{"first":{"b":1},"second":{"a":2,"z":3}},"order":[3,1,2]}"#
        );
    }
}
