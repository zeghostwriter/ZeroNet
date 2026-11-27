//! Putting several Xray configuration files together, the way Xray does when
//! it is given more than one `-c` or a `-confdir`.
//!
//! How this works: the files are applied in order (a directory's files in
//! file-name order, so `01_log.json` goes before `02_dns.json`), each one laid
//! over what the earlier ones made:
//!
//! * an object is merged key by key;
//! * `inbounds` and `outbounds` are merged by `tag`: an element with a tag
//!   already present replaces it, any other is added. New outbounds go to the
//!   *front* (the first outbound is the default), unless the file's name has
//!   `tail` in it, which puts them at the back; new inbounds go to the back;
//! * every other array (routing rules, balancers, DNS servers) is appended;
//! * anything else is replaced by the later file.
//!
//! After the last file, an array whose elements carry a `_priority` number is
//! put in order of it (smallest first, ties kept in file order), and the
//! marker is dropped. That is how a rule in a late file can still be tried
//! first.
//!
//! The surprise: replacing by tag replaces the *whole element*, not its
//! fields, so a later file that names an outbound must repeat all of it.

use serde_json::{Map, Value};

/// Lay `documents` over each other, in order. Each is `(file name, content)`;
/// the name only matters for the `tail` rule. Every document must be an
/// object.
pub fn merge_documents(documents: Vec<(String, Value)>) -> Result<Value, String> {
    let mut merged = Map::new();
    for (name, document) in documents {
        let Value::Object(object) = document else {
            return Err(format!("{name}: a configuration must be a JSON object"));
        };
        let tail = name.to_ascii_lowercase().contains("tail");
        merge_objects(&mut merged, object, tail, true);
    }
    let mut merged = Value::Object(merged);
    order_by_priority(&mut merged);
    Ok(merged)
}

fn merge_objects(into: &mut Map<String, Value>, from: Map<String, Value>, tail: bool, top: bool) {
    for (key, value) in from {
        match (into.get_mut(&key), value) {
            (Some(Value::Array(old)), Value::Array(new)) if top && key == "inbounds" => {
                merge_tagged(old, new, true)
            }
            (Some(Value::Array(old)), Value::Array(new)) if top && key == "outbounds" => {
                merge_tagged(old, new, tail)
            }
            (Some(Value::Array(old)), Value::Array(new)) => old.extend(new),
            (Some(Value::Object(old)), Value::Object(new)) => merge_objects(old, new, tail, false),
            (_, value) => {
                into.insert(key, value);
            }
        }
    }
}

/// Merge `new` into `old` by `tag`; elements with no tag, or a tag not yet
/// present, are added at the back (`at_back`) or the front, keeping their own
/// order.
fn merge_tagged(old: &mut Vec<Value>, new: Vec<Value>, at_back: bool) {
    let tag_of = |value: &Value| value.get("tag").and_then(Value::as_str).map(str::to_owned);
    let mut added = Vec::new();
    for element in new {
        let existing = tag_of(&element)
            .and_then(|tag| old.iter().position(|e| tag_of(e).as_deref() == Some(&tag)));
        match existing {
            Some(index) => old[index] = element,
            None => added.push(element),
        }
    }
    if at_back {
        old.extend(added);
    } else {
        old.splice(0..0, added);
    }
}

/// Sort every array whose elements have `_priority`, and drop the marker.
fn order_by_priority(value: &mut Value) {
    match value {
        Value::Array(items) => {
            let key = |item: &Value| item.get("_priority").and_then(Value::as_f64);
            if items.iter().any(|item| key(item).is_some()) {
                items.sort_by(|a, b| {
                    key(a)
                        .unwrap_or(0.0)
                        .partial_cmp(&key(b).unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            for item in items.iter_mut() {
                if let Value::Object(object) = item {
                    object.remove("_priority");
                }
                order_by_priority(item);
            }
        }
        Value::Object(object) => object.values_mut().for_each(order_by_priority),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn merge(files: &[(&str, Value)]) -> Value {
        merge_documents(
            files
                .iter()
                .map(|(n, v)| (n.to_string(), v.clone()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn objects_merge_and_scalars_are_replaced_by_the_later_file() {
        let merged = merge(&[
            (
                "01.json",
                json!({"log": {"loglevel": "info", "access": "a"}, "x": 1}),
            ),
            ("02.json", json!({"log": {"loglevel": "debug"}, "x": 2})),
        ]);
        assert_eq!(merged["log"], json!({"loglevel": "debug", "access": "a"}));
        assert_eq!(merged["x"], 2);
    }

    #[test]
    fn inbounds_merge_by_tag_and_new_ones_go_to_the_back() {
        let merged = merge(&[
            (
                "01.json",
                json!({"inbounds": [{"tag": "a", "port": 1}, {"tag": "b", "port": 2}]}),
            ),
            (
                "02.json",
                json!({"inbounds": [{"tag": "b", "port": 20}, {"tag": "c", "port": 3}]}),
            ),
        ]);
        assert_eq!(
            merged["inbounds"],
            json!([{"tag": "a", "port": 1}, {"tag": "b", "port": 20}, {"tag": "c", "port": 3}])
        );
    }

    #[test]
    fn new_outbounds_go_to_the_front_unless_the_file_says_tail() {
        let merged = merge(&[
            ("01.json", json!({"outbounds": [{"tag": "direct"}]})),
            ("02.json", json!({"outbounds": [{"tag": "proxy"}]})),
            ("03_tail.json", json!({"outbounds": [{"tag": "block"}]})),
        ]);
        let tags: Vec<_> = merged["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, ["proxy", "direct", "block"]);
    }

    #[test]
    fn other_arrays_are_appended() {
        let merged = merge(&[
            (
                "01.json",
                json!({"routing": {"rules": [{"outboundTag": "a"}]}, "dns": {"servers": ["1.1.1.1"]}}),
            ),
            (
                "02.json",
                json!({"routing": {"rules": [{"outboundTag": "b"}]}, "dns": {"servers": ["8.8.8.8"]}}),
            ),
        ]);
        assert_eq!(merged["routing"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(merged["dns"]["servers"], json!(["1.1.1.1", "8.8.8.8"]));
    }

    #[test]
    fn a_priority_puts_a_late_rule_first_and_is_not_kept() {
        let merged = merge(&[
            (
                "01.json",
                json!({"routing": {"rules": [{"outboundTag": "a"}]}}),
            ),
            (
                "02.json",
                json!({"routing": {"rules": [{"outboundTag": "b", "_priority": -1}]}}),
            ),
        ]);
        let rules = merged["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "b");
        assert!(rules[0].get("_priority").is_none());
    }

    #[test]
    fn a_document_that_is_not_an_object_is_refused() {
        let error = merge_documents(vec![("x.json".into(), json!([1]))]).unwrap_err();
        assert!(error.contains("x.json"));
    }
}
