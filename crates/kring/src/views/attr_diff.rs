//! Differences between two attribute sets, listed before saving.

use kring_core::model::Attributes;

/// Attribute changes, each list sorted by key.
#[derive(Debug, Default, PartialEq)]
pub struct AttrDiff {
    /// Keys removed, with their old value.
    pub removed: Vec<(String, String)>,
    /// Keys whose value changed: (key, old, new).
    pub changed: Vec<(String, String, String)>,
    /// Keys added, with their new value.
    pub added: Vec<(String, String)>,
}

impl AttrDiff {
    /// Returns true when nothing changes.
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.changed.is_empty() && self.added.is_empty()
    }

    /// Human readable lines: removed, then changed (old -> new), then added.
    pub fn lines(&self) -> Vec<String> {
        let removed = self
            .removed
            .iter()
            .map(|(k, v)| format!("Removed: {k} = {v}"));
        let changed = self
            .changed
            .iter()
            .map(|(k, old, new)| format!("Changed: {k}: {old} -> {new}"));
        let added = self.added.iter().map(|(k, v)| format!("Added: {k} = {v}"));
        removed.chain(changed).chain(added).collect()
    }
}

/// Compares the stored attributes with the edited ones.
pub fn attribute_diff(old: &Attributes, new: &Attributes) -> AttrDiff {
    let mut diff = AttrDiff::default();
    for (key, old_value) in old {
        match new.get(key) {
            None => diff.removed.push((key.clone(), old_value.clone())),
            Some(v) if v != old_value => {
                diff.changed
                    .push((key.clone(), old_value.clone(), v.clone()));
            }
            Some(_) => {}
        }
    }
    for (key, value) in new {
        if !old.contains_key(key) {
            diff.added.push((key.clone(), value.clone()));
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds attributes from pairs.
    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Removed, changed and added keys are classified; unchanged keys are omitted.
    #[test]
    fn classifies_changes() {
        let old = attrs(&[("gone", "1"), ("same", "s"), ("val", "a")]);
        let new = attrs(&[("new", "n"), ("same", "s"), ("val", "b")]);
        let d = attribute_diff(&old, &new);
        assert_eq!(d.removed, vec![("gone".to_string(), "1".to_string())]);
        assert_eq!(
            d.changed,
            vec![("val".to_string(), "a".to_string(), "b".to_string())]
        );
        assert_eq!(d.added, vec![("new".to_string(), "n".to_string())]);
        assert!(!d.is_empty());
        assert_eq!(
            d.lines(),
            [
                "Removed: gone = 1",
                "Changed: val: a -> b",
                "Added: new = n"
            ]
        );
    }

    /// Identical sets give an empty diff.
    #[test]
    fn identical_is_empty() {
        let a = attrs(&[("k", "v")]);
        let d = attribute_diff(&a, &a.clone());
        assert!(d.is_empty());
        assert!(d.lines().is_empty());
        assert!(attribute_diff(&Attributes::new(), &Attributes::new()).is_empty());
    }
}
