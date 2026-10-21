//! MAC vendor lookup from the IEEE MA-L registry (generated from /usr/share/hwdata/oui.txt).

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::model::Mac;

static OUI_TSV: &str = include_str!("../assets/oui.tsv");

fn table() -> &'static HashMap<u32, &'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        OUI_TSV
            .lines()
            .filter_map(|line| {
                let (prefix, vendor) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, vendor))
            })
            .collect()
    })
}

pub fn lookup(mac: Mac) -> Option<&'static str> {
    let [a, b, c, ..] = mac.0;
    let prefix = u32::from_be_bytes([0, a, b, c]);
    table().get(&prefix).copied().or_else(|| {
        mac.is_locally_administered()
            .then_some("Randomized / locally administered")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors() {
        assert_eq!(
            lookup("00:50:56:94:c6:c9".parse().unwrap()),
            Some("VMware, Inc.")
        );
        assert_eq!(
            lookup("f4:02:70:cf:d7:22".parse().unwrap()),
            Some("Dell Inc.")
        );
        assert_eq!(
            lookup("02:00:00:00:00:01".parse().unwrap()),
            Some("Randomized / locally administered")
        );
    }
}
