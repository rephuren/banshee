//! MITRE ATT&CK references taken from rule tags. There is no embedded ATT&CK matrix (no network, no bundled data), so
//! techniques are reported as the rule author tagged them and are not validated against the real matrix.

use std::collections::BTreeMap;

#[derive(Debug, Default, PartialEq)]
pub struct Tags {
    pub techniques: Vec<String>, // "T1059.001"
    pub tactics: Vec<String>,    // "execution"
}

/// Splits Sigma-style tags ("attack.t1059.001", "attack.execution") into techniques and tactics. Other tags are ignored.
pub fn parse_tags(tags: &[String]) -> Tags {
    let mut out = Tags::default();
    for tag in tags {
        let t = tag.to_ascii_lowercase();
        let Some(rest) = t.strip_prefix("attack.") else {
            continue;
        };
        let is_technique = rest.len() >= 5
            && rest.starts_with('t')
            && rest[1..5].chars().all(|c| c.is_ascii_digit())
            && rest[5..].chars().all(|c| c == '.' || c.is_ascii_digit());
        if is_technique {
            out.techniques.push(rest.to_ascii_uppercase());
        } else if !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
        {
            out.tactics.push(rest.replace('_', "-"));
        }
    }
    out
}

/// Counts how many matches carry each technique (and tactic).
pub fn tally<'a>(
    tag_lists: impl Iterator<Item = &'a Tags>,
) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut techniques = BTreeMap::new();
    let mut tactics = BTreeMap::new();
    for t in tag_lists {
        for x in &t.techniques {
            *techniques.entry(x.clone()).or_insert(0) += 1;
        }
        for x in &t.tactics {
            *tactics.entry(x.clone()).or_insert(0) += 1;
        }
    }
    (techniques, tactics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_techniques_and_tactics() {
        let tags = vec![
            "attack.t1059.001".to_string(),
            "attack.execution".into(),
            "attack.defense_evasion".into(),
            "cve.2021-1".into(),
            "attack.t10".into(),
        ];
        let t = parse_tags(&tags);
        assert_eq!(t.techniques, vec!["T1059.001"]);
        assert_eq!(t.tactics, vec!["execution", "defense-evasion"]);
    }

    #[test]
    fn tally_counts() {
        let a = Tags {
            techniques: vec!["T1".into()],
            tactics: vec!["x".into()],
        };
        let b = Tags {
            techniques: vec!["T1".into(), "T2".into()],
            tactics: vec![],
        };
        let (tech, tac) = tally([&a, &b].into_iter());
        assert_eq!(tech["T1"], 2);
        assert_eq!(tech["T2"], 1);
        assert_eq!(tac["x"], 1);
    }
}
