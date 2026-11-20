//! A subset of the YARA rule language: text strings (`nocase`, `wide`, `ascii`, `fullword`), hex strings with `??`, regular
//! expressions, and conditions built from `and`, `or`, `not`, parentheses, `$a`, `#a`, `N of`, `any of`, `all of`,
//! `filesize` and `uint8/16/32(offset)` comparisons.
//!
//! Not supported (and rejected with a reason, never ignored): modules (`import`), `include`, `private`/`global` rules,
//! hex jumps `[n-m]` and alternations, nibble wildcards, the modifiers `xor`, `base64`, `private`, `at`/`in` conditions,
//! `for` loops and string identifiers inside conditions other than `$name`.

use std::collections::BTreeMap;
use std::path::Path;

use regex::bytes::{Regex, RegexBuilder};

const MAX_OCCURRENCES: usize = 100_000; // per string: a degenerate pattern on a big file must not exhaust memory
pub const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
enum HexTok {
    Byte(u8),
    Any,
}

#[derive(Debug)]
enum StrKind {
    Text {
        bytes: Vec<u8>,
        nocase: bool,
        ascii: bool,
        wide: bool,
        fullword: bool,
    },
    Hex(Vec<HexTok>),
    Re(Regex),
}

#[derive(Debug)]
struct StrDef {
    name: String,
    kind: StrKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug)]
enum Operand {
    Int(i64),
    FileSize,
    Count(String),
    Uint {
        width: u8,
        big: bool,
        at: Box<Operand>,
    },
}

#[derive(Debug)]
enum Set {
    Them,
    Names(Vec<String>), // may end in `*`
}

#[derive(Debug)]
enum Quant {
    Any,
    All,
    Num(usize),
}

#[derive(Debug)]
enum Expr {
    Bool(bool),
    Str(String),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Cmp(Operand, Op, Operand),
    Of(Quant, Set),
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub meta: BTreeMap<String, String>,
    strings: Vec<StrDef>,
    condition: Expr,
}

impl Rule {
    pub fn description(&self) -> &str {
        self.meta
            .get("description")
            .map(String::as_str)
            .unwrap_or("")
    }

    /// ATT&CK technique ids from `mitre_attack`/`attack` meta ("T1059.001, T1204").
    pub fn techniques(&self) -> Vec<String> {
        let raw = self
            .meta
            .get("mitre_attack")
            .or_else(|| self.meta.get("attack"));
        raw.map(|s| {
            s.split([',', ' ', ';'])
                .filter(|x| !x.is_empty())
                .map(|x| x.to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default()
    }
}

// ---------------------------------------------------------------- parsing

struct Cur<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn ws(&mut self) -> Result<(), String> {
        loop {
            while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.s[self.i..].starts_with(b"//") {
                while self.i < self.s.len() && self.s[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.s[self.i..].starts_with(b"/*") {
                match find(&self.s[self.i + 2..], b"*/") {
                    Some(p) => self.i += 2 + p + 2,
                    None => return Err("unterminated /* comment".into()),
                }
            } else {
                return Ok(());
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn ident(&mut self) -> Option<String> {
        let start = self.i;
        while self.i < self.s.len()
            && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_')
        {
            self.i += 1;
        }
        (self.i > start).then(|| String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn quoted(c: &mut Cur) -> Result<Vec<u8>, String> {
    if !c.eat(b'"') {
        return Err("expected a string in double quotes".into());
    }
    let mut out = Vec::new();
    loop {
        let b = c.peek().ok_or("unterminated string")?;
        c.i += 1;
        match b {
            b'"' => return Ok(out),
            b'\\' => {
                let e = c.peek().ok_or("unterminated string")?;
                c.i += 1;
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'\\' => out.push(b'\\'),
                    b'"' => out.push(b'"'),
                    b'x' => {
                        let h = c.s.get(c.i..c.i + 2).ok_or("bad \\x escape")?;
                        let v = u8::from_str_radix(
                            std::str::from_utf8(h).map_err(|_| "bad \\x escape")?,
                            16,
                        )
                        .map_err(|_| "bad \\x escape")?;
                        out.push(v);
                        c.i += 2;
                    }
                    other => return Err(format!("unknown escape \\{}", other as char)),
                }
            }
            b'\n' => return Err("newline inside a string".into()),
            b => out.push(b),
        }
    }
}

fn hex_string(c: &mut Cur) -> Result<Vec<HexTok>, String> {
    c.eat(b'{');
    let mut out = Vec::new();
    loop {
        c.ws()?;
        match c.peek().ok_or("unterminated hex string")? {
            b'}' => {
                c.i += 1;
                break;
            }
            b'[' => return Err("hex jumps [n-m] are not supported".into()),
            b'(' | b'|' => return Err("hex alternations are not supported".into()),
            b'~' => return Err("hex negation is not supported".into()),
            b'?' => {
                if c.s.get(c.i + 1) != Some(&b'?') {
                    return Err("nibble wildcards (?A) are not supported, use ??".into());
                }
                c.i += 2;
                out.push(HexTok::Any);
            }
            b => {
                if !b.is_ascii_hexdigit() {
                    return Err(format!("bad character {:?} in a hex string", b as char));
                }
                let h = c.s.get(c.i..c.i + 2).ok_or("odd number of hex digits")?;
                if !h[1].is_ascii_hexdigit() && h[1] != b'?' {
                    return Err("odd number of hex digits in a hex string".into());
                }
                if !h[1].is_ascii_hexdigit() {
                    return Err("nibble wildcards (A?) are not supported, use ??".into());
                }
                out.push(HexTok::Byte(
                    u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16)
                        .map_err(|e| e.to_string())?,
                ));
                c.i += 2;
            }
        }
    }
    if out.is_empty() {
        return Err("empty hex string".into());
    }
    if matches!(out.first(), Some(HexTok::Any)) || matches!(out.last(), Some(HexTok::Any)) {
        return Err("a hex string must start and end with a concrete byte".into());
    }
    Ok(out)
}

fn regex_literal(c: &mut Cur) -> Result<(String, bool), String> {
    c.eat(b'/');
    let mut pat = Vec::new();
    loop {
        let b = c.peek().ok_or("unterminated regular expression")?;
        c.i += 1;
        match b {
            b'/' => break,
            b'\\' => {
                let n = c.peek().ok_or("unterminated regular expression")?;
                c.i += 1;
                if n == b'/' {
                    pat.push(b'/');
                } else {
                    pat.push(b'\\');
                    pat.push(n);
                }
            }
            b'\n' => return Err("newline inside a regular expression".into()),
            b => pat.push(b),
        }
    }
    let mut nocase = false;
    while let Some(f) = c.peek() {
        match f {
            b'i' => nocase = true,
            b's' | b'm' => {}
            _ => break,
        }
        c.i += 1;
    }
    Ok((
        String::from_utf8(pat).map_err(|_| "regular expression must be valid UTF-8")?,
        nocase,
    ))
}

fn parse_string_def(c: &mut Cur) -> Result<StrDef, String> {
    c.i += 1; // '$'
    let name = c
        .ident()
        .ok_or("anonymous strings ($ alone) are not supported")?;
    c.ws()?;
    if !c.eat(b'=') {
        return Err(format!("expected = after ${name}"));
    }
    c.ws()?;
    let kind_start = c.peek().ok_or("string definition ends unexpectedly")?;
    let (mut nocase, mut ascii, mut wide, mut fullword) = (false, false, false, false);
    enum Raw {
        Text(Vec<u8>),
        Hex(Vec<HexTok>),
        Re(String, bool),
    }
    let raw = match kind_start {
        b'"' => Raw::Text(quoted(c)?),
        b'{' => Raw::Hex(hex_string(c)?),
        b'/' => {
            let (p, i) = regex_literal(c)?;
            Raw::Re(p, i)
        }
        _ => {
            return Err(format!(
                "${name}: expected a string, hex string or regular expression"
            ))
        }
    };
    loop {
        let save = c.i;
        c.ws()?;
        let before = c.i;
        match c.ident() {
            Some(m) => match m.as_str() {
                "nocase" => nocase = true,
                "ascii" => ascii = true,
                "wide" => wide = true,
                "fullword" => fullword = true,
                "xor" | "base64" | "base64wide" | "private" => {
                    return Err(format!("string modifier `{m}` is not supported"))
                }
                _ => {
                    c.i = before.min(save.max(before)); // not a modifier: the next definition or section starts here
                    c.i = before;
                    break;
                }
            },
            None => break,
        }
    }
    let kind = match raw {
        Raw::Text(bytes) => {
            if bytes.is_empty() {
                return Err(format!("${name}: empty string"));
            }
            if !ascii && !wide {
                ascii = true;
            }
            StrKind::Text {
                bytes,
                nocase,
                ascii,
                wide,
                fullword,
            }
        }
        Raw::Hex(h) => {
            if nocase || wide || ascii || fullword {
                return Err(format!(
                    "${name}: text modifiers do not apply to hex strings"
                ));
            }
            StrKind::Hex(h)
        }
        Raw::Re(p, i) => {
            let re = RegexBuilder::new(&p)
                .case_insensitive(i || nocase)
                .unicode(false)
                .build()
                .map_err(|e| format!("${name}: bad regular expression: {e}"))?;
            StrKind::Re(re)
        }
    };
    Ok(StrDef { name, kind })
}

// condition tokens

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),     // $name
    StrGlob(String), // $name*
    Count(String),   // #name
    Int(i64),
    Word(String),
    Sym(&'static str),
}

fn lex_condition(src: &[u8]) -> Result<Vec<Tok>, String> {
    let mut c = Cur { s: src, i: 0 };
    let mut out = Vec::new();
    loop {
        c.ws()?;
        let Some(b) = c.peek() else { break };
        match b {
            b'$' => {
                c.i += 1;
                let n = c.ident().ok_or("anonymous strings are not supported")?;
                out.push(if c.eat(b'*') { Tok::StrGlob(n) } else { Tok::Str(n) });
            }
            b'#' => {
                c.i += 1;
                out.push(Tok::Count(c.ident().ok_or("expected a string name after #")?));
            }
            b'(' | b')' | b',' => {
                c.i += 1;
                out.push(Tok::Sym(match b {
                    b'(' => "(",
                    b')' => ")",
                    _ => ",",
                }));
            }
            b'=' | b'!' | b'<' | b'>' => {
                c.i += 1;
                let two = c.eat(b'=');
                out.push(Tok::Sym(match (b, two) {
                    (b'=', true) => "==",
                    (b'!', true) => "!=",
                    (b'<', true) => "<=",
                    (b'>', true) => ">=",
                    (b'<', false) => "<",
                    (b'>', false) => ">",
                    _ => return Err("unexpected = or ! in condition".into()),
                }));
            }
            b'0'..=b'9' => {
                let start = c.i;
                while c.i < src.len() && (src[c.i].is_ascii_alphanumeric()) {
                    c.i += 1;
                }
                let text = std::str::from_utf8(&src[start..c.i]).unwrap().to_ascii_lowercase();
                let (digits, mult) = if let Some(d) = text.strip_suffix("kb") {
                    (d, 1024i64)
                } else if let Some(d) = text.strip_suffix("mb") {
                    (d, 1024 * 1024)
                } else {
                    (text.as_str(), 1)
                };
                let v = if let Some(h) = digits.strip_prefix("0x") { i64::from_str_radix(h, 16) } else { digits.parse::<i64>() };
                let v = v.map_err(|_| format!("bad number {text:?}"))?;
                out.push(Tok::Int(v.checked_mul(mult).ok_or("number too large")?));
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let w = c.ident().unwrap().to_ascii_lowercase();
                if w == "for" {
                    return Err("`for` loops are not supported".into());
                }
                out.push(Tok::Word(w));
            }
            b'"' | b'/' | b'{' | b'[' => return Err("string literals, regular expressions and ranges are not supported inside conditions".into()),
            other => return Err(format!("unexpected character {:?} in condition", other as char)),
        }
    }
    Ok(out)
}

struct CondParser {
    t: Vec<Tok>,
    i: usize,
}

impl CondParser {
    fn peek_word(&self, w: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Word(x)) if x == w)
    }

    fn eat_sym(&mut self, s: &str) -> bool {
        if matches!(self.t.get(self.i), Some(Tok::Sym(x)) if *x == s) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.and()?];
        while self.peek_word("or") {
            self.i += 1;
            v.push(self.and()?);
        }
        Ok(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Expr::Or(v)
        })
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.not()?];
        while self.peek_word("and") {
            self.i += 1;
            v.push(self.not()?);
        }
        Ok(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Expr::And(v)
        })
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.peek_word("not") {
            self.i += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.cmp()
    }

    fn operand(&mut self) -> Result<Operand, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Int(n)) => {
                self.i += 1;
                Ok(Operand::Int(n))
            }
            Some(Tok::Count(n)) => {
                self.i += 1;
                Ok(Operand::Count(n))
            }
            Some(Tok::Word(w)) if w == "filesize" => {
                self.i += 1;
                Ok(Operand::FileSize)
            }
            Some(Tok::Word(w))
                if matches!(
                    w.as_str(),
                    "uint8" | "uint16" | "uint32" | "uint16be" | "uint32be"
                ) =>
            {
                self.i += 1;
                if !self.eat_sym("(") {
                    return Err(format!("{w} needs an offset in parentheses"));
                }
                let at = self.operand()?;
                if !self.eat_sym(")") {
                    return Err(format!("missing ) after the {w} offset"));
                }
                let width = if w.starts_with("uint8") {
                    1
                } else if w.starts_with("uint16") {
                    2
                } else {
                    4
                };
                Ok(Operand::Uint {
                    width,
                    big: w.ends_with("be"),
                    at: Box::new(at),
                })
            }
            other => Err(format!(
                "expected a number, #count, filesize or uintN(..), found {other:?}"
            )),
        }
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let n_of = matches!(self.t.get(self.i), Some(Tok::Int(_)))
            && self.t.get(self.i + 1) == Some(&Tok::Word("of".into()));
        let starts_operand = !n_of
            && matches!(self.t.get(self.i), Some(Tok::Int(_)) | Some(Tok::Count(_)))
            || self.peek_word("filesize")
            || ["uint8", "uint16", "uint32", "uint16be", "uint32be"]
                .iter()
                .any(|w| self.peek_word(w));
        if starts_operand {
            let l = self.operand()?;
            let op = match self.t.get(self.i) {
                Some(Tok::Sym("==")) => Op::Eq,
                Some(Tok::Sym("!=")) => Op::Ne,
                Some(Tok::Sym("<")) => Op::Lt,
                Some(Tok::Sym("<=")) => Op::Le,
                Some(Tok::Sym(">")) => Op::Gt,
                Some(Tok::Sym(">=")) => Op::Ge,
                _ => return Err("expected a comparison operator".into()),
            };
            self.i += 1;
            let r = self.operand()?;
            return Ok(Expr::Cmp(l, op, r));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Sym("(")) => {
                self.i += 1;
                let e = self.or()?;
                if !self.eat_sym(")") {
                    return Err("missing closing parenthesis in condition".into());
                }
                Ok(e)
            }
            Some(Tok::Str(n)) => {
                self.i += 1;
                if self.peek_word("at") || self.peek_word("in") {
                    return Err("`at` and `in` conditions are not supported".into());
                }
                Ok(Expr::Str(n))
            }
            Some(Tok::Word(w)) if w == "true" || w == "false" => {
                self.i += 1;
                Ok(Expr::Bool(w == "true"))
            }
            Some(Tok::Word(w)) if w == "for" => Err("`for` loops are not supported".into()),
            Some(Tok::Word(w)) if w == "any" || w == "all" => {
                self.i += 1;
                self.of(if w == "any" { Quant::Any } else { Quant::All })
            }
            Some(Tok::Int(n)) if self.t.get(self.i + 1) == Some(&Tok::Word("of".into())) => {
                self.i += 1;
                self.of(Quant::Num(
                    usize::try_from(n).map_err(|_| "negative count before `of`")?,
                ))
            }
            other => Err(format!("unexpected {other:?} in condition")),
        }
    }

    fn of(&mut self, q: Quant) -> Result<Expr, String> {
        if !self.peek_word("of") {
            return Err("expected `of`".into());
        }
        self.i += 1;
        if self.peek_word("them") {
            self.i += 1;
            return Ok(Expr::Of(q, Set::Them));
        }
        if !self.eat_sym("(") {
            return Err("expected `them` or a parenthesised list of strings after `of`".into());
        }
        let mut names = Vec::new();
        loop {
            match self.t.get(self.i).cloned() {
                Some(Tok::Str(n)) => names.push(n),
                Some(Tok::StrGlob(n)) => names.push(format!("{n}*")),
                other => return Err(format!("expected a string name, found {other:?}")),
            }
            self.i += 1;
            if self.eat_sym(",") {
                continue;
            }
            if self.eat_sym(")") {
                break;
            }
            return Err("expected , or ) in the string list".into());
        }
        Ok(Expr::Of(q, Set::Names(names)))
    }
}

fn selects(name: &str, def: &str) -> bool {
    match name.strip_suffix('*') {
        Some(prefix) => def.starts_with(prefix),
        None => name == def,
    }
}

fn check_refs(e: &Expr, defs: &[StrDef]) -> Result<(), String> {
    let has = |n: &str| defs.iter().any(|d| d.name == n);
    let has_any = |p: &str| defs.iter().any(|d| selects(p, &d.name));
    match e {
        Expr::Str(n) => has(n)
            .then_some(())
            .ok_or(format!("condition refers to undefined string ${n}")),
        Expr::Not(x) => check_refs(x, defs),
        Expr::And(v) | Expr::Or(v) => v.iter().try_for_each(|x| check_refs(x, defs)),
        Expr::Cmp(a, _, b) => [a, b].iter().try_for_each(|o| match o {
            Operand::Count(n) => has(n)
                .then_some(())
                .ok_or(format!("condition refers to undefined string #{n}")),
            _ => Ok(()),
        }),
        Expr::Of(_, Set::Names(ns)) => ns.iter().try_for_each(|n| {
            has_any(n)
                .then_some(())
                .ok_or(format!("`of` list names no defined string: ${n}"))
        }),
        Expr::Of(..) | Expr::Bool(_) => Ok(()),
    }
}

/// Parses every rule in `text`.
pub fn parse_rules(text: &str) -> Result<Vec<Rule>, String> {
    let mut c = Cur {
        s: text.as_bytes(),
        i: 0,
    };
    let mut rules = Vec::new();
    loop {
        c.ws()?;
        if c.peek().is_none() {
            break;
        }
        let kw = c.ident().ok_or("expected `rule`")?;
        match kw.as_str() {
            "rule" => {}
            "import" | "include" => {
                return Err(format!(
                    "`{kw}` is not supported (modules are not implemented)"
                ))
            }
            "private" | "global" => return Err(format!("`{kw}` rules are not supported")),
            other => return Err(format!("expected `rule`, found `{other}`")),
        }
        c.ws()?;
        let name = c.ident().ok_or("rule needs a name")?;
        let ctx = |e: String| format!("rule {name}: {e}");
        c.ws()?;
        let mut tags = Vec::new();
        if c.eat(b':') {
            loop {
                c.ws()?;
                match c.ident() {
                    Some(t) => tags.push(t),
                    None => break,
                }
            }
        }
        c.ws()?;
        if !c.eat(b'{') {
            return Err(ctx("expected {".into()));
        }
        let mut meta = BTreeMap::new();
        let mut strings = Vec::new();
        let mut condition = None;
        loop {
            c.ws().map_err(ctx)?;
            if c.eat(b'}') {
                break;
            }
            let sec = c
                .ident()
                .ok_or_else(|| ctx("expected meta:, strings:, condition: or }".into()))?;
            c.ws().map_err(ctx)?;
            if !c.eat(b':') {
                return Err(ctx(format!("expected : after `{sec}`")));
            }
            match sec.as_str() {
                "meta" => loop {
                    c.ws().map_err(ctx)?;
                    let save = c.i;
                    let Some(key) = c.ident() else { break };
                    c.ws().map_err(ctx)?;
                    if !c.eat(b'=') {
                        c.i = save; // a section keyword
                        break;
                    }
                    c.ws().map_err(ctx)?;
                    let val = match c.peek() {
                        Some(b'"') => {
                            String::from_utf8_lossy(&quoted(&mut c).map_err(ctx)?).into_owned()
                        }
                        _ => c.ident().ok_or_else(|| ctx("bad meta value".into()))?,
                    };
                    meta.insert(key, val);
                },
                "strings" => loop {
                    c.ws().map_err(ctx)?;
                    if c.peek() != Some(b'$') {
                        break;
                    }
                    let def = parse_string_def(&mut c).map_err(ctx)?;
                    if strings.iter().any(|d: &StrDef| d.name == def.name) {
                        return Err(ctx(format!("string ${} defined twice", def.name)));
                    }
                    strings.push(def);
                },
                "condition" => {
                    let rest = &c.s[c.i..];
                    let end = rest
                        .iter()
                        .position(|&b| b == b'}')
                        .ok_or_else(|| ctx("rule is not closed with }".into()))?;
                    let toks = lex_condition(&rest[..end]).map_err(ctx)?;
                    let mut p = CondParser { t: toks, i: 0 };
                    let e = p.or().map_err(ctx)?;
                    if p.i < p.t.len() {
                        return Err(ctx(format!("unexpected {:?} in condition", p.t[p.i])));
                    }
                    c.i += end;
                    condition = Some(e);
                }
                other => return Err(ctx(format!("unknown section `{other}`"))),
            }
        }
        let condition = condition.ok_or_else(|| ctx("missing condition".into()))?;
        check_refs(&condition, &strings).map_err(ctx)?;
        rules.push(Rule {
            name,
            tags,
            meta,
            strings,
            condition,
        });
    }
    Ok(rules)
}

// ---------------------------------------------------------------- matching

#[derive(Debug, Clone, Default)]
pub struct Occ {
    pub count: usize,
    pub first: Option<usize>,
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn text_occurrences(
    data: &[u8],
    pat: &[u8],
    nocase: bool,
    wide: bool,
    fullword: bool,
    occ: &mut Occ,
) {
    let needle: Vec<u8> = if wide {
        pat.iter().flat_map(|&b| [b, 0]).collect()
    } else {
        pat.to_vec()
    };
    if needle.len() > data.len() {
        return;
    }
    let step = if wide { 2 } else { 1 };
    let eq = |a: u8, b: u8| {
        if nocase {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    let mut i = 0;
    while i + needle.len() <= data.len() && occ.count < MAX_OCCURRENCES {
        if data[i..i + needle.len()]
            .iter()
            .zip(&needle)
            .all(|(&a, &b)| eq(a, b))
        {
            let ok = !fullword || {
                let before = if i >= step {
                    Some(data[i - step])
                } else {
                    None
                };
                let after = data.get(i + needle.len()).copied();
                let wide_zero =
                    |idx: usize| !wide || data.get(idx) == Some(&0) || data.get(idx).is_none();
                !before.map(is_word_byte).unwrap_or(false)
                    && !after.map(is_word_byte).unwrap_or(false)
                    && wide_zero(i.saturating_sub(1))
                    && wide_zero(i + needle.len() + 1)
            };
            if ok {
                occ.count += 1;
                occ.first.get_or_insert(i);
            }
        }
        i += 1;
    }
}

fn hex_occurrences(data: &[u8], toks: &[HexTok], occ: &mut Occ) {
    if toks.len() > data.len() {
        return;
    }
    let HexTok::Byte(first) = toks[0] else { return };
    let mut i = 0;
    while i + toks.len() <= data.len() && occ.count < MAX_OCCURRENCES {
        match data[i..=data.len() - toks.len()]
            .iter()
            .position(|&b| b == first)
        {
            None => break,
            Some(p) => i += p,
        }
        if toks
            .iter()
            .zip(&data[i..])
            .all(|(t, &b)| matches!(t, HexTok::Any) || matches!(t, HexTok::Byte(x) if *x == b))
        {
            occ.count += 1;
            occ.first.get_or_insert(i);
        }
        i += 1;
    }
}

fn find_occurrences(def: &StrDef, data: &[u8]) -> Occ {
    let mut occ = Occ::default();
    match &def.kind {
        StrKind::Text {
            bytes,
            nocase,
            ascii,
            wide,
            fullword,
        } => {
            if *ascii {
                text_occurrences(data, bytes, *nocase, false, *fullword, &mut occ);
            }
            if *wide {
                text_occurrences(data, bytes, *nocase, true, *fullword, &mut occ);
            }
        }
        StrKind::Hex(t) => hex_occurrences(data, t, &mut occ),
        StrKind::Re(r) => {
            for m in r.find_iter(data).take(MAX_OCCURRENCES) {
                occ.count += 1;
                occ.first.get_or_insert(m.start());
            }
        }
    }
    occ
}

struct Ctx<'a> {
    data: &'a [u8],
    occ: BTreeMap<&'a str, Occ>,
}

fn value(o: &Operand, cx: &Ctx) -> Option<i64> {
    match o {
        Operand::Int(n) => Some(*n),
        Operand::FileSize => i64::try_from(cx.data.len()).ok(),
        Operand::Count(n) => cx.occ.get(n.as_str()).map(|o| o.count as i64),
        Operand::Uint { width, big, at } => {
            let off = usize::try_from(value(at, cx)?).ok()?;
            let w = usize::from(*width);
            let bytes = cx.data.get(off..off.checked_add(w)?)?;
            let mut v: i64 = 0;
            if *big {
                for &b in bytes {
                    v = (v << 8) | i64::from(b);
                }
            } else {
                for &b in bytes.iter().rev() {
                    v = (v << 8) | i64::from(b);
                }
            }
            Some(v)
        }
    }
}

fn holds(e: &Expr, cx: &Ctx) -> bool {
    let present = |n: &str| cx.occ.get(n).map(|o| o.count > 0).unwrap_or(false);
    match e {
        Expr::Bool(b) => *b,
        Expr::Str(n) => present(n),
        Expr::Not(x) => !holds(x, cx),
        Expr::And(v) => v.iter().all(|x| holds(x, cx)),
        Expr::Or(v) => v.iter().any(|x| holds(x, cx)),
        Expr::Cmp(a, op, b) => match (value(a, cx), value(b, cx)) {
            (Some(l), Some(r)) => match op {
                Op::Eq => l == r,
                Op::Ne => l != r,
                Op::Lt => l < r,
                Op::Le => l <= r,
                Op::Gt => l > r,
                Op::Ge => l >= r,
            },
            _ => false, // an offset outside the file makes the comparison false, as in YARA
        },
        Expr::Of(q, set) => {
            let names: Vec<&str> = match set {
                Set::Them => cx.occ.keys().copied().collect(),
                Set::Names(ns) => cx
                    .occ
                    .keys()
                    .copied()
                    .filter(|d| ns.iter().any(|n| selects(n, d)))
                    .collect(),
            };
            let hits = names.iter().filter(|n| present(n)).count();
            match q {
                Quant::Any => hits >= 1,
                Quant::All => !names.is_empty() && hits == names.len(),
                Quant::Num(n) => hits >= *n,
            }
        }
    }
}

#[derive(Debug)]
pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    /// Strings that matched, with how many times and the offset of the first hit.
    pub strings: Vec<(String, Occ)>,
}

/// Runs every rule over `data`.
pub fn scan_bytes<'a>(rules: &'a [Rule], data: &[u8]) -> Vec<RuleMatch<'a>> {
    let mut out = Vec::new();
    for r in rules {
        let occ: BTreeMap<&str, Occ> = r
            .strings
            .iter()
            .map(|d| (d.name.as_str(), find_occurrences(d, data)))
            .collect();
        let cx = Ctx { data, occ };
        if holds(&r.condition, &cx) {
            let strings = cx
                .occ
                .iter()
                .filter(|(_, o)| o.count > 0)
                .map(|(n, o)| (n.to_string(), o.clone()))
                .collect();
            out.push(RuleMatch { rule: r, strings });
        }
    }
    out
}

/// Loads every `.yar`/`.yara` file under `dir`. Returns the rules and the files that could not be used, with the reason.
pub fn load_dir(dir: &Path) -> (Vec<Rule>, Vec<(String, String)>) {
    let mut rules = Vec::new();
    let mut skipped = Vec::new();
    for f in walk(dir, &["yar", "yara"], &mut skipped) {
        match std::fs::read_to_string(&f) {
            Ok(t) => match parse_rules(&t) {
                Ok(mut r) => rules.append(&mut r),
                Err(e) => skipped.push((f.display().to_string(), e)),
            },
            Err(e) => skipped.push((f.display().to_string(), e.to_string())),
        }
    }
    (rules, skipped)
}

/// Lists regular files below `root` (a file is returned as itself). Symlinks are not followed.
pub fn walk(
    root: &Path,
    exts: &[&str],
    skipped: &mut Vec<(String, String)>,
) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            skipped.push((p.display().to_string(), "cannot read".into()));
            continue;
        };
        if meta.is_file() {
            if exts.is_empty()
                || p.extension()
                    .and_then(|x| x.to_str())
                    .map(|x| exts.contains(&x))
                    .unwrap_or(false)
                || p == root
            {
                files.push(p);
            }
        } else if meta.is_dir() {
            match std::fs::read_dir(&p) {
                Ok(rd) => stack.extend(rd.flatten().map(|e| e.path())),
                Err(_) => skipped.push((p.display().to_string(), "cannot read directory".into())),
            }
        }
    }
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> Rule {
        let mut r = parse_rules(src).unwrap_or_else(|e| panic!("rule rejected: {e}"));
        assert_eq!(r.len(), 1);
        r.pop().unwrap()
    }

    fn hit(rule: &Rule, data: &[u8]) -> bool {
        !scan_bytes(std::slice::from_ref(rule), data).is_empty()
    }

    #[test]
    fn text_strings_with_modifiers() {
        let r = one(
            "rule t { strings: $a = \"Hello\" nocase $b = \"wide\" wide condition: $a and $b }",
        );
        assert!(hit(&r, b"say HELLO there w\0i\0d\0e\0"));
        assert!(!hit(&r, b"say HELLO there wide"));
        let f = one("rule t { strings: $a = \"cat\" fullword condition: $a }");
        assert!(hit(&f, b"a cat sat") && !hit(&f, b"concatenate") && !hit(&f, b"cats"));
    }

    #[test]
    fn hex_strings_with_wildcards() {
        let r = one("rule t { strings: $h = { 4D 5A ?? 00 50 } condition: $h }");
        assert!(hit(&r, &[1, 0x4d, 0x5a, 0x99, 0, 0x50, 7]));
        assert!(!hit(&r, &[0x4d, 0x5a, 0x99, 1, 0x50]));
    }

    #[test]
    fn regex_strings_nocase() {
        let r = one("rule t { strings: $r = /pass(word|wd)=[a-z0-9]{4,}/i condition: $r }");
        assert!(hit(&r, b"login PASSWD=hunter2 ok") && !hit(&r, b"password=ab"));
    }

    #[test]
    fn counts_filesize_and_uint() {
        let r = one("rule t { strings: $a = \"x\" condition: #a >= 3 and filesize < 1KB and uint16(0) == 0x5A4D }");
        assert!(hit(&r, b"MZ x x x"));
        assert!(!hit(&r, b"MZ x x"));
        assert!(!hit(&r, b"ZM x x x"));
        let big = one("rule t { condition: filesize > 1MB or uint32be(0) == 0x4d5a0000 }");
        assert!(hit(&big, &[0x4d, 0x5a, 0, 0]) && !hit(&big, &[1, 2, 3, 4]));
        let off = one("rule t { condition: uint8(100) == 1 }");
        assert!(!hit(&off, b"short"));
    }

    #[test]
    fn quantifiers_and_globs() {
        let r = one("rule t { strings: $api1 = \"VirtualAlloc\" $api2 = \"WriteProcessMemory\" $api3 = \"CreateRemoteThread\" $other = \"zzz\" condition: 2 of ($api*) and not $other }");
        assert!(hit(&r, b"VirtualAlloc WriteProcessMemory"));
        assert!(!hit(&r, b"VirtualAlloc only"));
        assert!(!hit(&r, b"VirtualAlloc WriteProcessMemory zzz"));
        let all = one("rule t { strings: $a = \"a1\" $b = \"b1\" condition: all of them }");
        assert!(hit(&all, b"a1 b1") && !hit(&all, b"a1"));
        let any = one("rule t { strings: $a = \"a1\" $b = \"b1\" condition: any of ($a, $b) }");
        assert!(hit(&any, b"b1") && !hit(&any, b"c1"));
    }

    #[test]
    fn meta_tags_comments_and_multiple_rules() {
        let rules = parse_rules("// leading\nrule one : tag1 tag2 { meta: description = \"d\" mitre_attack = \"T1059.001, T1204\" n = 5 /* c */ strings: $a = \"a\" condition: $a }\nrule two { condition: true }").unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].tags, vec!["tag1", "tag2"]);
        assert_eq!(rules[0].description(), "d");
        assert_eq!(rules[0].techniques(), vec!["T1059.001", "T1204"]);
    }

    #[test]
    fn unsupported_and_broken_rules_are_rejected_with_a_reason() {
        let bad = [
            ("import \"pe\"\nrule t { condition: true }", "import"),
            ("private rule t { condition: true }", "private"),
            ("rule t { strings: $a = \"x\" xor condition: $a }", "xor"),
            (
                "rule t { strings: $a = { 4D [2-4] 5A } condition: $a }",
                "jumps",
            ),
            (
                "rule t { strings: $a = { 4D ( 5A | 5B ) } condition: $a }",
                "alternations",
            ),
            ("rule t { strings: $a = { 4? 5A } condition: $a }", "nibble"),
            ("rule t { strings: $a = \"x\" condition: $a at 0 }", "at"),
            (
                "rule t { strings: $a = \"x\" condition: $missing }",
                "undefined",
            ),
            (
                "rule t { strings: $a = \"x\" condition: 2 of ($zzz*) }",
                "names no defined",
            ),
            (
                "rule t { strings: $a = \"x\" $a = \"y\" condition: $a }",
                "twice",
            ),
            ("rule t { strings: $a = \"x\" }", "condition"),
            (
                "rule t { strings: $a = /(/ condition: $a }",
                "regular expression",
            ),
            (
                "rule t { strings: $a = \"x\" condition: $a and }",
                "unexpected",
            ),
            ("rule t { condition: for any i in (1..3) : (true) }", "for"),
            (
                "rule t { strings: $a = \"unterminated condition: $a }",
                "string",
            ),
            (
                "rule t { strings: $a = { 4D 5 } condition: $a }",
                "odd number",
            ),
        ];
        for (src, why) in bad {
            let e = parse_rules(src)
                .err()
                .unwrap_or_else(|| panic!("should be rejected: {src}"));
            assert!(
                e.to_lowercase().contains(why),
                "error for {src:?} was {e:?}, expected to mention {why:?}"
            );
        }
    }

    #[test]
    fn occurrence_counts_are_capped_and_scanning_is_fast_on_degenerate_input() {
        let r = one("rule t { strings: $a = \"aa\" condition: #a > 10 }");
        let data = vec![b'a'; 2_000_000];
        let started = std::time::Instant::now();
        assert!(hit(&r, &data));
        assert!(started.elapsed().as_secs() < 5);
    }
}
