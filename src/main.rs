use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use banshee::{attack, sigma, yara};

const USAGE: &str = "usage:\n  banshee sigma --rules DIR --events FILE [--min-level LEVEL] [--json]\n  banshee yara  --rules DIR PATH [--json]";

fn excerpt(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 160 {
        let cut: String = s.chars().take(160).collect();
        format!("{cut}...")
    } else {
        s
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("sigma") => run_sigma(args),
        Some("yara") => run_yara(args),
        _ => Err(USAGE.into()),
    }
}

fn run_yara(args: &[String]) -> Result<ExitCode, String> {
    let mut rules_dir = None;
    let mut target = None;
    let mut as_json = false;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rules" => rules_dir = it.next().cloned(),
            "--json" => as_json = true,
            other if !other.starts_with("--") && target.is_none() => {
                target = Some(other.to_string())
            }
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let (Some(rules_dir), Some(target)) = (rules_dir, target) else {
        return Err(USAGE.into());
    };
    let (rules, mut skipped) = yara::load_dir(Path::new(&rules_dir));
    let files = yara::walk(Path::new(&target), &[], &mut skipped);
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        if size > yara::MAX_FILE_SIZE {
            skipped.push((
                f.display().to_string(),
                format!("larger than {} bytes, not scanned", yara::MAX_FILE_SIZE),
            ));
            continue;
        }
        match std::fs::read(f) {
            Ok(data) => {
                scanned += 1;
                for m in yara::scan_bytes(&rules, &data) {
                    hits.push((
                        f.display().to_string(),
                        m.rule.name.clone(),
                        m.rule.description().to_string(),
                        m.rule.techniques(),
                        m.strings,
                    ));
                }
            }
            Err(e) => skipped.push((f.display().to_string(), e.to_string())),
        }
    }
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for h in &hits {
        for t in &h.3 {
            *tally.entry(t.clone()).or_default() += 1;
        }
    }
    if as_json {
        let out = serde_json::json!({
            "rules_loaded": rules.len(),
            "files_scanned": scanned,
            "skipped": skipped.iter().map(|(f, r)| serde_json::json!({"file": f, "reason": r})).collect::<Vec<_>>(),
            "matches": hits.iter().map(|h| serde_json::json!({
                "file": h.0, "rule": h.1, "description": h.2, "techniques": h.3,
                "strings": h.4.iter().map(|(n, o)| serde_json::json!({"name": n, "count": o.count, "first_offset": o.first})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "techniques": tally,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "rules {} · files scanned {} (skipped {}) · matches {}",
            rules.len(),
            scanned,
            skipped.len(),
            hits.len()
        );
        for (file, reason) in &skipped {
            println!("  skipped {file}: {reason}");
        }
        for h in &hits {
            println!("{}  {}  {}", h.1, h.0, h.2);
            for (n, o) in &h.4 {
                println!(
                    "    ${n} ×{} (first at 0x{:x})",
                    o.count,
                    o.first.unwrap_or(0)
                );
            }
        }
        if !tally.is_empty() {
            let list: Vec<String> = tally.iter().map(|(t, n)| format!("{t} ×{n}")).collect();
            println!(
                "ATT&CK techniques (as tagged by rule authors): {}",
                list.join(", ")
            );
        }
    }
    Ok(if hits.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn run_sigma(args: &[String]) -> Result<ExitCode, String> {
    let mut rules_dir = None;
    let mut events_file = None;
    let mut min = sigma::Level::Informational;
    let mut as_json = false;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rules" => rules_dir = it.next().cloned(),
            "--events" => events_file = it.next().cloned(),
            "--min-level" => {
                let v = it.next().ok_or("--min-level needs a value")?;
                min = sigma::Level::parse(v).ok_or(format!("unknown level {v:?}"))?;
            }
            "--json" => as_json = true,
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let (rules_dir, events_file) = match (rules_dir, events_file) {
        (Some(r), Some(e)) => (r, e),
        _ => return Err(USAGE.into()),
    };
    let (rules, skipped) = sigma::load_dir(Path::new(&rules_dir));
    let text = std::fs::read_to_string(&events_file)
        .map_err(|e| format!("cannot read {events_file}: {e}"))?;
    let (events, bad_lines) = sigma::parse_events(&text);
    let matches: Vec<_> = sigma::run(&rules, &events)
        .into_iter()
        .filter(|m| m.rule.level >= min)
        .collect();
    let tag_lists: Vec<attack::Tags> = matches
        .iter()
        .map(|m| attack::parse_tags(&m.rule.tags))
        .collect();
    let (techniques, tactics) = attack::tally(tag_lists.iter());

    if as_json {
        let out = serde_json::json!({
            "rules_loaded": rules.len(),
            "rules_skipped": skipped.iter().map(|(f, r)| serde_json::json!({"file": f, "reason": r})).collect::<Vec<_>>(),
            "events": events.len(),
            "unparsable_event_lines": bad_lines,
            "matches": matches.iter().map(|m| serde_json::json!({
                "rule": m.rule.title, "id": m.rule.id, "level": m.rule.level.as_str(), "tags": m.rule.tags,
                "event_index": m.event_index, "event": events[m.event_index],
            })).collect::<Vec<_>>(),
            "techniques": techniques, "tactics": tactics,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "rules {} (skipped {}) · events {} · matches {}",
            rules.len(),
            skipped.len(),
            events.len(),
            matches.len()
        );
        for (file, reason) in &skipped {
            println!("  skipped {file}: {reason}");
        }
        if !bad_lines.is_empty() {
            println!(
                "  {} event line(s) were not JSON objects (first: line {})",
                bad_lines.len(),
                bad_lines[0]
            );
        }
        for m in &matches {
            println!(
                "[{:<13}] {}  (event #{})\n    {}",
                m.rule.level.as_str(),
                m.rule.title,
                m.event_index + 1,
                excerpt(&events[m.event_index])
            );
        }
        let by_tech: BTreeMap<_, _> = techniques.iter().collect();
        if !by_tech.is_empty() {
            let list: Vec<String> = by_tech.iter().map(|(t, n)| format!("{t} ×{n}")).collect();
            println!(
                "ATT&CK techniques (as tagged by rule authors): {}",
                list.join(", ")
            );
        }
    }
    Ok(if matches.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
