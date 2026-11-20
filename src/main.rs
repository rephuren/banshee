use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use banshee::{attack, sigma};

const USAGE: &str = "usage: banshee sigma --rules DIR --events FILE [--min-level LEVEL] [--json]";

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
    if args.first().map(String::as_str) != Some("sigma") {
        return Err(USAGE.into());
    }
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
