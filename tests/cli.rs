use std::process::Command;

fn banshee(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_banshee"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn bundled_rules_find_exactly_the_four_planted_events() {
    let (code, stdout, _) = banshee(&[
        "sigma",
        "--rules",
        "rules/sigma",
        "--events",
        "examples/events.jsonl",
        "--json",
    ]);
    assert_eq!(code, 1, "matches found must exit 1");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["rules_loaded"], 4);
    assert_eq!(v["rules_skipped"].as_array().unwrap().len(), 0);
    let mut hits: Vec<(u64, String)> = v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["event_index"].as_u64().unwrap(),
                m["id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    hits.sort();
    let want: Vec<(u64, String)> = vec![
        (0, "banshee-0001"),
        (2, "banshee-0002"),
        (4, "banshee-0003"),
        (6, "banshee-0004"),
    ]
    .into_iter()
    .map(|(i, s)| (i, s.to_string()))
    .collect();
    assert_eq!(
        hits, want,
        "benign events (cmd dir, plain curl, sshd, dpkg) must stay quiet"
    );
    assert!(v["techniques"]["T1059.001"] == 1 && v["techniques"]["T1098.004"] == 1);
}

#[test]
fn min_level_filters_and_clean_input_exits_zero() {
    let (_, stdout, _) = banshee(&[
        "sigma",
        "--rules",
        "rules/sigma",
        "--events",
        "examples/events.jsonl",
        "--json",
        "--min-level",
        "high",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["matches"].as_array().unwrap().len(), 2);
    let dir = std::env::temp_dir().join(format!("banshee-clean-{}.jsonl", std::process::id()));
    std::fs::write(&dir, "{\"Image\": \"/bin/ls\"}\n").unwrap();
    let (code, ..) = banshee(&[
        "sigma",
        "--rules",
        "rules/sigma",
        "--events",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    std::fs::remove_file(dir).ok();
}

#[test]
fn bad_usage_and_missing_files_exit_two_with_a_message() {
    let (code, _, err) = banshee(&[]);
    assert_eq!(code, 2);
    assert!(err.contains("usage"));
    let (code, _, err) = banshee(&[
        "sigma",
        "--rules",
        "rules/sigma",
        "--events",
        "no-such-file.jsonl",
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot read"));
}

#[test]
fn a_broken_rule_is_reported_not_swallowed() {
    let dir = std::env::temp_dir().join(format!("banshee-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("bad.yml"),
        "title: t\ndetection:\n  s:\n    a|base64: x\n  condition: s\n",
    )
    .unwrap();
    let (_, stdout, _) = banshee(&[
        "sigma",
        "--rules",
        dir.to_str().unwrap(),
        "--events",
        "examples/events.jsonl",
        "--json",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["rules_loaded"], 0);
    assert!(v["rules_skipped"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("base64"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn yara_finds_exactly_the_planted_samples() {
    let (code, stdout, _) = banshee(&[
        "yara",
        "--rules",
        "rules/yara",
        "examples/samples",
        "--json",
    ]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["rules_loaded"], 4);
    assert_eq!(v["skipped"].as_array().unwrap().len(), 0);
    assert_eq!(v["files_scanned"], 5);
    let mut hits: Vec<(String, String)> = v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let f = m["file"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string();
            (f, m["rule"].as_str().unwrap().to_string())
        })
        .collect();
    hits.sort();
    assert_eq!(
        hits,
        vec![
            (
                "dropper.sh".to_string(),
                "banshee_shell_dropper_script".to_string()
            ),
            (
                "fake_pe.bin".to_string(),
                "banshee_pe_with_injection_apis".to_string()
            ),
            ("note.txt".to_string(), "banshee_test_marker".to_string()),
            (
                "tiny.elf".to_string(),
                "banshee_elf_header_stub".to_string()
            ),
        ]
    );
    assert_eq!(v["techniques"]["T1055"], 1);
}

#[test]
fn yara_reports_unsupported_rule_files_and_exits_zero_when_clean() {
    let dir = std::env::temp_dir().join(format!("banshee-yara-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("bad.yar"),
        "import \"pe\"\nrule x { condition: true }",
    )
    .unwrap();
    std::fs::write(
        dir.join("ok.yar"),
        "rule nope { strings: $a = \"zzzzqq\" condition: $a }",
    )
    .unwrap();
    let (code, stdout, _) = banshee(&[
        "yara",
        "--rules",
        dir.to_str().unwrap(),
        "examples/samples/clean.txt",
    ]);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(code, 0);
    assert!(
        stdout.contains("skipped") && stdout.contains("import"),
        "{stdout}"
    );
}
