use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn keygen_prints_only_the_public_export() {
    let dir = std::env::temp_dir().join(format!(
        "cerveau-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let bin = env!("CARGO_BIN_EXE_cerveau");
    let out = Command::new(bin)
        .args([
            "keygen",
            "--agent",
            "agent-cli",
            "--dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("gb.agent_pub.v1"));
    assert!(stdout.contains("gb-agent-cli-"));
    assert!(!stdout.contains("ed25519_seed"));

    let key_path = dir.join("agents").join("agent-cli").join("key.json");
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let file = std::fs::read_to_string(&key_path).unwrap();
    let seed = seed_field(&file);
    assert!(!stdout.contains(seed), "stdout leaked the seed");

    let again = Command::new(bin)
        .args([
            "pubkey",
            "--agent",
            "agent-cli",
            "--dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(again.status.success());
    let pub_out = String::from_utf8(again.stdout).unwrap();
    assert!(pub_out.contains("gb.agent_pub.v1"));
    assert!(!pub_out.contains(seed), "pubkey leaked the seed");
    let _ = std::fs::remove_dir_all(&dir);
}

fn seed_field(file: &str) -> &str {
    let key = "\"ed25519_seed\": \"";
    let start = file.find(key).expect("seed field") + key.len();
    let rest = &file[start..];
    let end = rest.find('"').expect("seed end");
    &rest[..end]
}
