use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn init_prints_a_registration_bundle_and_locks_the_key() {
    let root = std::env::temp_dir().join(format!(
        "cerveau-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let config = root.join("config");
    let data = root.join("data");
    let bin = env!("CARGO_BIN_EXE_cerveau");
    let out = Command::new(bin)
        .args([
            "init",
            "--tenant",
            "tenant-cli",
            "--principal-id",
            "p_cli",
            "--display-name",
            "Cli Owner",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("gb.register.v1"));
    assert!(stdout.contains("tenant-cli"));
    assert!(!stdout.contains("principal_id"));
    assert!(!stdout.contains("p_cli"));
    assert!(!stdout.contains("Cli Owner"));
    assert!(stdout.contains("gb:tenant-cli:agent-cli"));
    assert!(!stdout.contains("ed25519_seed"));

    let key_path = data
        .join("tenants")
        .join("tenant-cli")
        .join("agents")
        .join("agent-cli")
        .join("key.json");
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let install = config
        .join("tenants")
        .join("tenant-cli")
        .join("install.json");
    let install_mode = std::fs::metadata(&install).unwrap().permissions().mode() & 0o777;
    assert_eq!(install_mode, 0o600);
    let file = std::fs::read_to_string(&key_path).unwrap();
    let seed = seed_field(&file);
    assert!(!stdout.contains(seed), "stdout leaked the seed");

    let again = Command::new(bin)
        .args([
            "register",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let pub_out = String::from_utf8(again.stdout).unwrap();
    assert!(pub_out.contains("gb.register.v1"));
    assert!(!pub_out.contains(seed), "register leaked the seed");
    let _ = std::fs::remove_dir_all(&root);
}

fn seed_field(file: &str) -> &str {
    let key = "\"ed25519_seed\": \"";
    let start = file.find(key).expect("seed field") + key.len();
    let rest = &file[start..];
    let end = rest.find('"').expect("seed end");
    &rest[..end]
}

#[test]
fn account_key_prints_the_public_bundle_and_locks_the_seed() {
    let root = std::env::temp_dir().join(format!(
        "cerveau-cli-account-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    let bin = env!("CARGO_BIN_EXE_cerveau");
    let args = [
        "account-key",
        "--tenant",
        "tenant-cli",
        "--principal",
        "u_cli",
        "--data-dir",
        data.to_str().unwrap(),
    ];
    let out = Command::new(bin).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("gb.account_pub.v1"));
    assert!(stdout.contains("u_cli"));
    assert!(stdout.contains("compte-tenant-cli-u_cli-"));
    assert!(!stdout.contains("ed25519_seed"));

    let key_path = data
        .join("tenants")
        .join("tenant-cli")
        .join("accounts")
        .join("u_cli.json");
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let file = std::fs::read_to_string(&key_path).unwrap();
    let seed = seed_field(&file);
    assert!(!stdout.contains(seed), "stdout leaked the seed");

    let again = Command::new(bin).args(args).output().unwrap();
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let reprinted = String::from_utf8(again.stdout).unwrap();
    assert_eq!(reprinted, stdout);
    assert!(!reprinted.contains(seed), "reprint leaked the seed");
    let _ = std::fs::remove_dir_all(&root);
}
