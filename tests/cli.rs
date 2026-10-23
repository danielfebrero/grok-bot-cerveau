use std::io::Write;
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
            "--user-id",
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
    assert!(!stdout.contains("user_id"));
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

#[test]
fn messages_accepts_inline_json_and_a_file_path() {
    let root = std::env::temp_dir().join(format!(
        "cerveau-cli-messages-{}-{}",
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
    let init = Command::new(bin)
        .args([
            "init",
            "--tenant",
            "tenant-cli",
            "--user-id",
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
    assert!(init.status.success(), "{}", text(&init));
    let pin = Command::new(bin)
        .args([
            "pin",
            "--tenant",
            "tenant-cli",
            "--recipient-key-id",
            "cerveau-test",
            "--recipient-public-key",
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(pin.status.success(), "{}", text(&pin));

    let inline = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            r#"[{"role":"agent","text":"inline"}]"#,
        ])
        .output()
        .unwrap();
    let inline_err = String::from_utf8_lossy(&inline.stderr);
    assert!(
        !inline.status.success() && inline_err.contains("missing an explicit from"),
        "{}",
        text(&inline)
    );
    assert!(!inline_err.contains("No such file"), "{}", text(&inline));

    let file = root.join("messages.json");
    std::fs::write(&file, r#"[{"role":"tool","from":"shell"}]"#).unwrap();
    let from_file = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let file_err = String::from_utf8_lossy(&from_file.stderr);
    assert!(
        !from_file.status.success() && file_err.contains("message text is missing"),
        "{}",
        text(&from_file)
    );

    let missing = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            root.join("no-such-messages.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let missing_err = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing_err.contains("No such file") || missing_err.contains("os error 2"),
        "{}",
        text(&missing)
    );

    let inline_ok = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--endpoint",
            "http://127.0.0.1:1",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            r#"[{"role":"agent","from":"gb:other","text":"inline-ok"}]"#,
        ])
        .output()
        .unwrap();
    assert!(inline_ok.status.success(), "{}", text(&inline_ok));
    let inline_out = String::from_utf8_lossy(&inline_ok.stdout);
    assert!(inline_out.contains("no_envelope"), "{}", text(&inline_ok));
    assert!(
        !String::from_utf8_lossy(&inline_ok.stderr).contains("No such file"),
        "{}",
        text(&inline_ok)
    );

    let ok_file = root.join("ok.json");
    std::fs::write(
        &ok_file,
        r#"[{"role":"tool","from":"shell","text":"file-ok"}]"#,
    )
    .unwrap();
    let file_ok = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--endpoint",
            "http://127.0.0.1:1",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            ok_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(file_ok.status.success(), "{}", text(&file_ok));
    assert!(
        String::from_utf8_lossy(&file_ok.stdout).contains("no_envelope"),
        "{}",
        text(&file_ok)
    );

    let mut child = Command::new(bin)
        .args([
            "run",
            "--tenant",
            "tenant-cli",
            "--agent",
            "agent-cli",
            "--config-dir",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--messages",
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"[{"role":"inbound","text":"stdin"}]"#)
        .unwrap();
    drop(child.stdin.take());
    let stdin_out = child.wait_with_output().unwrap();
    let stdin_err = String::from_utf8_lossy(&stdin_out.stderr);
    assert!(
        !stdin_out.status.success() && stdin_err.contains("missing an explicit from"),
        "status={}\nstdout={}\nstderr={stdin_err}",
        stdin_out.status,
        String::from_utf8_lossy(&stdin_out.stdout)
    );

    let _ = std::fs::remove_dir_all(&root);
}

fn text(out: &std::process::Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
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
        "--user",
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
