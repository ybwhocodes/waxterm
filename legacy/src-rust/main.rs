use std::env;
use std::process::Command;
use std::time::SystemTime;

// ponytail: pakai stdlib tanpa serde_json; ganti serde + russh saat butuh koneksi SSH socket langsung & custom cipher.

/// Escapes a string for inclusion in a JSON string literal according to RFC 8259.
/// All control characters (< 0x20) are escaped with standard shortcuts or \u00xx.
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Builds JSON response string containing exit_code, stdout, and stderr.
pub fn build_json_response(exit_code: i32, stdout: &str, stderr: &str) -> String {
    format!(
        r#"{{"exit_code":{},"stdout":"{}","stderr":"{}"}}"#,
        exit_code,
        escape_json(stdout),
        escape_json(stderr)
    )
}

/// Validates target host to prevent SSH option injection.
pub fn validate_host(host: &str) -> Result<(), &'static str> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("Host target tidak boleh kosong.");
    }
    if trimmed.starts_with('-') {
        return Err("Host target tidak valid: tidak boleh diawali dengan tanda '-' (mencegah SSH option injection).");
    }
    if trimmed.contains('\0') {
        return Err("Host target mengandung null byte.");
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: waxterm-core <host> <command> [port] [key_path]");
        println!("{}", build_json_response(1, "", "Usage: waxterm-core <host> <command> [port] [key_path]"));
        std::process::exit(1);
    }

    let host = &args[1];
    let cmd = &args[2];

    if let Err(err_msg) = validate_host(host) {
        eprintln!("Error: {}", err_msg);
        println!("{}", build_json_response(1, "", err_msg));
        std::process::exit(1);
    }

    if cmd.trim().is_empty() {
        let err_msg = "Command tidak boleh kosong.";
        eprintln!("Error: {}", err_msg);
        println!("{}", build_json_response(1, "", err_msg));
        std::process::exit(1);
    }

    let ssh_bin = env::var("WAXTERM_SSH_BIN").unwrap_or_else(|_| "ssh".to_string());
    let ssh_timeout = env::var("WAXTERM_SSH_TIMEOUT").unwrap_or_else(|_| "10".to_string());

    // Optional port & key path
    let port_arg = args.get(3).filter(|s| !s.is_empty());
    let key_arg = args.get(4).filter(|s| !s.is_empty());

    let mut command = Command::new(&ssh_bin);

    // Filter informational OpenSSH warnings & set timeout
    command
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg(format!("ConnectTimeout={}", ssh_timeout));

    // Handle optional SSH Password Authentication via SSH_ASKPASS
    let password = env::var("WAXTERM_SSH_PASSWORD").ok().filter(|s| !s.is_empty());
    let mut askpass_path: Option<std::path::PathBuf> = None;

    if let Some(ref pass) = password {
        let temp_dir = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let file_name = format!("waxterm_ap_{}_{}.sh", std::process::id(), nanos);
        let file_path = temp_dir.join(file_name);

        let escaped_pass = pass.replace('\'', "'\\''");
        let script = format!("#!/bin/sh\nprintf '%s' '{}'\n", escaped_pass);

        if std::fs::write(&file_path, script).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o700));
            }

            command.env("SSH_ASKPASS", &file_path);
            command.env("SSH_ASKPASS_REQUIRE", "force");
            command.env("DISPLAY", ":0");
            command.arg("-o").arg("BatchMode=no");
            command.arg("-o").arg("NumberOfPasswordPrompts=1");
            command.arg("-o").arg("PreferredAuthentications=password,keyboard-interactive,publickey");
            askpass_path = Some(file_path);
        } else {
            command.arg("-o").arg("BatchMode=yes");
        }
    } else {
        command.arg("-o").arg("BatchMode=yes");
    }

    if let Some(port) = port_arg {
        if let Ok(p) = port.parse::<u16>() {
            if p > 0 {
                command.arg("-p").arg(p.to_string());
            }
        }
    } else if let Ok(p) = env::var("WAXTERM_SSH_PORT") {
        if let Ok(p_num) = p.parse::<u16>() {
            if p_num > 0 {
                command.arg("-p").arg(p_num.to_string());
            }
        }
    }

    if let Some(key) = key_arg {
        let trimmed_key = key.trim();
        if !trimmed_key.is_empty() && !trimmed_key.starts_with('-') {
            command.arg("-i").arg(trimmed_key);
        }
    } else if let Ok(key) = env::var("WAXTERM_SSH_KEY") {
        let trimmed_key = key.trim();
        if !trimmed_key.is_empty() && !trimmed_key.starts_with('-') {
            command.arg("-i").arg(trimmed_key);
        }
    }

    command
        .arg("--")
        .arg(host)
        .arg(cmd);

    let output = command.output();

    // Clean up temporary askpass script
    if let Some(ref p) = askpass_path {
        let _ = std::fs::remove_file(p);
    }

    match output {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let stderr_str = String::from_utf8_lossy(&out.stderr);

            println!("{}", build_json_response(code, &stdout_str, &stderr_str));
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            println!("{}", build_json_response(-1, "", &err_msg));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_json_standard() {
        assert_eq!(escape_json("hello world"), "hello world");
        assert_eq!(escape_json("quote \" and slash \\"), "quote \\\" and slash \\\\");
        assert_eq!(escape_json("line1\nline2\r\ttab"), "line1\\nline2\\r\\ttab");
        assert_eq!(escape_json("backspace\x08formfeed\x0c"), "backspace\\bformfeed\\f");
    }

    #[test]
    fn test_escape_json_ansi_and_control_chars() {
        // ANSI escape code: \x1b[32mSuccess\x1b[0m
        let ansi = "\x1b[32mSuccess\x1b[0m";
        let escaped = escape_json(ansi);
        assert_eq!(escaped, "\\u001b[32mSuccess\\u001b[0m");

        // Null byte
        let with_null = "zero\x00byte";
        assert_eq!(escape_json(with_null), "zero\\u0000byte");
    }

    #[test]
    fn test_escape_json_unicode() {
        let text = "Halo dunia! 🚀 Selamat pagi — üñîçødë";
        assert_eq!(escape_json(text), text);
    }

    #[test]
    fn test_build_json_response() {
        let json = build_json_response(0, "output 1\n", "no errors");
        assert_eq!(json, r#"{"exit_code":0,"stdout":"output 1\n","stderr":"no errors"}"#);

        let json_err = build_json_response(127, "", "command not found: foo\n");
        assert_eq!(json_err, r#"{"exit_code":127,"stdout":"","stderr":"command not found: foo\n"}"#);
    }

    #[test]
    fn test_validate_host() {
        // Positive cases
        assert!(validate_host("user@192.168.1.1").is_ok());
        assert!(validate_host("localhost").is_ok());
        assert!(validate_host("root@vps.example.com").is_ok());

        // Negative cases
        assert!(validate_host("").is_err());
        assert!(validate_host("   ").is_err());
        assert!(validate_host("-oProxyCommand=calc.exe").is_err());
        assert!(validate_host("--option").is_err());
        assert!(validate_host("host\0name").is_err());
    }
}
