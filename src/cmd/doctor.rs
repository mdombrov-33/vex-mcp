use std::path::Path;

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let config_flag = flag_value(args, "--config");
    let (config_path, config_source) = if let Some(p) = config_flag {
        (p, "--config flag")
    } else if let Ok(p) = std::env::var("VEX_CONFIG") {
        (p, "VEX_CONFIG")
    } else {
        ("vex.toml".to_owned(), "default")
    };

    let mut errors: usize = 0;

    println!(
        "{} {} · {}/{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    println!();
    println!("config");

    let contents = match std::fs::read_to_string(&config_path) {
        Ok(c) => {
            println!("  \u{2713} {config_path}  ({config_source})");
            Some(c)
        }
        Err(e) => {
            println!("  \u{2717} {config_path}: {e}  ({config_source})");
            println!("     \u{2192} run `vex-mcp init` to generate a starter config");
            errors += 1;
            None
        }
    };

    let raw_cfg: Option<crate::config::RawConfig> = if let Some(ref c) = contents {
        match toml::from_str(c) {
            Ok(r) => {
                println!("  \u{2713} TOML valid");
                Some(r)
            }
            Err(e) => {
                println!("  \u{2717} TOML parse error: {e}");
                errors += 1;
                None
            }
        }
    } else {
        None
    };

    let paths: Option<(String, String)> = if let Some(raw) = raw_cfg {
        let audit = raw
            .audit
            .and_then(|a| a.path)
            .unwrap_or_else(|| "vex-audit.log".to_owned());
        let pins = raw
            .server
            .pin_store
            .unwrap_or_else(|| "pins.json".to_owned());
        match crate::policy::Policy::try_from(raw.policy) {
            Ok(p) => {
                let default = match p.default_action {
                    crate::policy::DefaultAction::Allow => "allow",
                    crate::policy::DefaultAction::Deny => "deny",
                };
                println!(
                    "  \u{2713} policy: default_action = {default}, {} allowed, {} blocked",
                    p.allowed_tools.len(),
                    p.blocked_tools.len(),
                );
                Some((audit, pins))
            }
            Err(e) => {
                println!("  \u{2717} policy error: {e}");
                errors += 1;
                None
            }
        }
    } else {
        None
    };

    println!();
    println!("paths");
    if let Some((audit, pins)) = paths {
        check_parent_dir(&audit, "audit log", &mut errors);
        check_parent_dir(&pins, "pin store", &mut errors);
    } else {
        println!("  (skipped \u{2014} fix config errors above)");
    }

    println!();
    if errors == 0 {
        println!("all checks passed");
        Ok(())
    } else {
        anyhow::bail!("{errors} check(s) failed");
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

fn check_parent_dir(path: &str, label: &str, errors: &mut usize) {
    let dir = Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if dir.is_dir() {
        println!("  \u{2713} {label}: {path}");
    } else {
        println!(
            "  \u{2717} {label}: directory `{}` does not exist",
            dir.display()
        );
        *errors += 1;
    }
}
