use std::collections::HashSet;
use std::env;
use std::path::Path;
use std::process::{self, Command};

#[derive(Debug)]
enum BlacklistError {
    BlockedDependency(String),
}

#[derive(Debug, Clone)]
struct BlacklistPolicy {
    blocked_env_values: Vec<(&'static str, &'static str)>,
    blocked_binaries: Vec<&'static str>,
    blocked_paths: Vec<&'static str>,
    blocked_features: Vec<&'static str>,
}

fn blacklist_dependencies_and_stop_web_app(
    policy: &BlacklistPolicy,
) -> Result<(), BlacklistError> {
    // Block startup IF and only IF an environment variable matches a blacklisted value.
    for (key, blocked_value) in &policy.blocked_env_values {
        if let Ok(actual) = env::var(key) {
            if actual.eq_ignore_ascii_case(blocked_value) {
                return Err(BlacklistError::BlockedDependency(format!(
                    "Environment variable {} is blacklisted ({})",
                    key, blocked_value
                )));
            }
        }
    }

    // Block startup IF and only IF a blacklisted binary exists in PATH.
    for binary in &policy.blocked_binaries {
        if binary_exists(binary) {
            return Err(BlacklistError::BlockedDependency(format!(
                "Blacklisted binary detected: {}",
                binary
            )));
        }
    }

    // Block startup IF and only IF a blacklisted path exists.
    for path in &policy.blocked_paths {
        if Path::new(path).exists() {
            return Err(BlacklistError::BlockedDependency(format!(
                "Blacklisted path detected: {}",
                path
            )));
        }
    }

    // Block startup IF and only IF a feature flag is explicitly enabled.
    let enabled_features = collect_enabled_features();
    for feature in &policy.blocked_features {
        if enabled_features.contains(&feature.to_lowercase()) {
            return Err(BlacklistError::BlockedDependency(format!(
                "Blacklisted feature enabled: {}",
                feature
            )));
        }
    }

    Ok(())
}

fn binary_exists(name: &str) -> bool {
    let checker = if cfg!(target_os = "windows") { "where" } else { "which" };

    Command::new(checker)
        .arg(name)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn collect_enabled_features() -> HashSet<String> {
    let raw = env::var("APP_FEATURES").unwrap_or_default();

    raw.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn start_web_app() {
    println!("Starting web application...");
    // Put your real startup logic here.
    // Example:
    // Command::new("./my_web_app").spawn().expect("failed to start app");
}

fn main() {
    let policy = BlacklistPolicy {
        blocked_env_values: vec![
            ("APP_MODE", "debug"),
            ("ALLOW_UNSAFE_PLUGINS", "true"),
        ],
        blocked_binaries: vec![
            "phantomjs",
            "chromedriver",
        ],
        blocked_paths: vec![
            "./legacy_plugins",
            "./tmp/unsafe_module",
        ],
        blocked_features: vec![
            "remote_eval",
            "legacy_shell",
        ],
    };

    match blacklist_dependencies_and_stop_web_app(&policy) {
        Ok(()) => {
            println!("Blacklist clean.");
            start_web_app();
        }
        Err(BlacklistError::BlockedDependency(reason)) => {
            eprintln!("Startup blocked: {}", reason);
            process::exit(1);
        }
    }
}