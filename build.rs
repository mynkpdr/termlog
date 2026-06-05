use clap::CommandFactory;
use clap::ValueEnum;
use std::collections::HashMap;
use std::env;
use std::fs::{create_dir_all, read_to_string, write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

mod cli {
    include!("src/cli.rs");
}

const ENV_KEY: &str = "ASCIINEMA_GEN_DIR";
const GOOGLE_CLIENT_ID_ENV: &str = "TERMLOG_GOOGLE_CLIENT_ID";
const GOOGLE_CLIENT_SECRET_ENV: &str = "TERMLOG_GOOGLE_CLIENT_SECRET";
const RECEIPT_SECRET_ENV: &str = "TERMLOG_RECEIPT_SECRET";

fn main() -> std::io::Result<()> {
    write_embedded_google_oauth()?;

    if let Some(dir) = env::var_os(ENV_KEY).or(env::var_os("OUT_DIR")) {
        let mut cmd = cli::Cli::command();
        let base_dir = PathBuf::from(dir);

        let man_dir = Path::join(&base_dir, "man");
        create_dir_all(&man_dir)?;
        clap_mangen::generate_to(cmd.clone(), &man_dir)?;

        let completion_dir = Path::join(&base_dir, "completion");
        create_dir_all(&completion_dir)?;

        for shell in clap_complete::Shell::value_variants() {
            clap_complete::generate_to(*shell, &mut cmd, "termlog", &completion_dir)?;
        }
    }

    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit());
    println!("cargo:rerun-if-env-changed={ENV_KEY}");
    println!("cargo:rerun-if-env-changed={GOOGLE_CLIENT_ID_ENV}");
    println!("cargo:rerun-if-env-changed={GOOGLE_CLIENT_SECRET_ENV}");
    println!("cargo:rerun-if-env-changed={RECEIPT_SECRET_ENV}");
    println!("cargo:rerun-if-changed=.env");
    println!("cargo:rerun-if-changed=.git/HEAD");

    Ok(())
}

fn write_embedded_google_oauth() -> std::io::Result<()> {
    let dotenv = load_dotenv();
    let client_id = required_build_var(GOOGLE_CLIENT_ID_ENV, &dotenv);
    let client_secret = required_build_var(GOOGLE_CLIENT_SECRET_ENV, &dotenv);
    let receipt_secret = required_build_var(RECEIPT_SECRET_ENV, &dotenv);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let output = format!(
        "pub const EMBEDDED_GOOGLE_CLIENT_ID: &str = {client_id:?};\n\
         pub const EMBEDDED_GOOGLE_CLIENT_SECRET: &str = {client_secret:?};\n\
         pub const EMBEDDED_RECEIPT_SECRET: &str = {receipt_secret:?};\n"
    );

    write(out_dir.join("google_oauth.rs"), output)
}

fn required_build_var(name: &str, dotenv: &HashMap<String, String>) -> String {
    env::var(name)
        .ok()
        .or_else(|| dotenv.get(name).cloned())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "{name} is required to build termlog. Set it in the build environment \
                 or create a local .env file from .env.example."
            )
        })
}

fn load_dotenv() -> HashMap<String, String> {
    let Ok(contents) = read_to_string(".env") else {
        return HashMap::new();
    };

    contents
        .lines()
        .filter_map(parse_dotenv_line)
        .collect::<HashMap<_, _>>()
}

fn parse_dotenv_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();

    if key.is_empty() {
        return None;
    }

    Some((key.to_owned(), unquote_dotenv_value(value.trim())))
}

fn unquote_dotenv_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();

        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }

    value.to_owned()
}

fn git_commit() -> String {
    ProcessCommand::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}
