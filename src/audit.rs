use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header as JwtHeader,
    Validation,
};
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;
use uuid::Uuid;

use crate::asciicast::{self, EventData, Proof};
use crate::cli::{self, ReportFormat};
use crate::status;

pub const PROOF_MODE: &str = "offline-local-v2";

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_DISCOVERY_URL: &str = "https://accounts.google.com/.well-known/openid-configuration";
// Intentional inclusion: build.rs injects the Google Desktop OAuth client used by
// the distributed termlog binary so students can run `termlog login` without a
// separate config file.
include!(concat!(env!("OUT_DIR"), "/google_oauth.rs"));
const DEFAULT_AUTH_CACHE_GRACE_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub client_id: String,
    pub id_token: String,
    pub claims: GoogleClaims,
    pub identity_status: String,
    pub cache_login_time: u64,
    pub cache_expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct RecordingAudit {
    pub auth: AuthSession,
    pub proof: Proof,
    pub started_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoogleClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<BoolLike>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BoolLike {
    Bool(bool),
    String(String),
}

impl BoolLike {
    fn is_true(&self) -> bool {
        match self {
            BoolLike::Bool(value) => *value,
            BoolLike::String(value) => value.eq_ignore_ascii_case("true"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthCache {
    client_id: String,
    id_token: String,
    refresh_token: Option<String>,
    access_token: Option<String>,
    token_expires_at: Option<u64>,
    login_time: u64,
    claims: GoogleClaims,
    jwks: Option<serde_json::Value>,
    dev: bool,
}

#[derive(Debug, Deserialize)]
struct ClientFile {
    installed: Option<ClientSection>,
    web: Option<ClientSection>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientSection {
    client_id: String,
    client_secret: Option<String>,
    auth_uri: Option<String>,
    token_uri: Option<String>,
}

#[derive(Clone, Debug)]
struct OAuthClient {
    client_id: String,
    client_secret: Option<String>,
    auth_uri: String,
    token_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: u64,
    pub nbf: u64,
    pub jti: String,
    pub google_sub: String,
    pub google_client_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub google_id_token: String,
    pub google_id_token_sha256: String,
    pub sha256: String,
    pub size: u64,
    pub format: String,
    pub proof_session_id: String,
    pub started_at: u64,
    pub ended_at: u64,
    pub exit_status: i32,
    pub capture_input: bool,
    pub client_version: String,
    pub client_git_commit: String,
    pub client_target: String,
    pub platform: String,
    pub timestamp_anchor_count: usize,
    #[serde(default)]
    pub recording_identity_status: Option<String>,
    #[serde(default)]
    pub auth_cache_login_time: Option<u64>,
    #[serde(default)]
    pub auth_cache_expires_at: Option<u64>,
    #[serde(default)]
    pub google_token_expires_at: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TimestampAnchorPayload {
    pub version: u8,
    pub hash_alg: String,
    pub event_count: u64,
    pub event_bytes_sha256: String,
    pub time_micros: u64,
    pub tsa_url: String,
    pub token_der_b64: String,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    ok: bool,
    cast: String,
    receipt: String,
    sha256: String,
    size: u64,
    proof_session_id: Option<String>,
    google_sub: String,
    email: String,
    expected_email: Option<String>,
    email_check: String,
    receipt_signature: String,
    cast_hash: String,
    proof_header: String,
    google_client_id: String,
    expected_google_client_id: String,
    google_client_id_check: String,
    google_identity: String,
    google_identity_check: String,
    recording_identity_status: String,
    google_token_status: String,
    google_token_fresh_during_session: bool,
    auth_cache_login_time: Option<u64>,
    auth_cache_expires_at: Option<u64>,
    exit_event_present: bool,
    timestamp_anchor_count: usize,
    timestamp_anchor_check: String,
    warnings: Vec<String>,
}

impl cli::Login {
    pub fn run(self) -> Result<()> {
        if dev_auth_enabled() {
            save_cache(&dev_cache())?;
            println!("Logged in as student@example.edu (development auth)");
            return Ok(());
        }

        let creds = load_oauth_client()?;
        let cache = browser_login(&creds)?;

        let email = cache
            .claims
            .email
            .clone()
            .unwrap_or_else(|| "(no email claim)".to_owned());

        save_cache(&cache)?;
        println!("Logged in as {email}");

        Ok(())
    }
}

impl cli::Logout {
    pub fn run(self) -> Result<()> {
        let path = auth_cache_path()?;

        match fs::remove_file(&path) {
            Ok(()) => println!("Logged out"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("Already logged out"),
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }
}

impl cli::Whoami {
    pub fn run(self) -> Result<()> {
        let auth = ensure_authenticated()?;
        let email = auth
            .claims
            .email
            .clone()
            .unwrap_or_else(|| "(no email claim)".to_owned());
        let name = auth.claims.name.unwrap_or_default();

        if name.is_empty() {
            println!("{email}");
        } else {
            println!("{email} ({name})");
        }

        Ok(())
    }
}

impl cli::Verify {
    pub fn run(self) -> Result<()> {
        let receipt = self
            .receipt
            .clone()
            .unwrap_or_else(|| format!("{}.jwt", self.cast));
        let report = verify_recording(
            Path::new(&self.cast),
            Path::new(&receipt),
            self.expect_email.as_deref(),
        )?;

        match self.format {
            ReportFormat::Text => print_text_report(&report),
            ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        }

        if report.ok {
            Ok(())
        } else {
            bail!("recording verification failed")
        }
    }
}

pub fn prepare_recording() -> Result<RecordingAudit> {
    let auth = ensure_authenticated()?;
    let proof = Proof {
        mode: PROOF_MODE.to_owned(),
        google_sub: auth.claims.sub.clone(),
        email: verified_email(&auth.claims)?,
        login_iat: auth.claims.iat,
        login_exp: auth.claims.exp,
        session_id: random_token(24),
        nonce: random_token(32),
    };

    Ok(RecordingAudit {
        auth,
        proof,
        started_at: unix_now(),
    })
}

pub fn write_receipt(
    cast_path: &Path,
    audit: &RecordingAudit,
    ended_at: u64,
    exit_status: i32,
    capture_input: bool,
) -> Result<PathBuf> {
    let bytes = fs::read(cast_path).with_context(|| {
        format!(
            "cannot read recording for proof signing: {}",
            cast_path.display()
        )
    })?;
    let sha256 = sha256_hex(&bytes);
    let size = bytes.len() as u64;
    let anchor_count = count_timestamp_anchors(cast_path).unwrap_or(0);
    let now = unix_now();
    let claims = ReceiptClaims {
        iss: "termlog-offline-v2".to_owned(),
        aud: "termlog-recording".to_owned(),
        sub: audit.auth.claims.sub.clone(),
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        google_sub: audit.auth.claims.sub.clone(),
        google_client_id: audit.auth.client_id.clone(),
        email: verified_email(&audit.auth.claims)?,
        email_verified: true,
        name: audit.auth.claims.name.clone(),
        google_id_token: audit.auth.id_token.clone(),
        google_id_token_sha256: sha256_hex(audit.auth.id_token.as_bytes()),
        sha256,
        size,
        format: "asciicast-v2".to_owned(),
        proof_session_id: audit.proof.session_id.clone(),
        started_at: audit.started_at,
        ended_at,
        exit_status,
        capture_input,
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        client_git_commit: env!("GIT_COMMIT").to_owned(),
        client_target: env!("TARGET").to_owned(),
        platform: std::env::consts::OS.to_owned(),
        timestamp_anchor_count: anchor_count,
        recording_identity_status: Some(audit.auth.identity_status.clone()),
        auth_cache_login_time: Some(audit.auth.cache_login_time),
        auth_cache_expires_at: Some(audit.auth.cache_expires_at),
        google_token_expires_at: Some(audit.auth.claims.exp),
    };

    let mut header = JwtHeader::new(Algorithm::HS256);
    header.kid = Some("termlog-local-v2".to_owned());
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(EMBEDDED_RECEIPT_SECRET.as_bytes()),
    )?;
    let receipt_path = receipt_sidecar_path(cast_path);
    atomic_write(&receipt_path, jwt.as_bytes())?;

    Ok(receipt_path)
}

pub fn receipt_sidecar_path(cast_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.jwt", cast_path.to_string_lossy()))
}

pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let bytes = fs::read(path)?;
    Ok((sha256_hex(&bytes), bytes.len() as u64))
}

pub fn unix_timestamp() -> u64 {
    unix_now()
}

pub fn create_timestamp_anchor(
    tsa_url: &str,
    event_bytes_sha256: &str,
    event_count: u64,
    time_micros: u64,
) -> Result<TimestampAnchorPayload> {
    let query = openssl_timestamp_query(event_bytes_sha256)?;
    let response = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
        .post(tsa_url)
        .header("content-type", "application/timestamp-query")
        .header("accept", "application/timestamp-reply")
        .body(query)
        .send()
        .context("timestamp authority request failed")?
        .error_for_status()
        .context("timestamp authority returned an error")?
        .bytes()
        .context("cannot read timestamp authority response")?
        .to_vec();

    Ok(TimestampAnchorPayload {
        version: 1,
        hash_alg: "sha256".to_owned(),
        event_count,
        event_bytes_sha256: event_bytes_sha256.to_owned(),
        time_micros,
        tsa_url: tsa_url.to_owned(),
        token_der_b64: BASE64.encode(response),
    })
}

fn ensure_authenticated() -> Result<AuthSession> {
    if dev_auth_enabled() {
        return Ok(auth_from_cache(dev_cache(), "development"));
    }

    let mut cache = read_cache().context("not logged in; run `termlog login` first")?;

    if cache.dev {
        return Ok(auth_from_cache(cache, "development"));
    }

    let creds = load_oauth_client()?;
    let now = unix_now();

    if cache.claims.exp <= now + 60 {
        match refresh_cache(&creds, &cache) {
            Ok(refreshed) => {
                cache = refreshed;
                save_cache(&cache)?;
                return Ok(auth_from_cache(cache, "online_refreshed"));
            }

            Err(refresh_error) => {
                if !auth_cache_within_grace(cache.login_time, now, auth_cache_grace_secs()) {
                    return Err(refresh_error).context(
                        "cached Google login is outside the 24-hour offline grace window; run `termlog login` again",
                    );
                }

                let claims = verify_google_id_token_cached(
                    &cache.id_token,
                    &cache.client_id,
                    cache.jwks.as_ref(),
                    true,
                )
                .with_context(|| {
                    format!(
                        "cached Google token expired and refresh failed ({refresh_error}); run `termlog login` again"
                    )
                })?;

                if !email_verified(&claims) {
                    bail!("Google account email is not verified");
                }

                cache.claims = claims;
                save_cache(&cache)?;
                status::warning!(
                    "Using cached Google identity within 24-hour offline grace; token expired at {}",
                    cache.claims.exp
                );

                return Ok(auth_from_cache(cache, "cached_expired_token_within_grace"));
            }
        }
    }

    let identity_status;
    let claims;

    match verify_google_id_token_online(&cache.id_token, &cache.client_id, false) {
        Ok((online_claims, jwks)) => {
            claims = online_claims;
            cache.jwks = Some(jwks);
            identity_status = "online_verified";
        }

        Err(online_error) => {
            claims = verify_google_id_token_cached(
                &cache.id_token,
                &cache.client_id,
                cache.jwks.as_ref(),
                false,
            )
            .with_context(|| {
                format!("cannot verify Google identity online ({online_error}) or with cached keys")
            })?;
            identity_status = "cached_valid_token";
        }
    }

    if !email_verified(&claims) {
        bail!("Google account email is not verified");
    }

    cache.claims = claims;
    save_cache(&cache)?;

    Ok(auth_from_cache(cache, identity_status))
}

fn auth_from_cache(cache: AuthCache, identity_status: &str) -> AuthSession {
    let cache_login_time = cache.login_time;
    AuthSession {
        client_id: cache.client_id,
        id_token: cache.id_token,
        claims: cache.claims,
        identity_status: identity_status.to_owned(),
        cache_login_time,
        cache_expires_at: auth_cache_expires_at(cache_login_time),
    }
}

fn browser_login(creds: &OAuthClient) -> Result<AuthCache> {
    let listener = TcpListener::bind("127.0.0.1:0").context("cannot bind loopback listener")?;
    listener.set_nonblocking(true)?;
    let redirect_uri = format!("http://{}", listener.local_addr()?);
    let verifier = random_pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let state = random_token(32);
    let nonce = random_token(32);

    let mut url = Url::parse(&creds.auth_uri)?;
    url.query_pairs_mut()
        .append_pair("client_id", &creds.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    println!("Opening Google login in your browser...");
    println!("{url}\n");
    if let Err(e) = open_browser(url.as_str()) {
        status::warning!("Could not launch browser automatically: {e}");
        println!("Copy the URL above and open it in a browser on this machine to continue login.");
        println!("Waiting for Google login callback...");
    }

    let code = wait_for_oauth_code(&listener, &state)?;
    let mut form = HashMap::new();
    form.insert("client_id", creds.client_id.clone());
    form.insert("code", code);
    form.insert("code_verifier", verifier);
    form.insert("grant_type", "authorization_code".to_owned());
    form.insert("redirect_uri", redirect_uri);

    if let Some(secret) = &creds.client_secret {
        form.insert("client_secret", secret.clone());
    }

    token_response_to_cache(creds, post_token(&creds.token_uri, &form)?)
}

fn post_token(url: &str, form: &HashMap<&str, String>) -> Result<TokenResponse> {
    let response = Client::new()
        .post(url)
        .form(form)
        .send()
        .context("Google token request failed")?;

    if response.status().is_success() {
        Ok(response.json()?)
    } else {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        let message = serde_json::from_str::<OAuthError>(&body)
            .map(|e| {
                e.error_description
                    .map(|desc| format!("{}: {desc}", e.error))
                    .unwrap_or(e.error)
            })
            .unwrap_or(body);

        bail!("Google token request failed ({status}): {message}")
    }
}

fn token_response_to_cache(creds: &OAuthClient, token: TokenResponse) -> Result<AuthCache> {
    let id_token = token
        .id_token
        .ok_or_else(|| anyhow!("Google did not return an ID token"))?;
    let (claims, jwks) = verify_google_id_token(&id_token, &creds.client_id, None, false)?;

    if !email_verified(&claims) {
        bail!("Google account email is not verified");
    }

    Ok(AuthCache {
        client_id: creds.client_id.clone(),
        id_token,
        refresh_token: token.refresh_token,
        access_token: token.access_token,
        token_expires_at: token.expires_in.map(|expires| unix_now() + expires),
        login_time: unix_now(),
        claims,
        jwks: Some(jwks),
        dev: false,
    })
}

fn refresh_cache(creds: &OAuthClient, cache: &AuthCache) -> Result<AuthCache> {
    let verified_at = unix_now();
    let refresh_token = cache
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow!("cached login has no refresh token"))?;
    let mut form = HashMap::new();
    form.insert("client_id", creds.client_id.clone());
    form.insert("grant_type", "refresh_token".to_owned());
    form.insert("refresh_token", refresh_token);

    if let Some(secret) = &creds.client_secret {
        form.insert("client_secret", secret.clone());
    }

    let token = post_token(&creds.token_uri, &form)?;
    let id_token = token
        .id_token
        .ok_or_else(|| anyhow!("Google refresh did not return an ID token"))?;
    let (claims, jwks) =
        verify_google_id_token(&id_token, &creds.client_id, cache.jwks.as_ref(), false)?;

    Ok(AuthCache {
        client_id: creds.client_id.clone(),
        id_token,
        refresh_token: cache.refresh_token.clone(),
        access_token: token.access_token.or_else(|| cache.access_token.clone()),
        token_expires_at: token.expires_in.map(|expires| unix_now() + expires),
        login_time: verified_at,
        claims,
        jwks: Some(jwks),
        dev: false,
    })
}

fn verify_google_id_token(
    id_token: &str,
    client_id: &str,
    cached_jwks: Option<&serde_json::Value>,
    allow_expired: bool,
) -> Result<(GoogleClaims, serde_json::Value)> {
    verify_google_id_token_online(id_token, client_id, allow_expired).or_else(|_| {
        verify_google_id_token_cached(id_token, client_id, cached_jwks, allow_expired).map(
            |claims| {
                (
                    claims,
                    cached_jwks.cloned().unwrap_or(serde_json::Value::Null),
                )
            },
        )
    })
}

fn verify_google_id_token_online(
    id_token: &str,
    client_id: &str,
    allow_expired: bool,
) -> Result<(GoogleClaims, serde_json::Value)> {
    let jwks_value = fetch_google_jwks()?;
    let claims = verify_google_id_token_with_jwks(id_token, client_id, &jwks_value, allow_expired)?;

    Ok((claims, jwks_value))
}

fn verify_google_id_token_cached(
    id_token: &str,
    client_id: &str,
    cached_jwks: Option<&serde_json::Value>,
    allow_expired: bool,
) -> Result<GoogleClaims> {
    let jwks_value = cached_jwks.ok_or_else(|| anyhow!("cached Google JWKS is not available"))?;

    verify_google_id_token_with_jwks(id_token, client_id, jwks_value, allow_expired)
}

fn verify_google_id_token_with_jwks(
    id_token: &str,
    client_id: &str,
    jwks_value: &serde_json::Value,
    allow_expired: bool,
) -> Result<GoogleClaims> {
    let header = decode_header(id_token)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("Google ID token has no key id"))?;
    let jwks: JwkSet = serde_json::from_value(jwks_value.clone())?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow!("Google JWKS does not contain token key id {kid}"))?;
    let key = DecodingKey::from_jwk(jwk)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

    if allow_expired {
        validation.validate_exp = false;
    }

    let data = decode::<GoogleClaims>(id_token, &key, &validation)?;
    Ok(data.claims)
}

fn fetch_google_jwks() -> Result<serde_json::Value> {
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let discovery: Discovery = client
        .get(GOOGLE_DISCOVERY_URL)
        .send()
        .context("cannot fetch Google OIDC discovery document")?
        .error_for_status()?
        .json()?;

    Ok(client
        .get(discovery.jwks_uri)
        .send()
        .context("cannot fetch Google JWKS")?
        .error_for_status()?
        .json()?)
}

fn read_verifier_jwks_cache() -> Result<serde_json::Value> {
    let path = verifier_jwks_cache_path()?;
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn save_verifier_jwks_cache(jwks: &serde_json::Value) {
    let Ok(path) = verifier_jwks_cache_path() else {
        return;
    };
    let Ok(data) = serde_json::to_vec_pretty(jwks) else {
        return;
    };

    let _ = atomic_write(&path, &data);
}

fn verifier_jwks_cache_path() -> Result<PathBuf> {
    Ok(state_home()?.join("google-jwks.json"))
}

fn load_oauth_client() -> Result<OAuthClient> {
    if let Ok(client_id) = env::var("TERMLOG_GOOGLE_CLIENT_ID") {
        return Ok(OAuthClient {
            client_id,
            client_secret: env::var("TERMLOG_GOOGLE_CLIENT_SECRET").ok(),
            auth_uri: GOOGLE_AUTH_URL.to_owned(),
            token_uri: GOOGLE_TOKEN_URL.to_owned(),
        });
    }

    let json = match env::var("TERMLOG_GOOGLE_CLIENT_JSON") {
        Ok(value) if value.trim_start().starts_with('{') => value,
        Ok(path) => fs::read_to_string(path)?,
        Err(_) => match user_google_client_file_path() {
            Some(path) => match fs::read_to_string(&path) {
                Ok(json) => json,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(default_oauth_client());
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("cannot read Google OAuth client file {}", path.display())
                    })
                }
            },
            None => return Ok(default_oauth_client()),
        },
    };

    parse_oauth_client_json(&json)
}

fn user_google_client_file_path() -> Option<PathBuf> {
    env::var("TERMLOG_CONFIG_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            env::var("XDG_CONFIG_HOME")
                .ok()
                .map(|home| Path::new(&home).join("termlog"))
        })
        .or_else(|| {
            env::var("HOME")
                .ok()
                .map(|home| Path::new(&home).join(".config").join("termlog"))
        })
        .map(|dir| dir.join("google-client.json"))
}

fn parse_oauth_client_json(json: &str) -> Result<OAuthClient> {
    let file: ClientFile = serde_json::from_str(json)?;
    let section = file.installed.or(file.web);

    if let Some(section) = section {
        Ok(OAuthClient {
            client_id: section.client_id,
            client_secret: section.client_secret,
            auth_uri: section
                .auth_uri
                .unwrap_or_else(|| GOOGLE_AUTH_URL.to_owned()),
            token_uri: section
                .token_uri
                .unwrap_or_else(|| GOOGLE_TOKEN_URL.to_owned()),
        })
    } else {
        Ok(OAuthClient {
            client_id: file
                .client_id
                .ok_or_else(|| anyhow!("Google client JSON is missing client_id"))?,
            client_secret: file.client_secret,
            auth_uri: file.auth_uri.unwrap_or_else(|| GOOGLE_AUTH_URL.to_owned()),
            token_uri: file
                .token_uri
                .unwrap_or_else(|| GOOGLE_TOKEN_URL.to_owned()),
        })
    }
}

fn default_oauth_client() -> OAuthClient {
    OAuthClient {
        client_id: EMBEDDED_GOOGLE_CLIENT_ID.to_owned(),
        client_secret: Some(EMBEDDED_GOOGLE_CLIENT_SECRET.to_owned()),
        auth_uri: GOOGLE_AUTH_URL.to_owned(),
        token_uri: GOOGLE_TOKEN_URL.to_owned(),
    }
}

fn wait_for_oauth_code(listener: &TcpListener, expected_state: &str) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(300);

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for Google OAuth redirect");
        }

        match listener.accept() {
            Ok((mut stream, _)) => return handle_oauth_callback(&mut stream, expected_state),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn handle_oauth_callback(stream: &mut TcpStream, expected_state: &str) -> Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = [0_u8; 8192];
    let n = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty OAuth callback request"))?;
    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("invalid OAuth callback request"))?;
    let url = Url::parse(&format!("http://127.0.0.1{path}"))?;
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();

    let response_body = "<html><body><h1>termlog login complete</h1><p>You can close this tab and return to the terminal.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());

    if let Some(error) = params.get("error") {
        bail!("Google login failed: {error}");
    }

    let state = params
        .get("state")
        .ok_or_else(|| anyhow!("OAuth callback missing state"))?;

    if state != expected_state {
        bail!("OAuth state mismatch");
    }

    params
        .get("code")
        .cloned()
        .ok_or_else(|| anyhow!("OAuth callback missing code"))
}

fn open_browser(url: &str) -> Result<()> {
    if let Ok(browser) = env::var("BROWSER") {
        Command::new(browser).arg(url).spawn()?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    };

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };

    command.spawn().context("cannot launch browser")?;
    Ok(())
}

fn verify_recording(
    cast_path: &Path,
    receipt_path: &Path,
    expected_email: Option<&str>,
) -> Result<VerifyReport> {
    let (sha256, size) = sha256_file(cast_path)?;
    let receipt = fs::read_to_string(receipt_path)
        .with_context(|| format!("cannot read receipt JWT {}", receipt_path.display()))?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["termlog-recording"]);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let claims = decode::<ReceiptClaims>(
        receipt.trim(),
        &DecodingKey::from_secret(EMBEDDED_RECEIPT_SECRET.as_bytes()),
        &validation,
    )
    .context("receipt JWT signature is invalid")?
    .claims;

    let mut warnings = Vec::new();
    let expected_google_client_id = expected_google_client_id();
    let dev_receipt = claims.google_client_id == "termlog-dev"
        && claims.google_id_token == "termlog-dev-id-token";
    let (google_client_id_ok, google_client_id_check) = if dev_receipt {
        if dev_auth_enabled() {
            (true, "dev-mode".to_owned())
        } else {
            warnings.push(
                "development auth receipt rejected; TERMLOG_ALLOW_DEV_AUTH is not enabled"
                    .to_owned(),
            );
            (false, "dev-mode-disabled".to_owned())
        }
    } else if claims.google_client_id == expected_google_client_id {
        (true, "valid".to_owned())
    } else {
        warnings.push(format!(
            "Google client ID mismatch: receipt has {}, expected {}",
            claims.google_client_id, expected_google_client_id
        ));
        (false, "mismatch".to_owned())
    };
    let cast_hash_ok = claims.sha256 == sha256 && claims.size == size;
    let (email_ok, email_check, expected_email) = match expected_email {
        Some(expected) if claims.email.eq_ignore_ascii_case(expected) => {
            (true, "valid".to_owned(), Some(expected.to_owned()))
        }
        Some(expected) => {
            warnings.push(format!(
                "verified email mismatch: receipt has {}, expected {}",
                claims.email, expected
            ));
            (false, "mismatch".to_owned(), Some(expected.to_owned()))
        }
        None => (true, "not_requested".to_owned(), None),
    };
    let mut cast_parse_ok = true;
    let mut proof_header_ok = false;
    let mut proof_session_id = None;
    let mut exit_event_present = false;

    match asciicast::open_from_path(cast_path) {
        Ok(cast) => {
            let proof = cast.header.proof;
            proof_header_ok = proof.as_ref().is_some_and(|proof| {
                proof.mode == PROOF_MODE
                    && proof.google_sub == claims.google_sub
                    && proof.email == claims.email
                    && proof.session_id == claims.proof_session_id
            });
            proof_session_id = proof.map(|proof| proof.session_id);

            for event in cast.events {
                match event {
                    Ok(event) if matches!(event.data, EventData::Exit(_)) => {
                        exit_event_present = true;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        cast_parse_ok = false;
                        warnings.push(format!("recording event parse failed: {e}"));
                    }
                }
            }
        }

        Err(e) => {
            cast_parse_ok = false;
            warnings.push(format!("recording parse failed: {e}"));
        }
    }

    let token_claims = decode_google_claims_unverified(&claims.google_id_token).ok();
    let google_token_status = if dev_receipt {
        "dev-mode".to_owned()
    } else {
        token_claims
            .as_ref()
            .map(|google| {
                if google.exp < claims.started_at {
                    "expired_before_session"
                } else if google.exp < claims.ended_at {
                    "expired_during_session"
                } else {
                    "fresh_during_session"
                }
            })
            .unwrap_or("unparseable")
            .to_owned()
    };
    let token_fresh = token_claims
        .as_ref()
        .is_some_and(|google| google.iat <= claims.started_at && google.exp >= claims.ended_at);

    let (google_identity, google_identity_check) = if dev_receipt {
        if dev_auth_enabled() {
            ("development".to_owned(), "dev-mode".to_owned())
        } else {
            ("invalid".to_owned(), "dev-mode-disabled".to_owned())
        }
    } else {
        match fetch_google_jwks() {
            Ok(jwks) => {
                save_verifier_jwks_cache(&jwks);

                match verify_google_id_token_with_jwks(
                    &claims.google_id_token,
                    &expected_google_client_id,
                    &jwks,
                    true,
                ) {
                    Ok(google_claims) => {
                        if google_claims.sub == claims.google_sub
                            && verified_email(&google_claims).ok().as_deref()
                                == Some(claims.email.as_str())
                            && email_verified(&google_claims)
                        {
                            ("valid".to_owned(), "online".to_owned())
                        } else {
                            warnings.push("Google identity claims do not match receipt".to_owned());
                            ("mismatch".to_owned(), "online_mismatch".to_owned())
                        }
                    }

                    Err(e) => {
                        warnings.push(format!("Google identity check failed: {e}"));
                        ("invalid".to_owned(), "online_invalid".to_owned())
                    }
                }
            }

            Err(online_error) => match read_verifier_jwks_cache() {
                Ok(jwks) => match verify_google_id_token_with_jwks(
                    &claims.google_id_token,
                    &expected_google_client_id,
                    &jwks,
                    true,
                ) {
                    Ok(google_claims) => {
                        if google_claims.sub == claims.google_sub
                            && verified_email(&google_claims).ok().as_deref()
                                == Some(claims.email.as_str())
                            && email_verified(&google_claims)
                        {
                            warnings.push(format!(
                                "Google identity checked with cached JWKS because online check failed: {online_error}"
                            ));
                            ("valid".to_owned(), "cached".to_owned())
                        } else {
                            warnings.push("Google identity claims do not match receipt".to_owned());
                            ("mismatch".to_owned(), "cached_mismatch".to_owned())
                        }
                    }

                    Err(e) => {
                        warnings.push(format!(
                            "Google identity cached-key check failed after online check failed ({online_error}): {e}"
                        ));
                        ("invalid".to_owned(), "cached_invalid".to_owned())
                    }
                },

                Err(cache_error) => {
                    warnings.push(format!(
                        "Google identity check skipped: online check failed ({online_error}); cached JWKS unavailable ({cache_error})"
                    ));
                    (
                        "skipped".to_owned(),
                        "skipped_no_network_no_cache".to_owned(),
                    )
                }
            },
        }
    };

    let recording_identity_status = claims
        .recording_identity_status
        .clone()
        .unwrap_or_else(|| "unknown_legacy".to_owned());
    let auth_cache_window_ok = match (claims.auth_cache_login_time, claims.auth_cache_expires_at) {
        (Some(login_time), Some(expires_at)) => {
            login_time <= claims.started_at && claims.started_at <= expires_at
        }
        _ => true,
    };

    if !auth_cache_window_ok {
        warnings.push("recording started outside the cached-auth grace window".to_owned());
    }

    let anchor_report = verify_timestamp_anchors(cast_path).unwrap_or_else(|e| AnchorReport {
        ok: false,
        count: 0,
        status: "invalid".to_owned(),
        warnings: vec![format!("timestamp anchor check failed: {e}")],
    });
    warnings.extend(anchor_report.warnings);

    let ok = cast_hash_ok
        && proof_header_ok
        && exit_event_present
        && cast_parse_ok
        && (google_identity == "valid"
            || google_identity == "skipped"
            || google_identity == "development")
        && google_client_id_ok
        && email_ok
        && auth_cache_window_ok
        && anchor_report.ok;

    Ok(VerifyReport {
        ok,
        cast: cast_path.display().to_string(),
        receipt: receipt_path.display().to_string(),
        sha256,
        size,
        proof_session_id,
        google_sub: claims.google_sub,
        email: claims.email,
        expected_email,
        email_check,
        receipt_signature: "valid".to_owned(),
        cast_hash: if cast_hash_ok { "valid" } else { "mismatch" }.to_owned(),
        proof_header: if proof_header_ok { "valid" } else { "mismatch" }.to_owned(),
        google_client_id: claims.google_client_id,
        expected_google_client_id,
        google_client_id_check,
        google_identity,
        google_identity_check,
        recording_identity_status,
        google_token_status,
        google_token_fresh_during_session: token_fresh,
        auth_cache_login_time: claims.auth_cache_login_time,
        auth_cache_expires_at: claims.auth_cache_expires_at,
        exit_event_present,
        timestamp_anchor_count: anchor_report.count,
        timestamp_anchor_check: anchor_report.status,
        warnings,
    })
}

fn print_text_report(report: &VerifyReport) {
    println!("termlog verification");
    println!("  ok: {}", report.ok);
    println!("  cast: {}", report.cast);
    println!("  receipt: {}", report.receipt);
    println!("  sha256: {}", report.sha256);
    println!("  size: {}", report.size);
    println!("  user: {} ({})", report.email, report.google_sub);
    if let Some(expected_email) = &report.expected_email {
        println!("  expected email: {expected_email}");
    }
    println!("  email check: {}", report.email_check);
    println!("  receipt signature: {}", report.receipt_signature);
    println!("  cast hash: {}", report.cast_hash);
    println!("  proof header: {}", report.proof_header);
    println!("  Google client ID: {}", report.google_client_id);
    println!(
        "  expected Google client ID: {}",
        report.expected_google_client_id
    );
    println!(
        "  Google client ID check: {}",
        report.google_client_id_check
    );
    println!("  Google identity: {}", report.google_identity);
    println!("  Google identity check: {}", report.google_identity_check);
    println!(
        "  recording identity status: {}",
        report.recording_identity_status
    );
    println!("  Google token status: {}", report.google_token_status);
    println!(
        "  Google token fresh during session: {}",
        report.google_token_fresh_during_session
    );
    if let Some(login_time) = report.auth_cache_login_time {
        println!("  auth cache login time: {login_time}");
    }
    if let Some(expires_at) = report.auth_cache_expires_at {
        println!("  auth cache expires at: {expires_at}");
    }
    println!("  exit event present: {}", report.exit_event_present);
    println!("  timestamp anchors: {}", report.timestamp_anchor_count);
    println!(
        "  timestamp anchor check: {}",
        report.timestamp_anchor_check
    );

    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
}

struct AnchorReport {
    ok: bool,
    count: usize,
    status: String,
    warnings: Vec<String>,
}

fn verify_timestamp_anchors(cast_path: &Path) -> Result<AnchorReport> {
    let content = fs::read_to_string(cast_path)?;
    let mut lines = content.lines();
    let _header = lines.next();
    let mut hash = Sha256::new();
    let mut event_count = 0_u64;
    let mut anchor_count = 0_usize;
    let mut warnings = Vec::new();
    let mut token_failures = 0_usize;

    for line in lines {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let value: serde_json::Value = serde_json::from_str(line)?;
        let code = value
            .as_array()
            .and_then(|items| items.get(1))
            .and_then(|code| code.as_str())
            .unwrap_or("");

        if code == "a" {
            anchor_count += 1;
            let payload = value
                .as_array()
                .and_then(|items| items.get(2))
                .and_then(|data| data.as_str())
                .ok_or_else(|| anyhow!("timestamp anchor event has invalid payload"))?;
            let payload: TimestampAnchorPayload = serde_json::from_str(payload)?;
            let current_hash = hex_digest(hash.clone().finalize());

            if payload.event_count != event_count || payload.event_bytes_sha256 != current_hash {
                return Ok(AnchorReport {
                    ok: false,
                    count: anchor_count,
                    status: "mismatch".to_owned(),
                    warnings,
                });
            }

            match verify_timestamp_token(&payload) {
                Ok(Some(())) => {}
                Ok(None) => warnings.push("timestamp token cryptographic check skipped".to_owned()),
                Err(e) => {
                    token_failures += 1;
                    warnings.push(format!("timestamp token check failed: {e}"));
                }
            }
        } else {
            hash.update(line.as_bytes());
            hash.update(b"\n");
            event_count += 1;
        }
    }

    let ok = token_failures == 0;
    let status = if anchor_count == 0 {
        "none".to_owned()
    } else if token_failures == 0 {
        "valid-or-skipped".to_owned()
    } else {
        "invalid".to_owned()
    };

    Ok(AnchorReport {
        ok,
        count: anchor_count,
        status,
        warnings,
    })
}

fn verify_timestamp_token(payload: &TimestampAnchorPayload) -> Result<Option<()>> {
    let ca_file = env::var("TERMLOG_TSA_CA_FILE").ok();
    let ca_path = env::var("TERMLOG_TSA_CA_PATH").ok().or_else(|| {
        Path::new("/etc/ssl/certs")
            .exists()
            .then(|| "/etc/ssl/certs".to_owned())
    });

    if ca_file.is_none() && ca_path.is_none() {
        return Ok(None);
    }

    let query = openssl_timestamp_query(&payload.event_bytes_sha256)?;
    let mut query_file = NamedTempFile::new()?;
    query_file.write_all(&query)?;
    let mut token_file = NamedTempFile::new()?;
    token_file.write_all(&BASE64.decode(&payload.token_der_b64)?)?;

    let mut command = Command::new("openssl");
    command
        .args(["ts", "-verify", "-queryfile"])
        .arg(query_file.path())
        .arg("-in")
        .arg(token_file.path());

    if let Some(path) = ca_file {
        command.arg("-CAfile").arg(path);
    } else if let Some(path) = ca_path {
        command.arg("-CApath").arg(path);
    }

    let output = command.output().context("cannot run openssl ts -verify")?;

    if output.status.success() {
        Ok(Some(()))
    } else {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }
}

fn count_timestamp_anchors(path: &Path) -> Result<usize> {
    let cast = asciicast::open_from_path(path)?;
    let mut count = 0;

    for event in cast.events {
        if matches!(event?.data, EventData::Other('a', _)) {
            count += 1;
        }
    }

    Ok(count)
}

fn openssl_timestamp_query(digest_hex: &str) -> Result<Vec<u8>> {
    let output = Command::new("openssl")
        .args([
            "ts",
            "-query",
            "-sha256",
            "-digest",
            digest_hex,
            "-cert",
            "-no_nonce",
        ])
        .output()
        .context("cannot run openssl ts -query")?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }
}

fn email_verified(claims: &GoogleClaims) -> bool {
    claims
        .email_verified
        .as_ref()
        .is_some_and(BoolLike::is_true)
}

fn verified_email(claims: &GoogleClaims) -> Result<String> {
    if !email_verified(claims) {
        bail!("Google account email is not verified");
    }

    claims
        .email
        .clone()
        .ok_or_else(|| anyhow!("Google ID token has no email claim"))
}

fn dev_auth_enabled() -> bool {
    env::var("TERMLOG_ALLOW_DEV_AUTH").is_ok_and(|value| value == "1")
}

fn expected_google_client_id() -> String {
    env::var("TERMLOG_EXPECTED_GOOGLE_CLIENT_ID")
        .or_else(|_| env::var("TERMLOG_GOOGLE_CLIENT_ID"))
        .unwrap_or_else(|_| EMBEDDED_GOOGLE_CLIENT_ID.to_owned())
}

fn auth_cache_grace_secs() -> u64 {
    env::var("TERMLOG_AUTH_CACHE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AUTH_CACHE_GRACE_SECS)
}

fn auth_cache_expires_at(login_time: u64) -> u64 {
    login_time.saturating_add(auth_cache_grace_secs())
}

fn auth_cache_within_grace(login_time: u64, now: u64, grace_secs: u64) -> bool {
    now <= login_time.saturating_add(grace_secs)
}

fn dev_cache() -> AuthCache {
    let now = unix_now();
    AuthCache {
        client_id: "termlog-dev".to_owned(),
        id_token: "termlog-dev-id-token".to_owned(),
        refresh_token: None,
        access_token: None,
        token_expires_at: Some(now + 86400),
        login_time: now,
        claims: GoogleClaims {
            iss: "termlog-dev".to_owned(),
            aud: "termlog-dev".to_owned(),
            sub: "termlog-dev-user".to_owned(),
            exp: now + 86400,
            iat: now,
            email: Some("student@example.edu".to_owned()),
            email_verified: Some(BoolLike::Bool(true)),
            name: Some("Development Student".to_owned()),
        },
        jwks: None,
        dev: true,
    }
}

fn state_home() -> Result<PathBuf> {
    env::var("TERMLOG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|_| env::var("XDG_STATE_HOME").map(|home| Path::new(&home).join("termlog")))
        .or_else(|_| {
            env::var("HOME").map(|home| {
                Path::new(&home)
                    .join(".local")
                    .join("state")
                    .join("termlog")
            })
        })
        .map_err(|_| anyhow!("need $HOME or $XDG_STATE_HOME or $TERMLOG_STATE_HOME"))
}

fn auth_cache_path() -> Result<PathBuf> {
    Ok(state_home()?.join("auth.json"))
}

fn read_cache() -> Result<AuthCache> {
    Ok(serde_json::from_str(&fs::read_to_string(
        auth_cache_path()?,
    )?)?)
}

fn save_cache(cache: &AuthCache) -> Result<()> {
    let path = auth_cache_path()?;
    let data = serde_json::to_vec_pretty(cache)?;
    atomic_write(&path, &data)
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("termlog")
    ));
    fs::write(&temp_path, data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(temp_path, path)?;
    Ok(())
}

fn random_pkce_verifier() -> String {
    random_token(64)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn decode_google_claims_unverified(token: &str) -> Result<GoogleClaims> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("invalid JWT"))?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex_digest(Sha256::digest(data.as_ref()))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        auth_cache_within_grace, pkce_challenge, random_pkce_verifier,
        DEFAULT_AUTH_CACHE_GRACE_SECS,
    };

    #[test]
    fn pkce_challenge_is_base64url_sha256() {
        let challenge = pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_verifier_has_required_length() {
        let verifier = random_pkce_verifier();

        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);
    }

    #[test]
    fn auth_cache_grace_accepts_exactly_24_hours() {
        let login_time = 1_000;

        assert!(auth_cache_within_grace(
            login_time,
            login_time + DEFAULT_AUTH_CACHE_GRACE_SECS,
            DEFAULT_AUTH_CACHE_GRACE_SECS
        ));
        assert!(!auth_cache_within_grace(
            login_time,
            login_time + DEFAULT_AUTH_CACHE_GRACE_SECS + 1,
            DEFAULT_AUTH_CACHE_GRACE_SECS
        ));
    }
}
