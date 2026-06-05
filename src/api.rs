use std::collections::HashMap;
use std::env;
use std::fmt::Debug;

use anyhow::{bail, Context, Result};
use reqwest::{header, Response};
use reqwest::{multipart::Form, Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::Config;

#[derive(Debug, Deserialize)]
pub struct RecordingResponse {
    pub url: String,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StreamResponse {
    pub id: u64,
    pub ws_producer_url: String,
    pub url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Unlisted,
    Private,
}

#[derive(Default, Serialize)]
pub struct RecordingChangeset {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_url: Option<Option<String>>,
}

#[derive(Default, Serialize)]
pub struct StreamChangeset {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term_type: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term_version: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Option<HashMap<String, String>>>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    message: String,
}

pub fn get_auth_url(config: &mut Config) -> Result<Url> {
    let mut url = config.get_server_url()?;
    url.set_path(&format!("connect/{}", config.get_install_id()?));

    Ok(url)
}

pub async fn create_recording(
    path: &str,
    changeset: RecordingChangeset,
    config: &mut Config,
) -> Result<RecordingResponse> {
    let server_url = &config.get_server_url()?;
    let install_id = config.get_install_id()?;

    let response = create_recording_request(server_url, install_id, path, changeset)
        .await?
        .send()
        .await?;

    if response.status().as_u16() == 413 {
        match response.json::<ErrorResponse>().await {
            Ok(json) => {
                bail!("{}", json.message);
            }

            Err(_) => {
                bail!("The recording exceeds the server-configured size limit");
            }
        }
    } else {
        response.error_for_status_ref()?;
    }

    Ok(response.json::<RecordingResponse>().await?)
}

async fn create_recording_request(
    server_url: &Url,
    install_id: String,
    path: &str,
    changeset: RecordingChangeset,
) -> Result<RequestBuilder> {
    let client = Client::new();
    let mut url = server_url.clone();
    url.set_path("api/v1/recordings");
    let form = Form::new().file("file", path).await?;
    let form = add_recording_changeset_fields(form, changeset);
    let builder = client.post(url).multipart(form);

    Ok(add_headers(builder, &install_id))
}

fn add_recording_changeset_fields(mut form: Form, changeset: RecordingChangeset) -> Form {
    if let Some(Some(title)) = changeset.title {
        form = form.text("title", title);
    }

    if let Some(Some(description)) = changeset.description {
        form = form.text("description", description);
    }

    if let Some(visibility) = changeset.visibility {
        let visibility = match visibility {
            Visibility::Public => "public",
            Visibility::Unlisted => "unlisted",
            Visibility::Private => "private",
        };

        form = form.text("visibility", visibility);
    }

    if let Some(Some(audio_url)) = changeset.audio_url {
        form = form.text("audio_url", audio_url);
    }

    form
}

pub async fn list_user_streams(prefix: &str, config: &mut Config) -> Result<Vec<StreamResponse>> {
    let server_url = config.get_server_url()?;
    let install_id = config.get_install_id()?;

    let response = list_user_streams_request(&server_url, prefix, &install_id)
        .send()
        .await
        .context("cannot obtain stream producer endpoint - is the server down?")?;

    parse_stream_response(response, &server_url).await
}

fn list_user_streams_request(server_url: &Url, prefix: &str, install_id: &str) -> RequestBuilder {
    let client = Client::new();
    let mut url = server_url.clone();
    url.set_path("api/v1/user/streams");
    url.set_query(Some(&format!("prefix={prefix}&limit=10")));

    add_headers(client.get(url), install_id)
}

pub async fn create_stream(
    changeset: StreamChangeset,
    config: &mut Config,
) -> Result<StreamResponse> {
    let server_url = config.get_server_url()?;
    let install_id = config.get_install_id()?;

    let response = create_stream_request(&server_url, &install_id, changeset)
        .send()
        .await
        .context("cannot obtain stream producer endpoint - is the server down?")?;

    parse_stream_response(response, &server_url).await
}

fn create_stream_request(
    server_url: &Url,
    install_id: &str,
    changeset: StreamChangeset,
) -> RequestBuilder {
    let client = Client::new();
    let mut url = server_url.clone();
    url.set_path("api/v1/streams");
    let builder = client.post(url);
    let builder = add_headers(builder, install_id);

    builder.json(&changeset)
}

pub async fn update_stream(
    stream_id: u64,
    changeset: StreamChangeset,
    config: &mut Config,
) -> Result<StreamResponse> {
    let server_url = config.get_server_url()?;
    let install_id = config.get_install_id()?;

    let response = update_stream_request(&server_url, &install_id, stream_id, changeset)
        .send()
        .await
        .context("cannot obtain stream producer endpoint - is the server down?")?;

    parse_stream_response(response, &server_url).await
}

fn update_stream_request(
    server_url: &Url,
    install_id: &str,
    stream_id: u64,
    changeset: StreamChangeset,
) -> RequestBuilder {
    let client = Client::new();
    let mut url = server_url.clone();
    url.set_path(&format!("api/v1/streams/{stream_id}"));
    let builder = client.patch(url);
    let builder = add_headers(builder, install_id);

    builder.json(&changeset)
}

async fn parse_stream_response<T: DeserializeOwned>(
    response: Response,
    server_url: &Url,
) -> Result<T> {
    let server_hostname = server_url.host().unwrap();

    match response.status().as_u16() {
        401 => bail!(
            "this CLI hasn't been authenticated with {server_hostname} - run `termlog auth` first"
        ),

        404 => match response.json::<ErrorResponse>().await {
            Ok(json) => bail!("{}", json.message),
            Err(_) => bail!("{server_hostname} doesn't support streaming"),
        },

        422 => match response.json::<ErrorResponse>().await {
            Ok(json) => bail!("{}", json.message),
            Err(_) => bail!("{server_hostname} doesn't support streaming"),
        },

        _ => {
            response.error_for_status_ref()?;
        }
    }

    response.json::<T>().await.map_err(|e| e.into())
}

fn add_headers(builder: RequestBuilder, install_id: &str) -> RequestBuilder {
    builder
        .basic_auth(get_username(), Some(install_id))
        .header(header::USER_AGENT, build_user_agent())
        .header(header::ACCEPT, "application/json")
}

fn get_username() -> String {
    env::var("USER").unwrap_or("".to_owned())
}

pub fn build_user_agent() -> String {
    let ua = concat!(
        "termlog/",
        env!("CARGO_PKG_VERSION"),
        " target/",
        env!("TARGET")
    );

    ua.to_owned()
}
