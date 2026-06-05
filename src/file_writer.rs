use std::env;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::{self, AsyncWrite, AsyncWriteExt};

use crate::asciicast;
use crate::audit;
use crate::encoder::Encoder;
use crate::notifier::Notifier;
use crate::session::{self, Metadata};

const DEFAULT_TSA_URL: &str = "http://timestamp.digicert.com";

pub struct FileWriter {
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    encoder: Box<dyn Encoder + Send>,
    notifier: Box<dyn Notifier>,
    metadata: Metadata,
}

pub struct LiveFileWriter {
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    encoder: Box<dyn Encoder + Send>,
    notifier: Box<dyn Notifier>,
    timestamp_anchor: Option<TimestampAnchor>,
}

struct TimestampAnchor {
    tsa_url: String,
    interval: Duration,
    next_at: Duration,
    hash: Sha256,
    event_count: u64,
    last_event_time: Duration,
    last_anchor_event_count: u64,
}

impl FileWriter {
    pub fn new(
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        encoder: Box<dyn Encoder + Send>,
        notifier: Box<dyn Notifier>,
        metadata: Metadata,
    ) -> Self {
        FileWriter {
            writer,
            encoder,
            notifier,
            metadata,
        }
    }

    pub async fn start(mut self) -> io::Result<LiveFileWriter> {
        let timestamp = self
            .metadata
            .time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = asciicast::Header {
            term_cols: self.metadata.term.size.0,
            term_rows: self.metadata.term.size.1,
            term_type: self.metadata.term.type_.clone(),
            term_version: self.metadata.term.version.clone(),
            term_theme: self.metadata.term.theme.clone(),
            timestamp: Some(timestamp),
            idle_time_limit: self.metadata.idle_time_limit,
            command: self.metadata.command.as_ref().cloned(),
            title: self.metadata.title.as_ref().cloned(),
            env: Some(self.metadata.env.clone()),
            proof: self.metadata.proof.clone(),
        };

        if let Err(e) = self.writer.write_all(&self.encoder.header(&header)).await {
            let _ = self
                .notifier
                .notify("Write error, session won't be recorded".to_owned())
                .await;

            return Err(e);
        }

        Ok(LiveFileWriter {
            writer: self.writer,
            encoder: self.encoder,
            notifier: self.notifier,
            timestamp_anchor: self
                .metadata
                .proof
                .as_ref()
                .and_then(|_| TimestampAnchor::from_env()),
        })
    }
}

#[async_trait]
impl session::Output for LiveFileWriter {
    async fn event(&mut self, event: session::Event) -> io::Result<()> {
        let time = event_time(&event);
        let encoded = self.encoder.event(event.into());

        match self.writer.write_all(&encoded).await {
            Ok(_) => {
                if let Some(anchor) = &mut self.timestamp_anchor {
                    anchor.observe(&encoded, time);

                    match anchor.maybe_create(time).await {
                        Ok(Some(payload)) => {
                            let event = asciicast::Event {
                                time,
                                data: asciicast::EventData::Other('a', payload),
                            };

                            if let Err(e) = self.writer.write_all(&self.encoder.event(event)).await
                            {
                                let _ = self
                                    .notifier
                                    .notify("Write error, timestamp anchor skipped".to_owned())
                                    .await;

                                return Err(e);
                            }
                        }

                        Ok(None) => {}

                        Err(e) => {
                            let _ = self
                                .notifier
                                .notify(format!("Timestamp anchor failed: {e}"))
                                .await;
                        }
                    }
                }

                Ok(())
            }

            Err(e) => {
                let _ = self
                    .notifier
                    .notify("Write error, recording suspended".to_owned())
                    .await;

                Err(e)
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        if let Some(anchor) = &mut self.timestamp_anchor {
            match anchor.finalize().await {
                Ok(Some(payload)) => {
                    let event = asciicast::Event {
                        time: anchor.last_event_time,
                        data: asciicast::EventData::Other('a', payload),
                    };

                    if let Err(e) = self.writer.write_all(&self.encoder.event(event)).await {
                        let _ = self
                            .notifier
                            .notify("Write error, timestamp anchor skipped".to_owned())
                            .await;

                        return Err(e);
                    }
                }

                Ok(None) => {}

                Err(e) => {
                    let _ = self
                        .notifier
                        .notify(format!("Timestamp anchor failed: {e}"))
                        .await;
                }
            }
        }

        self.writer.write_all(&self.encoder.flush()).await?;
        self.writer.flush().await
    }
}

impl TimestampAnchor {
    fn from_env() -> Option<Self> {
        if env::var("TERMLOG_DISABLE_TSA").is_ok_and(|value| value == "1") {
            return None;
        }

        let tsa_url = env::var("TERMLOG_TSA_URL").ok().or_else(|| {
            if env::var("TERMLOG_ALLOW_DEV_AUTH").is_ok_and(|value| value == "1") {
                None
            } else {
                Some(DEFAULT_TSA_URL.to_owned())
            }
        })?;
        let interval = env::var("TERMLOG_TSA_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300);

        if interval == 0 {
            return None;
        }

        Some(Self {
            tsa_url,
            interval: Duration::from_secs(interval),
            next_at: Duration::from_secs(interval),
            hash: Sha256::new(),
            event_count: 0,
            last_event_time: Duration::ZERO,
            last_anchor_event_count: 0,
        })
    }

    fn observe(&mut self, encoded_event: &[u8], time: Duration) {
        self.hash.update(encoded_event);
        self.event_count += 1;
        self.last_event_time = time;
    }

    async fn maybe_create(&mut self, time: Duration) -> anyhow::Result<Option<String>> {
        if time < self.next_at || self.event_count == 0 {
            return Ok(None);
        }

        while self.next_at <= time {
            self.next_at += self.interval;
        }

        self.create(time).await.map(Some)
    }

    async fn finalize(&mut self) -> anyhow::Result<Option<String>> {
        if self.event_count == 0 || self.event_count == self.last_anchor_event_count {
            return Ok(None);
        }

        self.create(self.last_event_time).await.map(Some)
    }

    async fn create(&mut self, time: Duration) -> anyhow::Result<String> {
        let tsa_url = self.tsa_url.clone();
        let hash = hex_digest(self.hash.clone().finalize());
        let event_count = self.event_count;
        let time_micros = time.as_micros().min(u128::from(u64::MAX)) as u64;
        let payload = tokio::task::spawn_blocking(move || {
            audit::create_timestamp_anchor(&tsa_url, &hash, event_count, time_micros)
        })
        .await
        .map_err(|e| anyhow::anyhow!("timestamp worker failed: {e}"))??;
        self.last_anchor_event_count = event_count;

        Ok(serde_json::to_string(&payload)?)
    }
}

fn event_time(event: &session::Event) -> Duration {
    match event {
        session::Event::Output(time, _)
        | session::Event::Input(time, _)
        | session::Event::Resize(time, _)
        | session::Event::Marker(time, _)
        | session::Event::Exit(time, _) => *time,
    }
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl From<session::Event> for asciicast::Event {
    fn from(event: session::Event) -> Self {
        match event {
            session::Event::Output(time, text) => asciicast::Event::output(time, text),
            session::Event::Input(time, text) => asciicast::Event::input(time, text),
            session::Event::Resize(time, tty_size) => {
                asciicast::Event::resize(time, tty_size.into())
            }
            session::Event::Marker(time, label) => asciicast::Event::marker(time, label),
            session::Event::Exit(time, status) => asciicast::Event::exit(time, status),
        }
    }
}
