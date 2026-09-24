use std::env;
use std::io::{self, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::asciicast;
use crate::audit;
use crate::encoder::Encoder;
use crate::notifier::Notifier;
use crate::output_writer::OutputWriter;
use crate::session::{self, Metadata};

const DEFAULT_TSA_URL: &str = "http://timestamp.digicert.com";

pub struct FileOutput {
    writer: Box<dyn OutputWriter>,
    encoder: Box<dyn Encoder + Send>,
    notifier: Box<dyn Notifier>,
    metadata: Metadata,
}

pub struct LiveFileOutput {
    commands: Option<mpsc::Sender<Command>>,
    worker: Option<thread::JoinHandle<()>>,
    notifier: Box<dyn Notifier>,
}

/// Worker replies: `Ok(Some(warning))` reports a non-fatal problem (e.g. a timestamp anchor
/// failed) that the async side shows via the notifier; recording continues.
type Reply = io::Result<Option<String>>;

enum Command {
    Event(session::Event, oneshot::Sender<Reply>),
    Finish(oneshot::Sender<Reply>),
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

impl FileOutput {
    pub fn new(
        writer: Box<dyn OutputWriter>,
        encoder: Box<dyn Encoder + Send>,
        notifier: Box<dyn Notifier>,
        metadata: Metadata,
    ) -> Self {
        Self {
            writer,
            encoder,
            notifier,
            metadata,
        }
    }

    pub async fn start(self) -> io::Result<LiveFileOutput> {
        let header = make_header(&self.metadata);
        let anchor = self
            .metadata
            .proof
            .as_ref()
            .and_then(|_| TimestampAnchor::from_env());
        let (commands_tx, commands_rx) = mpsc::channel();
        let (started_tx, started_rx) = oneshot::channel();

        let worker = thread::Builder::new()
            .name("asciinema-file-output".to_owned())
            .spawn(move || {
                run_worker(
                    self.writer,
                    self.encoder,
                    header,
                    anchor,
                    commands_rx,
                    started_tx,
                )
            })?;

        let mut output = LiveFileOutput {
            commands: Some(commands_tx),
            worker: Some(worker),
            notifier: self.notifier,
        };

        match started_rx.await {
            Ok(Ok(())) => Ok(output),

            Ok(Err(e)) => {
                output.join_worker()?;

                let _ = output
                    .notifier
                    .notify("Write error, session won't be recorded".to_owned())
                    .await;

                Err(e)
            }

            Err(_) => {
                output.join_worker()?;
                Err(worker_failed())
            }
        }
    }
}

#[async_trait]
impl session::Output for LiveFileOutput {
    async fn event(&mut self, event: session::Event) -> io::Result<()> {
        let result = match &self.commands {
            Some(commands) => send_command(commands, |result| Command::Event(event, result)).await,
            None => Err(worker_failed()),
        };

        match result {
            Ok(warning) => {
                self.notify_warning(warning).await;
                Ok(())
            }

            Err(e) => {
                self.commands.take();
                self.join_worker()?;

                let _ = self
                    .notifier
                    .notify("Write error, recording suspended".to_owned())
                    .await;

                Err(e)
            }
        }
    }

    async fn finish(&mut self) -> io::Result<()> {
        let Some(commands) = self.commands.take() else {
            return Ok(());
        };

        let result = send_command(&commands, Command::Finish).await;
        let join_result = self.join_worker();

        match result {
            Ok(warning) => {
                self.notify_warning(warning).await;
                join_result
            }

            Err(e) => Err(e),
        }
    }
}

impl LiveFileOutput {
    async fn notify_warning(&mut self, warning: Option<String>) {
        if let Some(message) = warning {
            let _ = self.notifier.notify(message).await;
        }
    }

    fn join_worker(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| worker_failed())?;
        }

        Ok(())
    }
}

fn run_worker(
    mut writer: Box<dyn OutputWriter>,
    mut encoder: Box<dyn Encoder + Send>,
    header: asciicast::Header,
    mut anchor: Option<TimestampAnchor>,
    commands: mpsc::Receiver<Command>,
    started: oneshot::Sender<io::Result<()>>,
) {
    let start_result = writer
        .write_all(&encoder.header(&header))
        .and_then(|()| writer.flush());

    if let Err(e) = start_result {
        let _ = writer.finish();
        let _ = started.send(Err(e));
        return;
    }

    if started.send(Ok(())).is_err() {
        let _ = writer.finish();
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            Command::Event(event, result) => {
                let time = event_time(&event);
                let encoded = encoder.event(event.into());

                if let Err(e) = writer.write_all(&encoded) {
                    let _ = writer.finish();
                    let _ = result.send(Err(e));
                    return;
                }

                let mut warning = None;

                if let Some(anchor) = &mut anchor {
                    anchor.observe(&encoded, time);

                    match anchor.maybe_create(time) {
                        Ok(Some(payload)) => {
                            if let Err(e) = write_anchor(&mut writer, &mut encoder, time, payload) {
                                let _ = writer.finish();
                                let _ = result.send(Err(e));
                                return;
                            }
                        }

                        Ok(None) => {}
                        Err(e) => warning = Some(format!("Timestamp anchor failed: {e}")),
                    }
                }

                let _ = result.send(Ok(warning));
            }

            Command::Finish(result) => {
                let mut warning = None;

                if let Some(anchor) = &mut anchor {
                    match anchor.finalize() {
                        Ok(Some(payload)) => {
                            let time = anchor.last_event_time;

                            if let Err(e) = write_anchor(&mut writer, &mut encoder, time, payload) {
                                let _ = writer.finish();
                                let _ = result.send(Err(e));
                                return;
                            }
                        }

                        Ok(None) => {}
                        Err(e) => warning = Some(format!("Timestamp anchor failed: {e}")),
                    }
                }

                let write_result = writer.write_all(&encoder.finish());

                let finish_result = match write_result {
                    Ok(()) => writer.finish().map(|()| warning),

                    Err(e) => {
                        let _ = writer.finish();
                        Err(e)
                    }
                };

                let _ = result.send(finish_result);

                return;
            }
        }
    }

    let _ = writer.write_all(&encoder.finish());
    let _ = writer.finish();
}

fn write_anchor(
    writer: &mut Box<dyn OutputWriter>,
    encoder: &mut Box<dyn Encoder + Send>,
    time: Duration,
    payload: String,
) -> io::Result<()> {
    let event = asciicast::Event {
        time,
        data: asciicast::EventData::Other('a', payload),
    };

    writer.write_all(&encoder.event(event))
}

async fn send_command(
    commands: &mpsc::Sender<Command>,
    make_command: impl FnOnce(oneshot::Sender<Reply>) -> Command,
) -> Reply {
    let (result_tx, result_rx) = oneshot::channel();

    commands
        .send(make_command(result_tx))
        .map_err(|_| worker_failed())?;

    result_rx.await.unwrap_or_else(|_| Err(worker_failed()))
}

fn make_header(metadata: &Metadata) -> asciicast::Header {
    let timestamp = metadata
        .time
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());

    asciicast::Header {
        term_cols: metadata.term.size.0,
        term_rows: metadata.term.size.1,
        term_type: metadata.term.type_.clone(),
        term_version: metadata.term.version.clone(),
        term_theme: metadata.term.theme.clone(),
        timestamp,
        idle_time_limit: metadata.idle_time_limit,
        command: metadata.command.clone(),
        title: metadata.title.clone(),
        env: Some(metadata.env.clone()),
        proof: metadata.proof.clone(),
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

    fn maybe_create(&mut self, time: Duration) -> anyhow::Result<Option<String>> {
        if time < self.next_at || self.event_count == 0 {
            return Ok(None);
        }

        while self.next_at <= time {
            self.next_at += self.interval;
        }

        self.create(time).map(Some)
    }

    fn finalize(&mut self) -> anyhow::Result<Option<String>> {
        if self.event_count == 0 || self.event_count == self.last_anchor_event_count {
            return Ok(None);
        }

        self.create(self.last_event_time).map(Some)
    }

    // Runs on the file-output worker thread (no async runtime), so the blocking
    // timestamp-authority request is safe to call directly.
    fn create(&mut self, time: Duration) -> anyhow::Result<String> {
        let hash = hex_digest(self.hash.clone().finalize());
        let time_micros = time.as_micros().min(u128::from(u64::MAX)) as u64;
        let payload =
            audit::create_timestamp_anchor(&self.tsa_url, &hash, self.event_count, time_micros)?;
        self.last_anchor_event_count = self.event_count;

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

fn worker_failed() -> io::Error {
    io::Error::other("file output worker failed")
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::time::{Duration, SystemTime};

    use tempfile::tempdir;

    use super::*;
    use crate::encoder::{AsciicastV2Encoder, AsciicastV3Encoder, Encoder};
    use crate::notifier::NullNotifier;
    use crate::output_writer;
    use crate::session::{Output, TermInfo};
    use crate::tty::TtySize;

    #[test]
    fn writes_appended_zstd_frames() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recording.cast.zst");

        write_recording(&path, false, true, "first", Duration::from_secs(1));
        write_recording(&path, true, true, "second", Duration::from_secs(2));

        assert!(asciicast::is_zstd(&path).unwrap());

        let cast = asciicast::open_from_path(&path).unwrap();
        let events = cast.events.collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(events.len(), 3);
        assert_eq!(events.last().unwrap().time, Duration::from_secs(3));
        assert_eq!(
            asciicast::get_duration(path).unwrap(),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn writes_plain_recording() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recording.cast");

        write_recording(&path, false, false, "output", Duration::from_secs(1));

        assert!(!asciicast::is_zstd(&path).unwrap());
        assert_eq!(asciicast::open_from_path(path).unwrap().events.count(), 1);
    }

    #[test]
    fn writes_appended_zstd_v2_frames() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recording.cast.zst");

        write_v2_recording(&path, false, "first", Duration::from_secs(1));
        write_v2_recording(&path, true, "second", Duration::from_secs(2));

        let cast = asciicast::open_from_path(&path).unwrap();
        assert_eq!(cast.version, asciicast::Version::Two);
        assert_eq!(
            cast.events.last().unwrap().unwrap().time,
            Duration::from_secs(3)
        );
    }

    fn write_recording(
        path: &std::path::Path,
        append: bool,
        compressed: bool,
        text: &str,
        time: Duration,
    ) {
        let file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create_new(!append)
            .open(path)
            .unwrap();
        write_with_encoder(
            file,
            compressed,
            Box::new(AsciicastV3Encoder::new(append)),
            text,
            time,
        );
    }

    fn write_v2_recording(path: &std::path::Path, append: bool, text: &str, time: Duration) {
        let time_offset = if append {
            asciicast::get_duration(path).unwrap()
        } else {
            Duration::ZERO
        };
        let file = fs::OpenOptions::new()
            .write(true)
            .append(append)
            .create_new(!append)
            .open(path)
            .unwrap();

        write_with_encoder(
            file,
            true,
            Box::new(AsciicastV2Encoder::new(append, time_offset)),
            text,
            time,
        );
    }

    fn write_with_encoder(
        file: fs::File,
        compressed: bool,
        encoder: Box<dyn Encoder + Send>,
        text: &str,
        time: Duration,
    ) {
        let writer = output_writer::new(file, compressed).unwrap();
        let metadata = Metadata {
            time: SystemTime::now(),
            term: TermInfo {
                type_: None,
                version: None,
                size: TtySize(80, 24),
                theme: None,
            },
            idle_time_limit: None,
            command: None,
            title: None,
            env: HashMap::new(),
            proof: None,
        };
        let file_output = FileOutput::new(writer, encoder, Box::new(NullNotifier), metadata);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let mut output = file_output.start().await.unwrap();
            output
                .event(session::Event::Output(time, text.to_owned()))
                .await
                .unwrap();
            output.finish().await.unwrap();
        });
    }
}
