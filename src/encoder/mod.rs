mod asciicast;
mod raw;
mod txt;

use std::io::Write;

use anyhow::Result;

use crate::asciicast::{Event, Header};
pub use asciicast::{AsciicastV2Encoder, AsciicastV3Encoder};
pub use raw::RawEncoder;
pub use txt::TextEncoder;

pub trait Encoder {
    fn header(&mut self, header: &Header) -> Vec<u8>;
    fn event(&mut self, event: Event) -> Vec<u8>;
    fn finish(&mut self) -> Vec<u8>;
}

pub trait EncoderExt {
    fn encode_to_writer<W: Write + ?Sized>(
        &mut self,
        cast: crate::asciicast::Asciicast,
        writer: &mut W,
    ) -> Result<()>;
}

impl<E: Encoder + ?Sized> EncoderExt for E {
    fn encode_to_writer<W: Write + ?Sized>(
        &mut self,
        cast: crate::asciicast::Asciicast,
        writer: &mut W,
    ) -> Result<()> {
        writer.write_all(&self.header(&cast.header))?;

        for event in cast.events {
            writer.write_all(&self.event(event?))?;
        }

        writer.write_all(&self.finish())?;

        Ok(())
    }
}
