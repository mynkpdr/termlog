use std::fs::File;
use std::io::{self, Write};

pub trait OutputWriter: Write + Send {
    fn finish(self: Box<Self>) -> io::Result<()>;
}

pub fn new(file: File, compressed: bool) -> io::Result<Box<dyn OutputWriter>> {
    if compressed {
        Ok(Box::new(zstd::stream::write::Encoder::new(file, 6)?))
    } else {
        Ok(Box::new(file))
    }
}

impl OutputWriter for File {
    fn finish(mut self: Box<Self>) -> io::Result<()> {
        self.flush()
    }
}

impl OutputWriter for zstd::stream::write::Encoder<'static, File> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        (*self).finish().map(drop)
    }
}
