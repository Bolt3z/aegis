use std::io::{self, Read, Write};

use crate::aead::{NONCE_LEN, TAG_LEN, decrypt, encrypt};
use crate::error::{Error, Result};
use crate::header::{CHUNK_SIZE, HEADER_LEN, NONCE_PREFIX_LEN};
use crate::key::Key;

const COUNTER_LEN: usize = 4;
const LAST_FLAG_OFFSET: usize = NONCE_PREFIX_LEN + COUNTER_LEN;
const _: () = assert!(LAST_FLAG_OFFSET + 1 == NONCE_LEN);

fn stream_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..LAST_FLAG_OFFSET].copy_from_slice(&counter.to_be_bytes());
    nonce[LAST_FLAG_OFFSET] = u8::from(last);
    nonce
}

fn io_err(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Push-style encryptor: implements `Write`. Buffers up to `CHUNK_SIZE` bytes
/// of plaintext, emits a non-last AEAD chunk on every full buffer, and emits
/// the final last-flagged chunk only when `finish()` is called.
pub struct StreamEncoder<W: Write> {
    writer: W,
    key: Key,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    header_aad: [u8; HEADER_LEN],
    counter: u32,
    buf: Vec<u8>,
    finished: bool,
}

impl<W: Write> StreamEncoder<W> {
    pub fn new(
        writer: W,
        key: Key,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        header_aad: [u8; HEADER_LEN],
    ) -> Self {
        Self {
            writer,
            key,
            nonce_prefix,
            header_aad,
            counter: 0,
            buf: Vec::with_capacity(CHUNK_SIZE),
            finished: false,
        }
    }

    fn emit_full_chunk(&mut self) -> Result<()> {
        debug_assert_eq!(self.buf.len(), CHUNK_SIZE);
        let nonce = stream_nonce(&self.nonce_prefix, self.counter, false);
        let ct = encrypt(&self.key, &nonce, &self.header_aad, &self.buf)?;
        self.writer.write_all(&ct)?;
        self.buf.clear();
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(Error::ChunkCounterOverflow)?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        let nonce = stream_nonce(&self.nonce_prefix, self.counter, true);
        let ct = encrypt(&self.key, &nonce, &self.header_aad, &self.buf)?;
        self.writer.write_all(&ct)?;
        self.buf.clear();
        self.finished = true;
        Ok(self.writer)
    }
}

impl<W: Write> Write for StreamEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut offset = 0;
        while offset < data.len() {
            let want = CHUNK_SIZE - self.buf.len();
            let take = want.min(data.len() - offset);
            self.buf.extend_from_slice(&data[offset..offset + take]);
            offset += take;
            if self.buf.len() == CHUNK_SIZE {
                self.emit_full_chunk().map_err(io_err)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Do NOT emit the final chunk here — STREAM construction requires
        // exactly one last-flagged chunk, only on `finish()`.
        self.writer.flush()
    }
}


/// Pull-style decryptor: implements `Read`. Reads one ciphertext chunk at a
/// time, decrypts, and surfaces plaintext to the caller. When a decryption
/// error occurs, `Read::read` returns an `io::Error` AND stashes the typed
/// error; callers should consult `take_error()` after a copy failure to
/// recover the precise `Error` variant.
pub struct StreamDecoder<R: Read> {
    reader: R,
    key: Key,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    header_aad: [u8; HEADER_LEN],
    counter: u32,
    plaintext: Vec<u8>,
    pos: usize,
    done: bool,
    stashed: Option<Error>,
}

impl<R: Read> StreamDecoder<R> {
    pub fn new(
        reader: R,
        key: Key,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        header_aad: [u8; HEADER_LEN],
    ) -> Self {
        Self {
            reader,
            key,
            nonce_prefix,
            header_aad,
            counter: 0,
            plaintext: Vec::new(),
            pos: 0,
            done: false,
            stashed: None,
        }
    }

    pub fn take_error(&mut self) -> Option<Error> {
        self.stashed.take()
    }

    fn fetch_next_chunk(&mut self) -> Result<()> {
        let mut buf = vec![0u8; CHUNK_SIZE + TAG_LEN];
        let mut total = 0;
        while total < buf.len() {
            match self.reader.read(&mut buf[total..])? {
                0 => break,
                n => total += n,
            }
        }
        if total < TAG_LEN {
            return Err(Error::Truncated);
        }
        let is_last = total < CHUNK_SIZE + TAG_LEN;
        let nonce = stream_nonce(&self.nonce_prefix, self.counter, is_last);
        let pt = decrypt(&self.key, &nonce, &self.header_aad, &buf[..total])?;
        self.plaintext = pt;
        self.pos = 0;
        if is_last {
            self.done = true;
        } else {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or(Error::ChunkCounterOverflow)?;
        }
        Ok(())
    }
}

impl<R: Read> Read for StreamDecoder<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.plaintext.len() {
                let n = (self.plaintext.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.plaintext[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            if let Err(e) = self.fetch_next_chunk() {
                let msg = e.to_string();
                self.stashed = Some(e);
                return Err(io::Error::other(msg));
            }
            // Loop and try to serve from the freshly-populated buffer.
        }
    }
}
