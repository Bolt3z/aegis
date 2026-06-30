use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::error::{Error, Result};
use crate::header::{FLAG_COMPRESSED, FLAG_DIRECTORY, HEADER_LEN, Header};
use crate::kdf::{KdfParams, derive_key};
use crate::stream::{StreamDecoder, StreamEncoder};

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().into();
    s.push(suffix);
    PathBuf::from(s)
}

struct PathGuard {
    path: PathBuf,
    armed: bool,
    is_dir: bool,
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        if self.armed {
            if self.is_dir {
                let _ = std::fs::remove_dir_all(&self.path);
            } else {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

fn open_tmp_file_exclusive(tmp_path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(tmp_path)?)
}

fn read_header_from(reader: &mut impl Read) -> Result<(Header, [u8; HEADER_LEN])> {
    let mut bytes = [0u8; HEADER_LEN];
    reader.read_exact(&mut bytes).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::Truncated
        } else {
            Error::Io(e)
        }
    })?;
    let header = Header::parse(&bytes)?;
    Ok((header, bytes))
}

/// Read just the 64-byte header from a .bml file. Used by callers (e.g. the
/// CLI) to decide whether the payload is a file or a directory before
/// committing to an output path.
pub fn peek_header(input: &Path) -> Result<Header> {
    let mut reader = BufReader::new(File::open(input)?);
    let (header, _) = read_header_from(&mut reader)?;
    Ok(header)
}

fn encrypt_payload<F>(
    output: &Path,
    flags: u8,
    password: &[u8],
    params: KdfParams,
    write_plaintext: F,
) -> Result<()>
where
    F: FnOnce(&mut StreamEncoder<BufWriter<File>>) -> Result<()>,
{
    if output.exists() {
        return Err(Error::OutputAlreadyExists);
    }
    let tmp_path = append_suffix(output, ".tmp");
    if tmp_path.exists() {
        return Err(Error::OutputAlreadyExists);
    }

    let header = Header::new(flags, params)?;
    let header_bytes = header.serialize();
    let key = derive_key(password, &header.salt, header.kdf_params)?;

    let tmp_file = open_tmp_file_exclusive(&tmp_path)?;
    let mut guard = PathGuard {
        path: tmp_path.clone(),
        armed: true,
        is_dir: false,
    };
    let mut writer = BufWriter::new(tmp_file);
    writer.write_all(&header_bytes)?;

    let mut encoder = StreamEncoder::new(writer, key, header.nonce_prefix, header_bytes);
    write_plaintext(&mut encoder)?;
    let writer = encoder.finish()?;

    let mut file = writer.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp_path, output)?;
    guard.armed = false;
    Ok(())
}

pub fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    params: KdfParams,
    extra_flags: u8,
) -> Result<()> {
    if !input.is_file() {
        return Err(Error::Io(io::Error::other(format!(
            "encrypt_file: not a regular file: {}",
            input.display()
        ))));
    }
    encrypt_payload(output, extra_flags, password, params, |encoder| {
        let mut reader = BufReader::new(File::open(input)?);
        io::copy(&mut reader, encoder)?;
        Ok(())
    })
}

pub fn encrypt_dir(
    input: &Path,
    output: &Path,
    password: &[u8],
    params: KdfParams,
    extra_flags: u8,
) -> Result<()> {
    if !input.is_dir() {
        return Err(Error::Io(io::Error::other(format!(
            "encrypt_dir: not a directory: {}",
            input.display()
        ))));
    }
    let compress = extra_flags & FLAG_COMPRESSED != 0;
    encrypt_payload(
        output,
        FLAG_DIRECTORY | extra_flags,
        password,
        params,
        |encoder| {
            if compress {
                // Pipeline: tar -> gzip -> AEAD encoder. Finish the gzip layer
                // before returning so all compressed bytes reach the encoder.
                let gz = GzEncoder::new(encoder, Compression::default());
                let mut builder = tar::Builder::new(gz);
                builder.follow_symlinks(false);
                builder.append_dir_all(".", input)?;
                let gz = builder.into_inner()?;
                gz.finish()?;
            } else {
                let mut builder = tar::Builder::new(encoder);
                builder.follow_symlinks(false);
                builder.append_dir_all(".", input)?;
                builder.finish()?;
                drop(builder);
            }
            Ok(())
        },
    )
}

pub fn decrypt_file(input: &Path, output: &Path, password: &[u8]) -> Result<()> {
    if output.exists() {
        return Err(Error::OutputAlreadyExists);
    }
    let tmp_path = append_suffix(output, ".tmp");
    if tmp_path.exists() {
        return Err(Error::OutputAlreadyExists);
    }

    let mut reader = BufReader::new(File::open(input)?);
    let (header, header_bytes) = read_header_from(&mut reader)?;
    if header.flags & FLAG_DIRECTORY != 0 {
        return Err(Error::InvalidHeader(
            "this .bml contains a directory; use decrypt_dir / `aegis decrypt` with a directory output",
        ));
    }
    let key = derive_key(password, &header.salt, header.kdf_params)?;

    let tmp_file = open_tmp_file_exclusive(&tmp_path)?;
    let mut guard = PathGuard {
        path: tmp_path.clone(),
        armed: true,
        is_dir: false,
    };
    let mut writer = BufWriter::new(tmp_file);

    let mut decoder = StreamDecoder::new(reader, key, header.nonce_prefix, header_bytes);
    if let Err(e) = io::copy(&mut decoder, &mut writer) {
        return Err(decoder.take_error().unwrap_or(Error::Io(e)));
    }

    let mut file = writer.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp_path, output)?;
    guard.armed = false;
    Ok(())
}

pub fn decrypt_dir(input: &Path, output: &Path, password: &[u8]) -> Result<()> {
    // Output dir: must not exist, or must be an empty directory.
    if output.exists() {
        if !output.is_dir() {
            return Err(Error::OutputAlreadyExists);
        }
        let mut entries = std::fs::read_dir(output)?;
        if entries.next().is_some() {
            return Err(Error::OutputAlreadyExists);
        }
    }
    let tmp_path = append_suffix(output, ".tmp");
    if tmp_path.exists() {
        return Err(Error::OutputAlreadyExists);
    }

    let mut reader = BufReader::new(File::open(input)?);
    let (header, header_bytes) = read_header_from(&mut reader)?;
    if header.flags & FLAG_DIRECTORY == 0 {
        return Err(Error::InvalidHeader(
            "this .bml contains a file; use decrypt_file / `aegis decrypt` with a file output",
        ));
    }
    let compress = header.flags & FLAG_COMPRESSED != 0;
    let key = derive_key(password, &header.salt, header.kdf_params)?;

    std::fs::create_dir_all(&tmp_path)?;
    let mut guard = PathGuard {
        path: tmp_path.clone(),
        armed: true,
        is_dir: true,
    };

    let mut decoder = StreamDecoder::new(reader, key, header.nonce_prefix, header_bytes);
    // Compute the unpack result in a scope that drops the archive (and the gzip
    // layer, if any) before we touch `decoder` again for error reporting.
    let unpack_result = if compress {
        // Pipeline: AEAD decoder -> gunzip -> tar.
        let mut archive = tar::Archive::new(GzDecoder::new(&mut decoder));
        archive.set_overwrite(false);
        archive.set_preserve_permissions(true);
        archive.unpack(&tmp_path)
    } else {
        let mut archive = tar::Archive::new(&mut decoder);
        archive.set_overwrite(false);
        archive.set_preserve_permissions(true);
        archive.unpack(&tmp_path)
    };
    if let Err(e) = unpack_result {
        return Err(decoder.take_error().unwrap_or(Error::Io(e)));
    }

    // Done writing. Move tmp dir into final place.
    if output.exists() {
        // Existed-empty case: remove the empty placeholder so we can rename.
        std::fs::remove_dir(output)?;
    }
    std::fs::rename(&tmp_path, output)?;
    guard.armed = false;
    Ok(())
}

