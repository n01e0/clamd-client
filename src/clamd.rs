use anyhow::{Context, Result};
use std::ffi::CString;
use std::fs::File;
use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use thiserror::Error;

/// Default value for chunk size used in instream scan ref: man clamd
const DEFAULT_CHUNK_SIZE: u32 = 4096;

#[derive(Debug, Error)]
pub enum ClamdError {
    #[error("Can't create String from utf8 vec")]
    StringifyError(Vec<u8>),
    #[error("The path is not absolute")]
    PathIsNotAbsolute,
}

#[derive(Debug)]
pub struct Clamd {
    stream: UnixStream,
}

impl Drop for Clamd {
    fn drop(&mut self) {
        _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Clamd {
    /// Connect to clamd with default socket
    pub fn new() -> Result<Clamd> {
        Clamd::local_connect("/var/run/clamav/clamd.ctl")
    }

    /// Connect to clamd with specificated socket
    pub fn local_connect<P: AsRef<Path>>(sock: P) -> Result<Clamd> {
        Ok(Clamd {
            stream: UnixStream::connect(sock.as_ref())
                .with_context(|| "Can't connect unix stream")?,
        })
    }

    /// Check the daemon's state. It should reply with "PONG\0".
    pub fn ping(&mut self) -> Result<String> {
        self.command("zPING")
    }

    /// Check the clamav and database versions.
    pub fn version(&mut self) -> Result<String> {
        self.command("zVERSION")
    }

    /// Reload the database.
    pub fn reload(&mut self) -> Result<String> {
        self.command("zRELOAD")
    }

    /// Shutdown the clamd service.
    pub fn shutdown(&mut self) -> Result<()> {
        self.stream
            .write_all(
                CString::new("SHUTDOWN")
                    .with_context(|| "Can't create CString")?
                    .as_bytes_with_nul(),
            )
            .with_context(|| "Can't write to unix stream")
    }

    /// Scan a file or directory (recursively).
    pub fn scan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        if !path.as_ref().is_absolute() {
            return Err(ClamdError::PathIsNotAbsolute.into());
        }
        self.command(format!("zSCAN {}", path.as_ref().display()))
    }

    /// Scan a file or directory (recursively) and don't stop the scanning when a malware found.
    pub fn contscan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        self.command(format!("zCONTSCAN {}", path.as_ref().display()))
    }

    /// Scan a file or directory (recursively) using multi thread.
    pub fn multiscan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        self.command(format!("zMULTISCAN {}", path.as_ref().display()))
    }

    /// Instream Scan.
    pub fn instream_scan<P: AsRef<Path>>(
        &mut self,
        path: P,
        chunk_size: Option<u32>,
    ) -> Result<String> {
        self.sendmsg("zINSTREAM")?;
        let mut file = File::open(path).with_context(|| "Can't open file")?;
        let mut buf = vec![0; chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE) as usize];
        loop {
            let size = file
                .read(&mut buf)
                .with_context(|| "Can't read from file")?;
            if size != 0 {
                self.send((size as u32).to_be_bytes())?;
                self.send(&buf[0..size])?
            } else {
                self.send([0; 4])?; // zero sized chunk
                break;
            }
        }

        self.recv()
    }

    fn send<S: AsRef<[u8]>>(&mut self, data: S) -> Result<()> {
        self.stream.write_all(data.as_ref()).with_context(|| "Can't write to unix stream")
    }

    fn sendmsg<S: AsRef<[u8]>>(&mut self, msg: S) -> Result<()> {
        let req = CString::new(msg.as_ref()).with_context(|| "Can't create CString for send from {:?}")?;
        self.stream
            .write_all(req.as_bytes_with_nul())
            .with_context(|| "Can't write to unix stream")?;
        Ok(())
    }

    fn recv(&mut self) -> Result<String> {
        let mut resp = Vec::new();
        self.stream
            .read_to_end(&mut resp)
            .with_context(|| "Can't read from unix stream")?;

        Ok(String::from_utf8(resp)
            .map_err(|e| ClamdError::StringifyError(e.as_bytes().to_vec()))?)
    }

    fn command<S: AsRef<[u8]>>(&mut self, msg: S) -> Result<String> {
        self.sendmsg(msg)?;
        self.recv()
    }
}

#[cfg(test)]
mod clamd {
    use super::*;

    #[test]
    fn clamd_local_connection() {
        assert!(Clamd::new().is_ok());
        assert!(Clamd::local_connect("/var/run/clamav/clamd.ctl").is_ok());
    }

    #[test]
    fn ping() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.ping();
        assert!(resp.is_ok());
        assert_eq!("PONG\0", &resp.unwrap()[..])
    }
    #[test]
    fn version() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.version();
        assert!(resp.is_ok());
        assert!(resp.unwrap().contains("ClamAV"));
    }

    #[test]
    fn reload() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.reload();
        assert!(resp.is_ok());
        assert_eq!("RELOADING\0", &resp.unwrap()[..]);
    }

    #[test]
    fn scan() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.scan("/proc/self/exe");
        assert!(resp.is_ok());
        assert_eq!("/proc/self/exe: OK\0", &resp.unwrap()[..]);
    }

    #[test]
    fn contscan() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.contscan("/proc/self/exe");
        assert!(resp.is_ok());
        assert_eq!("/proc/self/exe: OK\0", &resp.unwrap()[..]);
    }

    #[test]
    fn multiscan() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.multiscan("/proc/self/exe");
        assert!(resp.is_ok());
        assert_eq!("/proc/self/exe: OK\0", &resp.unwrap()[..]);
    }

    #[test]
    fn scan_failure_iff_path_is_not_absolute() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.scan("./d0a353461bc77cb023d730e527c5160c7eb8b303");
        assert!(resp.is_err());
    }

    #[test]
    fn instream_scan() {
        let mut clamd = Clamd::new().unwrap();

        let resp = clamd.instream_scan("/bin/ls", None);
        assert!(resp.is_ok());
    }
}
