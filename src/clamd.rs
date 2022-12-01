use anyhow::{Context, Result};
use std::ffi::CString;
use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::path::Path;
use thiserror::Error;

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

impl Clamd {
    /// Connect to clamd with default socket
    pub fn new() -> Result<Clamd> {
        Clamd::connect("/var/run/clamav/clamd.ctl")
    }

    /// Connect to clamd with specificated socket
    pub fn connect<P: AsRef<Path>>(sock: P) -> Result<Clamd> {
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

    /// Scan a file or directory (recursively)
    pub fn scan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        if !path.as_ref().is_absolute() {
            return Err(ClamdError::PathIsNotAbsolute.into());
        }
        self.command(format!("zSCAN {}", path.as_ref().display()))
    }

    pub fn contscan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        self.command(format!("zCONTSCAN {}", path.as_ref().display()))
    }

    pub fn multiscan<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        self.command(format!("zMULTISCAN {}", path.as_ref().display()))
    }

    fn command<S: AsRef<str>>(&mut self, request: S) -> Result<String> {
        let mut resp = Vec::new();
        let req = CString::new(request.as_ref()).with_context(|| "Can't create CString")?;

        self.stream
            .write_all(req.as_bytes_with_nul())
            .with_context(|| "Can't write to unix stream")?;
        self.stream
            .read_to_end(&mut resp)
            .with_context(|| "Can't read from unix stream")?;

        Ok(
            String::from_utf8(resp)
            .map_err(|e| ClamdError::StringifyError(e.as_bytes().to_vec()))?
        )
    }
}

#[cfg(test)]
mod clamd {
    use super::*;

    #[test]
    fn clamd_connection() {
        assert!(Clamd::new().is_ok());
        assert!(Clamd::connect("/var/run/clamav/clamd.ctl").is_ok());
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
        let resp = clamd.scan("/proc/self/cwd");
        assert!(resp.is_ok());
    }
}
