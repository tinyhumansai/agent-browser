//! Process-launch contracts for an embedding host that owns native isolation.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CONTROL_READ_BUFFER_BYTES: usize = 8192;

/// Maximum size of one NUL-delimited Chromium DevTools pipe frame.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Read one complete Chromium DevTools pipe message, excluding its NUL byte.
/// A missing delimiter cannot grow the buffer beyond the configured limit.
pub fn read_control_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut message = Vec::new();
    let mut byte = [0];
    loop {
        match reader.read(&mut byte)? {
            0 if message.is_empty() => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete CDP pipe message",
                ))
            }
            _ if byte[0] == 0 => return Ok(Some(message)),
            _ => {
                if message.len() == MAX_CONTROL_MESSAGE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CDP pipe message exceeds maximum size",
                    ));
                }
                message.push(byte[0]);
            }
        }
    }
}

/// Write a complete NUL-delimited Chromium DevTools pipe message.
pub fn write_control_message(writer: &mut dyn Write, message: &[u8]) -> io::Result<()> {
    if message.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CDP pipe message exceeds maximum size",
        ));
    }
    if message.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CDP pipe message contains NUL",
        ));
    }
    writer.write_all(message)?;
    writer.write_all(&[0])?;
    writer.flush()
}

/// Bounded asynchronous reader for the Chromium NUL-framed DevTools pipe.
pub(crate) struct BrowserControlPipeReader {
    reader: Box<dyn AsyncRead + Send + Unpin>,
    buffered: Vec<u8>,
    cursor: usize,
}

impl BrowserControlPipeReader {
    pub(crate) fn new(reader: Box<dyn AsyncRead + Send + Unpin>) -> Self {
        Self {
            reader,
            buffered: Vec::new(),
            cursor: 0,
        }
    }

    /// Read one bounded NUL-delimited message, retaining bytes read past its delimiter.
    pub(crate) async fn read_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut message = Vec::new();
        let mut chunk = [0; CONTROL_READ_BUFFER_BYTES];
        loop {
            let available = &self.buffered[self.cursor..];
            if let Some(delimiter) = available.iter().position(|byte| *byte == 0) {
                if message.len() + delimiter > MAX_CONTROL_MESSAGE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CDP pipe message exceeds maximum size",
                    ));
                }
                message.extend_from_slice(&available[..delimiter]);
                self.cursor += delimiter + 1;
                if self.cursor == self.buffered.len() {
                    self.buffered.clear();
                    self.cursor = 0;
                }
                return Ok(Some(message));
            }

            if message.len() + available.len() > MAX_CONTROL_MESSAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CDP pipe message exceeds maximum size",
                ));
            }
            message.extend_from_slice(available);
            self.buffered.clear();
            self.cursor = 0;

            let count = self.reader.read(&mut chunk).await?;
            if count == 0 {
                return if message.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "incomplete CDP pipe message",
                    ))
                };
            }
            self.buffered.extend_from_slice(&chunk[..count]);
        }
    }
}

/// Asynchronously write one bounded, NUL-delimited DevTools message.
pub async fn write_control_message_async(
    writer: &mut (dyn AsyncWrite + Send + Unpin),
    message: &[u8],
) -> io::Result<()> {
    if message.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CDP pipe message exceeds maximum size",
        ));
    }
    if message.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CDP pipe message contains NUL",
        ));
    }
    writer.write_all(message).await?;
    writer.write_all(&[0]).await?;
    writer.flush().await
}

/// Browser-to-controller transport selected before process creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserControlTransport {
    /// Chromium exposes DevTools over its normal loopback WebSocket endpoint.
    WebSocket,
    /// Chromium exposes DevTools only through inherited private process pipes.
    InheritedPipe,
}

/// The parent ends of Chromium's inherited DevTools pipes.
pub struct BrowserControlPipe {
    reader: Box<dyn AsyncRead + Send + Unpin>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    control: Arc<dyn BrowserControlPipeControl>,
}

/// Interrupts both ends of a DevTools pipe. Implementations must make pending
/// asynchronous reads and writes return promptly; Unix providers normally use
/// nonblocking descriptors with a cancellation fd, while Windows providers
/// cancel pending overlapped I/O.
pub trait BrowserControlPipeControl: Send + Sync {
    /// Interrupt pending I/O on both pipe endpoints and prevent future writes.
    fn shutdown(&self);
}

impl BrowserControlPipe {
    /// Build a control channel from the parent ends created during spawn.
    #[must_use]
    pub fn new(
        reader: Box<dyn AsyncRead + Send + Unpin>,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        control: Arc<dyn BrowserControlPipeControl>,
    ) -> Self {
        Self {
            reader,
            writer,
            control,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
        Arc<dyn BrowserControlPipeControl>,
    ) {
        (self.reader, self.writer, self.control)
    }
}

/// Immutable launch description assembled by agent-browser after validating
/// the browser request. Debug output intentionally omits arguments and
/// environment values because they may contain proxy credentials.
pub struct BrowserLaunchSpec {
    executable: PathBuf,
    args: Vec<String>,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    headless: bool,
    control_transport: BrowserControlTransport,
}

impl BrowserLaunchSpec {
    pub(crate) fn new(
        executable: PathBuf,
        args: Vec<String>,
        environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        headless: bool,
        control_transport: BrowserControlTransport,
    ) -> Self {
        Self {
            executable,
            args,
            environment,
            headless,
            control_transport,
        }
    }

    /// Resolved executable selected by agent-browser's normal discovery.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Full browser argument vector, in launch order.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Per-child environment additions selected by agent-browser.
    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }

    /// Whether this launch uses Chrome's headless mode.
    #[must_use]
    pub fn headless(&self) -> bool {
        self.headless
    }

    /// Selected control channel. A network-isolated launch must use
    /// [`BrowserControlTransport::InheritedPipe`], never a browser loopback
    /// TCP endpoint that the host cannot reach without a broker.
    #[must_use]
    pub fn control_transport(&self) -> BrowserControlTransport {
        self.control_transport
    }

    /// Build Chromium's Windows inherited-pipe switch from the exact pipe
    /// handle values placed in its restricted inherited-handle list.
    pub fn args_for_windows_pipe_handles(
        &self,
        read_handle: usize,
        write_handle: usize,
    ) -> Result<Vec<String>, String> {
        if self.control_transport != BrowserControlTransport::InheritedPipe {
            return Err("Windows pipe handles require inherited-pipe transport".to_owned());
        }
        if read_handle == 0 || write_handle == 0 || read_handle == write_handle {
            return Err("Windows CDP pipe handles must be distinct nonzero values".to_owned());
        }
        let mut args = self.args.clone();
        let flag = args
            .iter_mut()
            .find(|arg| arg.as_str() == "--remote-debugging-io-pipes")
            .ok_or_else(|| "launch spec lacks the Windows inherited-pipe switch".to_owned())?;
        *flag = format!("--remote-debugging-io-pipes={read_handle},{write_handle}");
        Ok(args)
    }
}

impl std::fmt::Debug for BrowserLaunchSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserLaunchSpec")
            .field("executable", &self.executable)
            .field("argument_count", &self.args.len())
            .field(
                "environment_keys",
                &self
                    .environment
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<Vec<_>>(),
            )
            .field("headless", &self.headless)
            .field("control_transport", &self.control_transport)
            .finish()
    }
}

/// Owned process handle needed by agent-browser to read DevTools startup
/// output and terminate the full browser process tree.
pub trait BrowserChildProcess: Send {
    /// Operating-system process identifier for diagnostics and ownership.
    fn id(&self) -> u32;

    /// Take the captured stderr stream once, if the backend captured it.
    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>>;

    /// Take the parent ends of the inherited DevTools pipe, if requested.
    fn take_control_pipe(&mut self) -> Result<Option<BrowserControlPipe>, String>;

    /// Check whether the browser has exited without blocking.
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;

    /// Wait for the browser process to exit.
    fn wait(&mut self) -> io::Result<ExitStatus>;

    /// Terminate the browser and every process it started.
    fn terminate_tree(&mut self) -> io::Result<()>;
}

/// Trusted embedding-host hook for spawning Chromium under native policy.
/// Implementations must establish the requested boundary for the actual
/// browser process and its descendants, or return an error. They must not
/// silently downgrade to an ordinary spawn. This contract alone does not
/// prove that an implementation enforces isolation.
pub trait BrowserSpawnSupervisor: Send + Sync {
    /// Refuse unsupported control or isolation requirements before creating
    /// any process. Implementations must validate that they can create the
    /// requested transport and OS-native process boundary. In particular,
    /// Windows pipe launches must create inheritable child handles, make the
    /// parent ends non-inheritable, allowlist exactly the child endpoints, and
    /// use [`BrowserLaunchSpec::args_for_windows_pipe_handles`] before spawn.
    /// Unix pipe launches must arrange Chrome's read/write endpoints as FD 3/4
    /// and provide cancellable asynchronous wrappers for the parent endpoints.
    /// Unsupported platforms or missing capabilities must return an error.
    fn preflight(&self, spec: &BrowserLaunchSpec) -> Result<(), String>;

    /// Spawn the already-validated browser command and retain ownership of
    /// its process tree for its lifetime. For inherited pipes, Unix
    /// implementations must pass the Chrome-read endpoint as FD 3 and
    /// Chrome-write endpoint as FD 4 with cancellable nonblocking parent IO.
    /// Windows implementations must pass
    /// exactly the pipe handles named by
    /// [`BrowserLaunchSpec::args_for_windows_pipe_handles`] in the process
    /// handle allowlist. Other platforms must reject this mode in `preflight`.
    fn spawn(&self, spec: BrowserLaunchSpec) -> Result<Box<dyn BrowserChildProcess>, String>;
}

pub(crate) fn spawn_chrome_process<F>(
    spec: BrowserLaunchSpec,
    supervisor: Option<Arc<dyn BrowserSpawnSupervisor>>,
    required: bool,
    default_spawn: F,
) -> Result<Box<dyn BrowserChildProcess>, String>
where
    F: FnOnce(BrowserLaunchSpec) -> Result<Box<dyn BrowserChildProcess>, String>,
{
    if let Some(supervisor) = supervisor {
        supervisor.preflight(&spec)?;
        return supervisor.spawn(spec);
    }
    if required {
        return Err("browser launch requires a browser process supervisor".to_owned());
    }
    default_spawn(spec)
}
