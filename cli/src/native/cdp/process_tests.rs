use super::process::{
    spawn_chrome_process, BrowserChildProcess, BrowserControlPipeControl, BrowserControlTransport,
    BrowserLaunchSpec, BrowserSpawnSupervisor,
};
use serde_json::Value;
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn inherited_pipe_frames_are_bounded_and_handle_partial_io() {
    use super::process::{read_control_message, write_control_message, MAX_CONTROL_MESSAGE_BYTES};
    use std::io::{self, Read, Write};

    struct ShortWriter(Vec<u8>);
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let len = bytes.len().min(2);
            self.0.extend_from_slice(&bytes[..len]);
            Ok(len)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct ShortReader<'a>(&'a [u8]);
    impl Read for ShortReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let len = out.len().min(1).min(self.0.len());
            out[..len].copy_from_slice(&self.0[..len]);
            self.0 = &self.0[len..];
            Ok(len)
        }
    }

    let mut writer = ShortWriter(Vec::new());
    write_control_message(&mut writer, br#"{"id":1}"#).unwrap();
    assert_eq!(writer.0, b"{\"id\":1}\0");
    assert_eq!(
        read_control_message(&mut ShortReader(&writer.0)).unwrap(),
        Some(br#"{"id":1}"#.to_vec())
    );
    assert_eq!(read_control_message(&mut ShortReader(b"")).unwrap(), None);
    assert_eq!(
        read_control_message(&mut ShortReader(b"partial"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        write_control_message(&mut Vec::new(), &vec![b'x'; MAX_CONTROL_MESSAGE_BYTES + 1])
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        read_control_message(&mut ShortReader(&vec![b'x'; MAX_CONTROL_MESSAGE_BYTES + 1]))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        write_control_message(&mut Vec::new(), b"bad\0frame")
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires installed Chrome and its supported sandbox helper"]
async fn supervised_launch_drives_real_chrome_over_inherited_pipe() {
    use super::process::{BrowserControlPipe, BrowserLaunchSpec};
    use crate::native::browser::BrowserManager;
    use crate::native::cdp::chrome::{find_chrome, LaunchOptions};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct LinuxPipeChild {
        child: Child,
        pid: u32,
        pipe: Arc<std::sync::Mutex<Option<BrowserControlPipe>>>,
    }

    struct UnixPipeControl(UnixStream, UnixStream);
    impl BrowserControlPipeControl for UnixPipeControl {
        fn shutdown(&self) {
            let _ = self.0.shutdown(std::net::Shutdown::Both);
            let _ = self.1.shutdown(std::net::Shutdown::Both);
        }
    }
    impl BrowserChildProcess for LinuxPipeChild {
        fn id(&self) -> u32 {
            self.pid
        }
        fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
            self.child.stderr.take().map(|stderr| Box::new(stderr) as _)
        }
        fn take_control_pipe(&mut self) -> Result<Option<BrowserControlPipe>, String> {
            Ok(self.pipe.lock().unwrap().take())
        }
        fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            self.child.try_wait()
        }
        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            self.child.wait()
        }
        fn terminate_tree(&mut self) -> std::io::Result<()> {
            // The test owns this newly created process group exclusively.
            unsafe {
                libc::kill(-(self.pid as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            self.child.wait().map(|_| ())
        }
    }

    struct LinuxPipeSupervisor {
        pipe: Arc<std::sync::Mutex<Option<BrowserControlPipe>>>,
        pid: Arc<AtomicU32>,
    }
    impl BrowserSpawnSupervisor for LinuxPipeSupervisor {
        fn spawn(&self, spec: BrowserLaunchSpec) -> Result<Box<dyn BrowserChildProcess>, String> {
            let (parent_to_chrome, child_read) = UnixStream::pair().map_err(|e| e.to_string())?;
            let (child_write, chrome_to_parent) = UnixStream::pair().map_err(|e| e.to_string())?;
            let control = Arc::new(UnixPipeControl(
                parent_to_chrome.try_clone().map_err(|e| e.to_string())?,
                chrome_to_parent.try_clone().map_err(|e| e.to_string())?,
            ));
            let child_read = duplicate_for_child(child_read.as_raw_fd())?;
            let child_write = duplicate_for_child(child_write.as_raw_fd())?;
            let read_fd = child_read.as_raw_fd();
            let write_fd = child_write.as_raw_fd();
            parent_to_chrome
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            chrome_to_parent
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            let parent_to_chrome = tokio::net::UnixStream::from_std(parent_to_chrome)
                .map_err(|error| error.to_string())?;
            let chrome_to_parent = tokio::net::UnixStream::from_std(chrome_to_parent)
                .map_err(|error| error.to_string())?;
            let (chrome_reader, _) = chrome_to_parent.into_split();
            let (_, chrome_writer) = parent_to_chrome.into_split();
            let mut command = Command::new(spec.executable());
            command
                .args(spec.args())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            for (key, value) in spec.environment() {
                command.env(key, value);
            }
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(read_fd, 3) < 0
                        || libc::dup2(write_fd, 4) < 0
                        || libc::setpgid(0, 0) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn().map_err(|e| format!("spawn Chrome: {e}"))?;
            let pid = child.id();
            self.pid.store(pid, Ordering::SeqCst);
            drop(child_read);
            drop(child_write);
            *self.pipe.lock().unwrap() = Some(BrowserControlPipe::new(
                Box::new(chrome_reader),
                Box::new(chrome_writer),
                control,
            ));
            Ok(Box::new(LinuxPipeChild {
                child,
                pid,
                pipe: self.pipe.clone(),
            }))
        }
        fn preflight(&self, spec: &BrowserLaunchSpec) -> Result<(), String> {
            if spec.control_transport() != BrowserControlTransport::InheritedPipe {
                return Err("test supervisor only supports inherited pipes".to_owned());
            }
            Ok(())
        }
    }
    fn duplicate_for_child(fd: std::os::fd::RawFd) -> Result<OwnedFd, String> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }

    let chrome = find_chrome().expect("Chrome must be installed for the live inherited-pipe test");
    let supervisor = Arc::new(LinuxPipeSupervisor {
        pipe: Arc::new(std::sync::Mutex::new(None)),
        pid: Arc::new(AtomicU32::new(0)),
    });
    async fn launch(
        chrome: &std::path::Path,
        supervisor: Arc<LinuxPipeSupervisor>,
    ) -> BrowserManager {
        let options = LaunchOptions {
            executable_path: Some(chrome.display().to_string()),
            ..Default::default()
        };
        BrowserManager::launch_with_supervisor(options, Some("chrome"), Some(supervisor), true)
            .await
            .expect("Chrome must start and speak CDP through FD 3/4")
    }
    fn assert_process_tree_terminated(pid: u32) {
        assert_ne!(pid, 0, "test supervisor must record the Chrome pid");
        // wait_or_kill must reap Chrome itself; the process-group signal must
        // leave no live renderer, utility, or crashpad helper behind.
        let result = unsafe { libc::kill(pid as i32, 0) };
        let error = std::io::Error::last_os_error();
        assert_eq!(result, -1);
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
            {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(fields) = stat.rsplit_once(')').map(|(_, fields)| fields) else {
                continue;
            };
            let fields: Vec<_> = fields.split_whitespace().collect();
            if fields.get(2).and_then(|group| group.parse::<u32>().ok()) == Some(pid) {
                assert_eq!(
                    fields.first().copied(),
                    Some("Z"),
                    "live Chrome process remained: {stat}"
                );
            }
        }
    }

    let mut browser = launch(&chrome, supervisor.clone()).await;
    let version = browser
        .client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .expect("pipe-backed CDP command must reach Chrome");
    assert!(version.get("product").and_then(Value::as_str).is_some());
    browser
        .close()
        .await
        .expect("browser process tree should close cleanly");
    assert_process_tree_terminated(supervisor.pid.load(Ordering::SeqCst));

    let browser = launch(&chrome, supervisor.clone()).await;
    let version = browser
        .client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .expect("second pipe-backed CDP command must reach Chrome");
    assert!(version.get("product").and_then(Value::as_str).is_some());
    let pid = supervisor.pid.load(Ordering::SeqCst);
    drop(browser);
    assert_process_tree_terminated(pid);
}

fn spec() -> BrowserLaunchSpec {
    BrowserLaunchSpec::new(
        PathBuf::from("/missing/chrome"),
        vec!["--proxy-password=top-secret".to_owned()],
        vec![("PROXY_PASSWORD".into(), "top-secret".into())],
        true,
        BrowserControlTransport::InheritedPipe,
    )
}

#[test]
fn required_launch_without_supervisor_fails_before_default_spawn() {
    let default_spawn_called = Cell::new(false);

    let error = spawn_chrome_process(spec(), None, true, |_| {
        default_spawn_called.set(true);
        panic!("required launches must never fall back to an ordinary spawn");
    })
    .err()
    .expect("required launch without a supervisor must fail closed");

    assert!(error.contains("requires a browser process supervisor"));
    assert!(!default_spawn_called.get());
}

struct RejectingSupervisor;

impl BrowserSpawnSupervisor for RejectingSupervisor {
    fn preflight(&self, _spec: &BrowserLaunchSpec) -> Result<(), String> {
        Ok(())
    }

    fn spawn(&self, _spec: BrowserLaunchSpec) -> Result<Box<dyn BrowserChildProcess>, String> {
        Err("native network confinement is unavailable".to_owned())
    }
}

struct UnsupportedSupervisor;

impl BrowserSpawnSupervisor for UnsupportedSupervisor {
    fn preflight(&self, _spec: &BrowserLaunchSpec) -> Result<(), String> {
        Err("inherited control pipes are unavailable on this platform".to_owned())
    }

    fn spawn(&self, _spec: BrowserLaunchSpec) -> Result<Box<dyn BrowserChildProcess>, String> {
        panic!("unsupported requirements must be rejected before process creation");
    }
}

#[test]
fn launch_spec_debug_redacts_arguments_and_environment_values() {
    let debug = format!("{:?}", spec());

    assert!(!debug.contains("top-secret"));
    assert!(debug.contains("argument_count"));
    assert!(debug.contains("environment_keys"));
    assert!(debug.contains("InheritedPipe"));
}

#[test]
fn windows_pipe_switch_names_exact_distinct_inherited_handles() {
    let spec = BrowserLaunchSpec::new(
        PathBuf::from("chrome.exe"),
        vec!["--remote-debugging-io-pipes".to_owned()],
        Vec::new(),
        true,
        BrowserControlTransport::InheritedPipe,
    );
    assert_eq!(
        spec.args_for_windows_pipe_handles(123, 456).unwrap(),
        vec!["--remote-debugging-io-pipes=123,456"]
    );
    assert!(spec.args_for_windows_pipe_handles(0, 456).is_err());
    assert!(spec.args_for_windows_pipe_handles(123, 123).is_err());
}

#[test]
fn configured_supervisor_failure_never_falls_back_to_default_spawn() {
    let default_spawn_called = Cell::new(false);

    let error = spawn_chrome_process(spec(), Some(Arc::new(RejectingSupervisor)), false, |_| {
        default_spawn_called.set(true);
        panic!("configured supervisor failures must not downgrade to an ordinary spawn");
    })
    .err()
    .expect("supervisor failure must be returned");

    assert!(error.contains("native network confinement is unavailable"));
    assert!(!default_spawn_called.get());
}

#[test]
fn unsupported_control_transport_fails_in_preflight_before_spawn() {
    let default_spawn_called = Cell::new(false);

    let error = spawn_chrome_process(spec(), Some(Arc::new(UnsupportedSupervisor)), true, |_| {
        default_spawn_called.set(true);
        panic!("unsupported control pipes must not fall back to WebSocket");
    })
    .err()
    .expect("unsupported transport must fail closed");

    assert!(error.contains("inherited control pipes are unavailable"));
    assert!(!default_spawn_called.get());
}

#[test]
fn optional_supervision_without_provider_uses_the_standard_spawn_path() {
    let default_spawn_called = Cell::new(false);

    let error = spawn_chrome_process(spec(), None, false, |_| {
        default_spawn_called.set(true);
        Err("ordinary spawn reached".to_owned())
    })
    .err()
    .expect("test default spawner reports its invocation");

    assert_eq!(error, "ordinary spawn reached");
    assert!(default_spawn_called.get());
}
