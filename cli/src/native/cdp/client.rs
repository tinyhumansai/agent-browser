use std::collections::HashMap;
use std::io::Write;
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::BoxStream;
use futures_util::{SinkExt, StreamExt};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

use super::process::{
    write_control_message_async, BrowserControlPipe, BrowserControlPipeControl,
    BrowserControlPipeReader,
};
use super::types::{CdpCommand, CdpError, CdpEvent, CdpMessage};

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<CdpMessage>>>>;
type WsTx = Arc<
    Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
    >,
>;

/// Sessions whose events go to one private receiver instead of the broadcast.
type PrivateSessions = Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<CdpEvent>>>>;
type PipeTx = Arc<Mutex<Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>>;

struct TransportParts {
    ws_tx: Option<WsTx>,
    pipe_tx: Option<PipeTx>,
    pipe_control: Option<Arc<dyn BrowserControlPipeControl>>,
    socket: Option<socket2::Socket>,
}

struct PipeWriteCancelGuard {
    control: Arc<dyn BrowserControlPipeControl>,
    closed: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for PipeWriteCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.closed.store(true, Ordering::SeqCst);
            self.control.shutdown();
        }
    }
}

/// Events buffered for a private session receiver that has fallen behind.
/// Newer events are dropped once it is full; a screencast consumer that
/// cannot keep up should lose frames, not stall the reader.
const PRIVATE_SESSION_BUFFER: usize = 16;

/// Lossless taps for events that must each get a reply (paused requests,
/// auth challenges, targets waiting for the debugger). Unlike the bounded
/// broadcast, a tap never drops an event when its reader falls behind.
type MethodTaps =
    Arc<std::sync::Mutex<Vec<(&'static [&'static str], mpsc::UnboundedSender<CdpEvent>)>>>;

/// Interval between WebSocket ping frames sent to keep the connection alive
/// through intermediate proxies (reverse proxies, load balancers, service meshes).
const WS_KEEPALIVE_INTERVAL_SECS: u64 = 30;
const TRANSPORT_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);
const PIPE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_CLOSED_ERROR: &str = "CDP connection closed";

fn normalize_websocket_root_path(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|index| index + 3) else {
        return url.to_string();
    };
    let authority = &url[scheme_end..];
    let Some(query_offset) = authority.find('?') else {
        return url.to_string();
    };
    if authority[..query_offset].contains('/') {
        return url.to_string();
    }
    let query_index = scheme_end + query_offset;
    format!("{}/{}", &url[..query_index], &url[query_index..])
}

/// Raw incoming CDP message (text) broadcast to all subscribers.
/// Used by the inspect proxy to forward responses and events to DevTools.
#[derive(Debug, Clone)]
pub struct RawCdpMessage {
    pub text: String,
    pub session_id: Option<String>,
}

#[derive(Deserialize)]
struct CdpIdEnvelope {
    id: Option<u64>,
    #[serde(rename = "result")]
    _result: Option<IgnoredAny>,
    #[serde(rename = "error")]
    _error: Option<IgnoredAny>,
    #[serde(rename = "method")]
    _method: Option<IgnoredAny>,
    #[serde(rename = "params")]
    _params: Option<IgnoredAny>,
    #[serde(rename = "sessionId")]
    _session_id: Option<IgnoredAny>,
}

fn sanitize_lone_surrogates(msg: &str) -> Option<String> {
    const ESCAPE_LEN: usize = 6;
    const HIGH_START: u32 = 0xD800;
    const LOW_START: u32 = 0xDC00;
    const SURROGATE_END: u32 = 0xE000;

    let read_escape = |bytes: &[u8], at: usize| -> Option<u32> {
        let end = at.checked_add(ESCAPE_LEN)?;
        if end > bytes.len() || bytes[at] != b'\\' || bytes[at + 1] != b'u' {
            return None;
        }
        let hex = &bytes[at + 2..end];
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
    };

    let bytes = msg.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] != b'u' {
            i += 2;
            continue;
        }

        let Some(unit) = read_escape(bytes, i) else {
            i += 1;
            continue;
        };

        let is_high = (HIGH_START..LOW_START).contains(&unit);
        let is_low = (LOW_START..SURROGATE_END).contains(&unit);
        let paired = is_high
            && read_escape(bytes, i + ESCAPE_LEN)
                .is_some_and(|next| (LOW_START..SURROGATE_END).contains(&next));

        if paired {
            i += ESCAPE_LEN * 2;
            continue;
        }

        if is_high || is_low {
            let buf = out.get_or_insert_with(String::new);
            buf.push_str(&msg[copied..i]);
            buf.push(char::REPLACEMENT_CHARACTER);
            copied = i + ESCAPE_LEN;
        }
        i += ESCAPE_LEN;
    }

    if let Some(buf) = out.as_mut() {
        buf.push_str(&msg[copied..]);
    }

    out
}

fn extract_command_id(msg: &str) -> Option<u64> {
    let envelope: CdpIdEnvelope = serde_json::from_str(msg).ok()?;
    envelope.id.filter(|id| *id > 0)
}

pub struct CdpClient {
    ws_tx: Option<WsTx>,
    pipe_tx: Option<PipeTx>,
    pipe_control: Option<Arc<dyn BrowserControlPipeControl>>,
    socket: Option<socket2::Socket>,
    closed: Arc<AtomicBool>,
    close_complete: AtomicBool,
    close_lock: Mutex<()>,
    cancel_tx: watch::Sender<bool>,
    next_id: AtomicU64,
    pending: PendingMap,
    event_tx: broadcast::Sender<CdpEvent>,
    raw_tx: broadcast::Sender<RawCdpMessage>,
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    keepalive_handle: Mutex<Option<JoinHandle<()>>>,
    private_sessions: PrivateSessions,
    stealth: AtomicBool,
    method_taps: MethodTaps,
}

/// Removes a pending entry if `send_command` is cancelled mid-await (e.g. an
/// outer timeout on the liveness probe), so a command whose response never
/// comes can't leak until the connection closes (#1528). Normal exits disarm
/// it via `done`.
struct PendingGuard {
    pending: PendingMap,
    id: u64,
    done: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let pending = self.pending.clone();
        let id = self.id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}

impl CdpClient {
    pub fn is_pipe_transport(&self) -> bool {
        self.pipe_tx.is_some()
    }

    pub async fn connect(url: &str) -> Result<Self, String> {
        Self::connect_with_headers(url, None).await
    }

    pub async fn connect_with_headers(
        url: &str,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<Self, String> {
        let normalized_url = normalize_websocket_root_path(url);
        let mut request = normalized_url
            .as_str()
            .into_client_request()
            .map_err(|e| format!("Invalid WebSocket URL: {}", e))?;

        if let Some(hdrs) = headers {
            let req_headers = request.headers_mut();
            for (key, value) in hdrs {
                if let (Ok(name), Ok(val)) = (
                    key.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>(),
                    value.parse::<tokio_tungstenite::tungstenite::http::header::HeaderValue>(),
                ) {
                    req_headers.insert(name, val);
                }
            }
        }

        let ws_config = WebSocketConfig {
            max_message_size: None,
            max_frame_size: None,
            ..Default::default()
        };

        Self::connect_request(request, ws_config, None).await
    }

    /// Connect to Chromium's inherited NUL-framed DevTools pipe. The pipe
    /// endpoints use cancellable asynchronous IO; all CDP response and event
    /// dispatch remains on the same async path as WebSocket connections.
    pub async fn connect_pipe(pipe: BrowserControlPipe) -> Result<Self, String> {
        let (reader, writer, control) = pipe.into_parts();
        let reader = BrowserControlPipeReader::new(reader);
        let incoming = Box::pin(futures_util::stream::unfold(
            (reader, false),
            |(mut reader, done)| async move {
                if done {
                    return None;
                }
                match reader.read_message().await {
                    Ok(Some(bytes)) => {
                        let message =
                            String::from_utf8(bytes)
                                .map(Message::Text)
                                .map_err(|error| {
                                    format!("invalid UTF-8 from Chromium CDP pipe: {error}")
                                });
                        Some((message, (reader, false)))
                    }
                    Ok(None) => None,
                    Err(error) => Some((
                        Err(format!("failed to read Chromium CDP pipe: {error}")),
                        (reader, true),
                    )),
                }
            },
        ));
        Self::from_transport(
            TransportParts {
                ws_tx: None,
                pipe_tx: Some(Arc::new(Mutex::new(Some(writer)))),
                pipe_control: Some(control),
                socket: None,
            },
            incoming,
            false,
        )
        .await
    }

    async fn connect_request(
        request: Request<()>,
        ws_config: WebSocketConfig,
        connector: Option<Connector>,
    ) -> Result<Self, String> {
        let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(ws_config),
            false,
            connector,
        )
        .await
        .map_err(|e| format!("CDP WebSocket connect failed: {}", e))?;

        enable_tcp_keepalive(ws_stream.get_ref());
        let tcp_stream = underlying_tcp_stream(ws_stream.get_ref())
            .ok_or_else(|| "Unsupported CDP stream type".to_string())?;
        let socket = socket2::SockRef::from(tcp_stream)
            .try_clone()
            .map_err(|error| format!("Failed to duplicate CDP socket: {}", error))?;

        let (ws_tx, ws_rx) = ws_stream.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        let incoming = Box::pin(ws_rx.map(|message| message.map_err(|error| error.to_string())));
        Self::from_transport(
            TransportParts {
                ws_tx: Some(ws_tx),
                pipe_tx: None,
                pipe_control: None,
                socket: Some(socket),
            },
            incoming,
            true,
        )
        .await
    }

    async fn from_transport(
        parts: TransportParts,
        mut ws_rx: BoxStream<'static, Result<Message, String>>,
        websocket_keepalive: bool,
    ) -> Result<Self, String> {
        let TransportParts {
            ws_tx,
            pipe_tx,
            pipe_control,
            socket,
        } = parts;
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _) = broadcast::channel(4096);
        let (raw_tx, _) = broadcast::channel(4096);
        let closed = Arc::new(AtomicBool::new(false));

        let private_sessions: PrivateSessions = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let method_taps: MethodTaps = Arc::new(std::sync::Mutex::new(Vec::new()));

        let pending_clone = pending.clone();
        let event_tx_clone = event_tx.clone();
        let raw_tx_clone = raw_tx.clone();
        let closed_reader = closed.clone();
        let private_clone = private_sessions.clone();
        let taps_clone = method_taps.clone();

        // Notify used to stop the keepalive task when the reader loop exits.
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let reader_cancel_tx = cancel_tx.clone();

        let reader_handle = tokio::spawn(async move {
            while let Some(msg) = ws_rx.next().await {
                // Accept both Text and Binary frames — remote CDP proxies
                // (e.g. Browserless) may send responses as Binary frames.
                let msg = match msg {
                    Ok(Message::Text(text)) => text,
                    Ok(Message::Binary(data)) => match String::from_utf8(data) {
                        Ok(text) => text,
                        Err(_) => continue,
                    },
                    Ok(Message::Close(frame)) => {
                        if std::env::var("AGENT_BROWSER_DEBUG").is_ok() {
                            let reason = frame
                                .as_ref()
                                .map(|f| format!("code={}, reason={}", f.code, f.reason))
                                .unwrap_or_else(|| "no frame".to_string());
                            let _ =
                                writeln!(std::io::stderr(), "[cdp] WebSocket Close: {}", reason);
                        }
                        break;
                    }
                    Ok(Message::Pong(_)) => continue,
                    Ok(_) => continue,
                    Err(e) => {
                        if std::env::var("AGENT_BROWSER_DEBUG").is_ok() {
                            let _ = writeln!(std::io::stderr(), "[cdp] WebSocket Error: {}", e);
                        }
                        break;
                    }
                };

                // Broadcast raw message for inspect proxy subscribers before typed parse,
                // so messages with negative IDs (used by the inspect proxy) are still delivered.
                if raw_tx_clone.receiver_count() > 0 {
                    let session_id = serde_json::from_str::<serde_json::Value>(&msg)
                        .ok()
                        .and_then(|v| v.get("sessionId")?.as_str().map(String::from));
                    let _ = raw_tx_clone.send(RawCdpMessage {
                        text: msg.clone(),
                        session_id,
                    });
                }

                let parsed: CdpMessage = match serde_json::from_str(&msg) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        let repaired = sanitize_lone_surrogates(&msg);
                        let candidate = repaired.as_deref().unwrap_or(&msg);
                        match serde_json::from_str(candidate) {
                            Ok(parsed) => parsed,
                            Err(error) => {
                                if let Some(id) = extract_command_id(candidate) {
                                    let waiter = pending_clone.lock().await.remove(&id);
                                    if let Some(tx) = waiter {
                                        let _ = tx.send(CdpMessage {
                                            id: Some(id),
                                            result: None,
                                            error: Some(CdpError {
                                                code: None,
                                                message: format!(
                                                    "Malformed CDP response: {}",
                                                    error
                                                ),
                                                data: None,
                                            }),
                                            method: None,
                                            params: None,
                                            session_id: None,
                                        });
                                    }
                                }
                                continue;
                            }
                        }
                    }
                };

                if let Some(id) = parsed.id {
                    // Response to a command
                    let mut pending = pending_clone.lock().await;
                    if let Some(tx) = pending.remove(&id) {
                        let _ = tx.send(parsed);
                    }
                } else if let Some(ref method) = parsed.method {
                    // Event
                    let event = CdpEvent {
                        method: method.clone(),
                        params: parsed.params.clone().unwrap_or(Value::Null),
                        session_id: parsed.session_id.clone(),
                    };
                    let routed = event.session_id.as_deref().is_some_and(|sid| {
                        let mut routes = private_clone.lock().unwrap_or_else(|e| e.into_inner());
                        match routes.get(sid) {
                            Some(tx) => match tx.try_send(event.clone()) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    routes.remove(sid);
                                    false
                                }
                            },
                            None => false,
                        }
                    });
                    if !routed {
                        let mut taps = taps_clone.lock().unwrap_or_else(|e| e.into_inner());
                        taps.retain(|(methods, tx)| {
                            !methods.contains(&event.method.as_str())
                                || tx.send(event.clone()).is_ok()
                        });
                        drop(taps);
                        let _ = event_tx_clone.send(event);
                    }
                }
            }

            // Reader loop exited (connection closed or error). Drop all pending
            // command senders so callers get an immediate channel-closed error
            // instead of waiting for the 30-second timeout.
            closed_reader.store(true, Ordering::SeqCst);
            pending_clone.lock().await.clear();

            // Stop the keepalive task because the connection is gone.
            let _ = reader_cancel_tx.send(true);
        });

        // Spawn a keepalive task that sends WebSocket Ping frames at a regular
        // interval. This prevents intermediate proxies (Envoy, nginx, OpenResty,
        // cloud load balancers) from closing idle WebSocket connections. If the
        // send fails, the connection is dead and we stop pinging.
        let keepalive_handle = if websocket_keepalive {
            let keepalive_tx = ws_tx.clone().expect("WebSocket transport has a sink");
            let closed_keepalive = closed.clone();
            Some(tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(WS_KEEPALIVE_INTERVAL_SECS);
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {}
                        _ = cancel_rx.changed() => break,
                    }
                    let mut tx = keepalive_tx.lock().await;
                    if closed_keepalive.load(Ordering::SeqCst) {
                        break;
                    }
                    if tx.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }))
        } else {
            None
        };

        Ok(Self {
            ws_tx,
            pipe_tx,
            pipe_control,
            socket,
            closed,
            close_complete: AtomicBool::new(false),
            close_lock: Mutex::new(()),
            cancel_tx,
            next_id: AtomicU64::new(1),
            pending,
            event_tx,
            raw_tx,
            reader_handle: Mutex::new(Some(reader_handle)),
            keepalive_handle: Mutex::new(keepalive_handle),
            private_sessions,
            stealth: AtomicBool::new(false),
            method_taps,
        })
    }

    /// Stealth connections never write `Runtime.enable`. It is the call
    /// detection scripts look for: it makes the browser serialise console
    /// arguments, which a page can observe. Commands that need no Runtime
    /// domain state, such as `Runtime.evaluate` and `Runtime.callFunctionOn`,
    /// work without it.
    pub fn set_stealth(&self, stealth: bool) {
        self.stealth.store(stealth, Ordering::SeqCst);
    }

    /// True for `Runtime.enable` on a stealth connection, which is dropped
    /// and reported as done.
    fn withheld(&self, method: &str) -> bool {
        method == "Runtime.enable" && self.stealth.load(Ordering::SeqCst)
    }

    fn ensure_open(&self) -> Result<(), String> {
        if self.closed.load(Ordering::SeqCst) {
            Err(CONNECTION_CLOSED_ERROR.to_string())
        } else {
            Ok(())
        }
    }

    async fn send_transport_text(&self, text: String) -> Result<(), String> {
        self.ensure_open()?;
        if let Some(ws_tx) = &self.ws_tx {
            return ws_tx
                .lock()
                .await
                .send(Message::Text(text))
                .await
                .map_err(|error| format!("Failed to send CDP command: {error}"));
        }
        let Some(pipe_tx) = &self.pipe_tx else {
            return Err(CONNECTION_CLOSED_ERROR.to_owned());
        };
        let pipe_tx = pipe_tx.clone();
        let mut cancel = PipeWriteCancelGuard {
            control: self
                .pipe_control
                .as_ref()
                .expect("pipe has cancellation control")
                .clone(),
            closed: self.closed.clone(),
            armed: true,
        };
        let result = tokio::time::timeout(PIPE_WRITE_TIMEOUT, async {
            let mut pipe = pipe_tx.lock().await;
            let writer = pipe
                .as_mut()
                .ok_or_else(|| CONNECTION_CLOSED_ERROR.to_owned())?;
            write_control_message_async(&mut **writer, text.as_bytes())
                .await
                .map_err(|error| format!("Failed to write CDP pipe command: {error}"))
        })
        .await
        .map_err(|_| "timed out writing CDP command to Chromium pipe".to_owned())?;
        if result.is_ok() {
            cancel.armed = false;
        }
        result
    }

    async fn abort_task(handle: &Mutex<Option<JoinHandle<()>>>) {
        let Some(task) = handle.lock().await.take() else {
            return;
        };
        task.abort();
        let _ = tokio::time::timeout(TRANSPORT_CLOSE_TIMEOUT, task).await;
    }

    pub async fn close(&self) {
        let _close_guard = self.close_lock.lock().await;
        if self.close_complete.load(Ordering::SeqCst) {
            return;
        }
        self.closed.store(true, Ordering::SeqCst);

        let _ = self.cancel_tx.send(true);
        Self::abort_task(&self.keepalive_handle).await;

        if let Some(ws_tx) = &self.ws_tx {
            let _ = tokio::time::timeout(TRANSPORT_CLOSE_TIMEOUT, async {
                let mut ws_tx = ws_tx.lock().await;
                let _ = ws_tx.close().await;
            })
            .await;
        }

        if let Some(socket) = &self.socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(control) = &self.pipe_control {
            control.shutdown();
        }
        if let Some(pipe_tx) = &self.pipe_tx {
            pipe_tx.lock().await.take();
        }
        Self::abort_task(&self.reader_handle).await;
        self.pending.lock().await.clear();
        self.close_complete.store(true, Ordering::SeqCst);
    }

    pub async fn send_command(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
    ) -> Result<Value, String> {
        if self.withheld(method) {
            return Ok(Value::Null);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let cmd = CdpCommand {
            id,
            method: method.to_string(),
            params,
            session_id: session_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        };

        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize CDP command: {}", e))?;

        let (tx, rx) = oneshot::channel();

        // Cleans up the pending entry if this future is cancelled mid-await (#1528).
        let mut guard = PendingGuard {
            pending: self.pending.clone(),
            id,
            done: false,
        };

        {
            self.ensure_open()?;
            let mut pending = self.pending.lock().await;
            pending.insert(id, tx);
            drop(pending);
            if let Err(error) = self.send_transport_text(json).await {
                self.pending.lock().await.remove(&id);
                guard.done = true;
                return Err(error);
            }
        }

        let response = match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(resp)) => {
                guard.done = true;
                resp
            }
            Ok(Err(_)) => {
                guard.done = true;
                return Err("CDP response channel closed".to_string());
            }
            Err(_) => {
                guard.done = true;
                self.pending.lock().await.remove(&id);
                return Err(format!("CDP command timed out: {}", method));
            }
        };

        if let Some(error) = response.error {
            return Err(format!("CDP error ({}): {}", method, error));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.event_tx.subscribe()
    }

    /// Deliver every event whose method is in `methods` to the returned
    /// receiver without loss. The events still reach the broadcast. Dropping
    /// the receiver ends the tap on the next matching event.
    pub fn subscribe_methods(
        &self,
        methods: &'static [&'static str],
    ) -> mpsc::UnboundedReceiver<CdpEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.method_taps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((methods, tx));
        rx
    }

    /// Deliver every event carrying `session_id` to the returned receiver
    /// instead of the broadcast, so a high-volume session (a screencast) is
    /// neither cloned to every subscriber nor able to overflow their buffers.
    /// Events without a session id are unaffected. Call
    /// [`unsubscribe_session`](Self::unsubscribe_session) when done; a dropped
    /// receiver also ends the route on the next event for that session.
    pub fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<CdpEvent> {
        let (tx, rx) = mpsc::channel(PRIVATE_SESSION_BUFFER);
        self.private_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id.to_string(), tx);
        rx
    }

    pub fn unsubscribe_session(&self, session_id: &str) {
        self.private_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session_id);
    }

    /// Subscribe to all raw incoming CDP messages (responses + events).
    /// Used by the inspect proxy to forward traffic to the DevTools frontend.
    pub fn subscribe_raw(&self) -> broadcast::Receiver<RawCdpMessage> {
        self.raw_tx.subscribe()
    }

    /// Create a lightweight handle for the inspect WebSocket proxy.
    /// Contains only what's needed to forward messages bidirectionally.
    pub fn inspect_handle(&self) -> InspectProxyHandle {
        InspectProxyHandle {
            ws_tx: self.ws_tx.clone(),
            raw_tx: self.raw_tx.clone(),
            closed: self.closed.clone(),
        }
    }

    pub async fn send_command_typed<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        session_id: Option<&str>,
    ) -> Result<R, String> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| format!("Failed to serialize params: {}", e))?;
        let result = self
            .send_command(method, Some(params_value), session_id)
            .await?;
        serde_json::from_value(result)
            .map_err(|e| format!("Failed to deserialize CDP response for {}: {}", method, e))
    }

    pub async fn send_command_no_params(
        &self,
        method: &str,
        session_id: Option<&str>,
    ) -> Result<Value, String> {
        self.send_command(method, None, session_id).await
    }

    /// Send a CDP command without waiting for its response.
    ///
    /// This is useful for best-effort commands where Chrome may not emit a
    /// response for every target session, but the command still needs to be
    /// written before the caller can continue processing events.
    pub async fn send_command_no_wait(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
    ) -> Result<(), String> {
        if self.withheld(method) {
            return Ok(());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let cmd = CdpCommand {
            id,
            method: method.to_string(),
            params,
            session_id: session_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        };

        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize CDP command: {}", e))?;

        self.send_transport_text(json).await
    }

    /// Send raw JSON through the WebSocket without tracking a response.
    /// Used by the inspect proxy to forward DevTools frontend messages.
    pub async fn send_raw(&self, json: String) -> Result<(), String> {
        if self.pipe_tx.is_some() {
            return Err("raw CDP forwarding is unavailable for inherited-pipe sessions".to_owned());
        }
        self.send_transport_text(json).await.map_err(|error| {
            error.replace(
                "Failed to send CDP command",
                "Failed to send raw CDP message",
            )
        })
    }

    /// Test-only: count of in-flight commands still awaiting a response, so a
    /// test can assert a cancelled command left no orphaned entry (#1528).
    #[cfg(test)]
    pub(crate) async fn pending_len(&self) -> usize {
        self.pending.lock().await.len()
    }
}

/// Lightweight handle for the inspect WebSocket proxy, holding only
/// the cloneable parts of CdpClient needed for bidirectional message forwarding.
pub struct InspectProxyHandle {
    ws_tx: Option<WsTx>,
    raw_tx: broadcast::Sender<RawCdpMessage>,
    closed: Arc<AtomicBool>,
}

impl InspectProxyHandle {
    pub async fn send_raw(&self, json: String) -> Result<(), String> {
        let Some(ws_tx) = &self.ws_tx else {
            return Err(
                "inspect WebSocket proxy is unavailable for inherited-pipe sessions".to_owned(),
            );
        };
        let mut ws_tx = ws_tx.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(CONNECTION_CLOSED_ERROR.to_string());
        }
        ws_tx
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send raw CDP message: {}", e))
    }

    pub fn subscribe_raw(&self) -> broadcast::Receiver<RawCdpMessage> {
        self.raw_tx.subscribe()
    }
}

/// Enable TCP SO_KEEPALIVE on the underlying socket of a WebSocket connection.
/// This is best-effort: failures are silently ignored since the WebSocket-level
/// Ping keepalive provides the primary connection liveness mechanism.
fn enable_tcp_keepalive(stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>) {
    let Some(tcp_stream) = underlying_tcp_stream(stream) else {
        return;
    };

    // SockRef borrows the fd without taking ownership.
    let sock = socket2::SockRef::from(tcp_stream);
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(30));

    // with_interval sets TCP_KEEPINTVL — the time between probes after the
    // first keepalive probe goes unanswered. Available on most platforms
    // (Linux, macOS, Windows, FreeBSD, etc.) but not OpenBSD or Haiku.
    #[cfg(not(any(target_os = "openbsd", target_os = "haiku")))]
    let keepalive = keepalive.with_interval(std::time::Duration::from_secs(10));

    let _ = sock.set_tcp_keepalive(&keepalive);
}

fn underlying_tcp_stream(
    stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
) -> Option<&tokio::net::TcpStream> {
    match stream {
        tokio_tungstenite::MaybeTlsStream::Plain(stream) => Some(stream),
        tokio_tungstenite::MaybeTlsStream::Rustls(stream) => Some(stream.get_ref().0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::json;
    use std::io::Read;
    use std::net::TcpListener as StdTcpListener;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[cfg(unix)]
    #[tokio::test]
    async fn inherited_pipe_dispatches_cdp_and_closes_after_child_eof() {
        use crate::native::cdp::process::{
            write_control_message_async, BrowserControlPipe, BrowserControlPipeControl,
            BrowserControlPipeReader,
        };
        use tokio::net::UnixStream;

        struct PipeControl;
        impl BrowserControlPipeControl for PipeControl {
            fn shutdown(&self) {}
        }

        let (client_side, child_side) = UnixStream::pair().unwrap();
        let (client_reader, client_writer) = client_side.into_split();
        let (child_reader, mut child_writer) = child_side.into_split();
        let control = Arc::new(PipeControl);
        let child = tokio::spawn(async move {
            let request = BrowserControlPipeReader::new(Box::new(child_reader))
                .read_message()
                .await
                .unwrap()
                .unwrap();
            let request: Value = serde_json::from_slice(&request).unwrap();
            let response = serde_json::json!({
                "id": request["id"],
                "result": { "product": "Chrome/pipe-test" }
            });
            write_control_message_async(&mut child_writer, response.to_string().as_bytes())
                .await
                .unwrap();
        });

        let client = CdpClient::connect_pipe(BrowserControlPipe::new(
            Box::new(client_reader),
            Box::new(client_writer),
            control,
        ))
        .await
        .unwrap();
        assert!(client.is_pipe_transport());
        let version = client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(version["product"], "Chrome/pipe-test");
        child.await.unwrap();
        client.close().await;
    }

    #[tokio::test]
    async fn cancelled_full_pipe_write_closes_transport_and_allows_bounded_close() {
        use crate::native::cdp::process::{BrowserControlPipe, BrowserControlPipeControl};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PipeControl(AtomicBool);
        impl BrowserControlPipeControl for PipeControl {
            fn shutdown(&self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (client_stream, peer_stream) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(client_stream);
        let control = Arc::new(PipeControl(AtomicBool::new(false)));
        let client = CdpClient::connect_pipe(BrowserControlPipe::new(
            Box::new(reader),
            Box::new(writer),
            control.clone(),
        ))
        .await
        .unwrap();

        {
            let write = client.send_transport_text("x".repeat(1024));
            tokio::pin!(write);
            tokio::select! {
                _ = &mut write => panic!("the fixture writer must remain blocked"),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }

        assert!(control.0.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(1), client.close())
            .await
            .expect("close must release the pipe after caller cancellation");
        drop(peer_stream);
    }

    const TEST_CERT_DER: &str = "MIIBPDCB46ADAgECAgkA9xwXmIhbzQIwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgzMDA1NTU0NFoXDTM2MDgyNzA1NTU0NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQdmPO0sXXFRmVn7+8MViXGom2rYy8aV3Oc0pNZhUmFGaPl4MRFzc1G0yaV/WRBPF/BUh2LGsXCvUsn7NqaYkFaMeMBwwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIQC32oureGNAupABEmonQPAQBD7OdJjXmUxoVQNr0UB+6AIgb23GMwxTjwHyLG4tZcJST7r3cCW8K/Y+1h618j2f+Uw=";
    const TEST_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIVZST8Vhc5f3OW+4kF78f8o1nQCRwjW/Yo8CXQ35Y9uhRANCAARB2Y87SxdcVGZWfv7wxWJcaibatjLxpXc5zSk1mFSYUZo+XgxEXNzUbTJpX9ZEE8X8FSHYsaxcK9Syfs2ppiQV";

    #[test]
    fn repairs_only_unpaired_surrogate_escapes() {
        let msg = r#"{"id":1,"result":{"high":"\ud800","low":"\udfff","pair":"\ud83d\ude00","escaped":"\\ud800","text":"café 中文"}}"#;
        let repaired = sanitize_lone_surrogates(msg).expect("lone surrogates should be repaired");
        let parsed: CdpMessage = serde_json::from_str(&repaired).expect("repaired message");
        let result = parsed.result.expect("result");

        assert_eq!(result["high"], "\u{fffd}");
        assert_eq!(result["low"], "\u{fffd}");
        assert_eq!(result["pair"], "😀");
        assert_eq!(result["escaped"], r"\ud800");
        assert_eq!(result["text"], "café 中文");
    }

    #[test]
    fn extracts_only_positive_top_level_command_ids() {
        assert_eq!(
            extract_command_id(r#"{"id":7,"result":{"value":"\ud800"}}"#),
            Some(7)
        );
        assert_eq!(
            extract_command_id(r#"{"result":{"id":42,"value":"\ud800"}}"#),
            None
        );
        assert_eq!(
            extract_command_id(r#"{"id":-1,"result":{"value":"\ud800"}}"#),
            None
        );
        assert_eq!(
            extract_command_id(r#"{"method":"Fetch.requestPaused","params":{"value":"\ud800"}}"#),
            None
        );
        assert_eq!(extract_command_id(r#"{"id":0,"result":{}}"#), None);
    }

    /// Serves one connection and returns every method it was sent, in order,
    /// answering each with an empty result.
    async fn record_methods(listener: TcpListener, count: usize) -> Vec<String> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut methods = Vec::new();
        while methods.len() < count {
            let text = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let command: Value = serde_json::from_str(&text).unwrap();
            methods.push(command["method"].as_str().unwrap().to_string());
            let id = command["id"].as_u64().unwrap();
            ws.send(Message::Text(json!({"id": id, "result": {}}).to_string()))
                .await
                .unwrap();
        }
        methods
    }

    #[tokio::test]
    async fn stealth_connection_never_writes_runtime_enable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(record_methods(listener, 2));

        let client = CdpClient::connect(&url).await.unwrap();
        client.set_stealth(true);
        client
            .send_command_no_params("Runtime.enable", Some("s1"))
            .await
            .unwrap();
        client
            .send_command_no_wait("Runtime.enable", None, Some("s1"))
            .await
            .unwrap();
        client
            .send_command_no_params("Page.enable", Some("s1"))
            .await
            .unwrap();
        client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();

        assert_eq!(
            server.await.unwrap(),
            ["Page.enable", "Browser.getVersion"],
            "Runtime.enable must not reach the wire"
        );
        client.close().await;
    }

    #[tokio::test]
    async fn connection_without_stealth_writes_runtime_enable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(record_methods(listener, 2));

        let client = CdpClient::connect(&url).await.unwrap();
        client
            .send_command_no_params("Runtime.enable", Some("s1"))
            .await
            .unwrap();
        client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();

        assert_eq!(
            server.await.unwrap(),
            ["Runtime.enable", "Browser.getVersion"]
        );
        client.close().await;
    }

    #[tokio::test]
    async fn repairs_response_and_event_then_processes_next_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let first_id = serde_json::from_str::<Value>(&first).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"id":{first_id},"result":{{"value":"\ud800"}}}}"#
            )))
            .await
            .unwrap();
            ws.send(Message::Text(
                r#"{"method":"Fetch.requestPaused","params":{"requestId":"r1","request":{"url":"https://example.test/\udfff"}},"sessionId":"s1"}"#.to_string(),
            ))
            .await
            .unwrap();

            let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let second_id = serde_json::from_str::<Value>(&second).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(
                json!({"id": second_id, "result": {"value": "ok"}}).to_string(),
            ))
            .await
            .unwrap();
        });

        let client = CdpClient::connect(&url).await.unwrap();
        let mut events = client.subscribe();

        let first = tokio::time::timeout(
            Duration::from_secs(1),
            client.send_command_no_params("Accessibility.getFullAXTree", None),
        )
        .await
        .expect("surrogate response should complete")
        .unwrap();
        assert_eq!(first["value"], "\u{fffd}");

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("surrogate event should arrive")
            .unwrap();
        assert_eq!(event.method, "Fetch.requestPaused");
        assert_eq!(
            event.params["request"]["url"],
            "https://example.test/\u{fffd}"
        );

        let second = client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(second["value"], "ok");

        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_response_fails_only_its_top_level_pending_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let first_id = serde_json::from_str::<Value>(&first).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"id":{first_id},"result":{{"value":"\ud800"}},"method":42}}"#
            )))
            .await
            .unwrap();

            let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let second_id = serde_json::from_str::<Value>(&second).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"result":{{"id":{second_id},"value":"\ud800"}},"method":42}}"#
            )))
            .await
            .unwrap();
            ws.send(Message::Text(
                json!({"id": second_id, "result": {"value": "still-open"}}).to_string(),
            ))
            .await
            .unwrap();
        });

        let client = CdpClient::connect(&url).await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            client.send_command_no_params("Broken.response", None),
        )
        .await
        .expect("malformed response should not time out")
        .unwrap_err();
        assert!(error.contains("Malformed CDP response"), "{error}");

        let result = client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(result["value"], "still-open");

        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn close_releases_pending_and_rejects_all_write_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (command_seen_tx, command_seen_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = ws.next().await;
            let _ = command_seen_tx.send(());
            while ws.next().await.is_some() {}
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let inspect = client.inspect_handle();
        let command_client = client.clone();
        let command = tokio::spawn(async move {
            command_client
                .send_command_no_params("Never.responds", None)
                .await
        });

        command_seen_rx.await.unwrap();
        assert_eq!(client.pending_len().await, 1);
        client.close().await;

        let command_error = tokio::time::timeout(Duration::from_secs(1), command)
            .await
            .expect("pending command should be released")
            .unwrap()
            .unwrap_err();
        assert_eq!(command_error, "CDP response channel closed");
        assert_eq!(client.pending_len().await, 0);

        assert_eq!(
            client
                .send_command_no_params("Browser.getVersion", None)
                .await
                .unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            client
                .send_command_no_wait("Browser.getVersion", None, None)
                .await
                .unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            client.send_raw("{}".to_string()).await.unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            inspect.send_raw("{}".to_string()).await.unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_close_sends_close_and_forces_tcp_eof_with_inspect_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let close = tokio::time::timeout(Duration::from_secs(1), ws.next())
                .await
                .expect("server should receive close")
                .expect("stream should yield close")
                .expect("close frame should parse");
            assert!(matches!(close, Message::Close(_)));

            let mut byte = [0u8; 1];
            let count = tokio::time::timeout(Duration::from_secs(1), ws.get_mut().read(&mut byte))
                .await
                .expect("server should observe TCP shutdown")
                .expect("server TCP read should succeed");
            assert_eq!(count, 0);
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let inspect = client.inspect_handle();
        let close_a = {
            let client = client.clone();
            tokio::spawn(async move { client.close().await })
        };
        let close_b = {
            let client = client.clone();
            tokio::spawn(async move { client.close().await })
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            close_a.await.unwrap();
            close_b.await.unwrap();
            client.close().await;
        })
        .await
        .expect("concurrent close should be bounded");

        server.await.unwrap();
        drop(inspect);
    }

    #[tokio::test]
    async fn close_is_bounded_when_the_sink_is_busy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (accepted_tx, accepted_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = accepted_tx.send(());
            while ws.next().await.is_some() {}
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        accepted_rx.await.unwrap();
        let sink_guard = client.ws_tx.as_ref().unwrap().lock().await;
        let close_client = client.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            close_client.close().await;
        })
        .await
        .expect("close should not wait indefinitely for the sink");
        drop(sink_guard);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rustls_close_forces_underlying_tcp_eof() {
        let certificate = CertificateDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_CERT_DER)
                .unwrap(),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_KEY_DER)
                .unwrap(),
        ));
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)
                .unwrap(),
        );

        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let tls = rustls::StreamOwned::new(connection, stream);
            let mut ws = tokio_tungstenite::tungstenite::accept(tls).unwrap();
            assert!(matches!(ws.read().unwrap(), Message::Close(_)));

            let mut byte = [0u8; 1];
            let count = ws
                .get_mut()
                .get_mut()
                .read(&mut byte)
                .expect("server TCP read should succeed");
            assert_eq!(count, 0);
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let request = format!("wss://127.0.0.1:{port}")
            .into_client_request()
            .unwrap();
        let config = WebSocketConfig {
            max_message_size: None,
            max_frame_size: None,
            ..Default::default()
        };
        let client =
            CdpClient::connect_request(request, config, Some(Connector::Rustls(client_config)))
                .await
                .unwrap();

        client.close().await;
        server.join().unwrap();
    }

    #[test]
    fn normalizes_only_root_websocket_queries() {
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example?token=a%2Fb"),
            "wss://browser.example/?token=a%2Fb"
        );
        assert_eq!(
            normalize_websocket_root_path("ws://[::1]:9222?token=test"),
            "ws://[::1]:9222/?token=test"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://user:pass@browser.example?token=test"),
            "wss://user:pass@browser.example/?token=test"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example?"),
            "wss://browser.example/?"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example/?token=a%2Fb"),
            "wss://browser.example/?token=a%2Fb"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example/cdp?token=a%2Fb"),
            "wss://browser.example/cdp?token=a%2Fb"
        );
    }

    #[tokio::test]
    async fn root_websocket_url_with_query_sends_slash_request_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (path_tx, path_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio::io::BufReader::new(stream);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let end = line == "\r\n" || line == "\n";
                request.push_str(&line);
                if end {
                    break;
                }
            }
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_owned();
            let _ = path_tx.send(path);
            let key = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_owned())
                })
                .expect("WebSocket request contains its key");
            let accept =
                tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .unwrap();
        });

        let url = format!("ws://127.0.0.1:{}?token=a%2Fb&scope=browser%20test", port);
        let _client = CdpClient::connect(&url).await.unwrap();

        assert_eq!(path_rx.await.unwrap(), "/?token=a%2Fb&scope=browser%20test");
        server.await.unwrap();
    }
    /// Events on a privately subscribed session reach only that receiver;
    /// everything else still reaches broadcast subscribers.
    #[tokio::test]
    async fn private_session_events_bypass_the_broadcast() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ready_rx.await.unwrap();
            for (method, session) in [
                ("Page.screencastFrame", Some("S-REC")),
                ("Page.screencastFrame", Some("S-PAGE")),
                ("Target.detachedFromTarget", None),
            ] {
                let mut msg = serde_json::json!({ "method": method, "params": {} });
                if let Some(sid) = session {
                    msg["sessionId"] = serde_json::json!(sid);
                }
                ws.send(Message::Text(msg.to_string())).await.unwrap();
            }
            // Keep the connection open until the client is done reading.
            let _ = ws.next().await;
        });

        let client = CdpClient::connect(&format!("ws://127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut broadcast_rx = client.subscribe();
        let mut private_rx = client.subscribe_session("S-REC");
        ready_tx.send(()).unwrap();

        let wait = std::time::Duration::from_secs(2);
        let first = tokio::time::timeout(wait, broadcast_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.session_id.as_deref(), Some("S-PAGE"));
        let second = tokio::time::timeout(wait, broadcast_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.method, "Target.detachedFromTarget");

        let private = tokio::time::timeout(wait, private_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(private.session_id.as_deref(), Some("S-REC"));
        assert!(
            private_rx.try_recv().is_err(),
            "only S-REC events are routed privately"
        );

        client.unsubscribe_session("S-REC");
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn method_tap_keeps_every_event_when_the_broadcast_lags() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ready_rx.await.unwrap();
            for i in 0..7000 {
                let method = if i % 7 == 0 {
                    "Fetch.requestPaused"
                } else {
                    "Network.dataReceived"
                };
                let msg = serde_json::json!({ "method": method, "params": { "n": i } });
                ws.send(Message::Text(msg.to_string())).await.unwrap();
            }
            let _ = ws.next().await;
        });

        let client = CdpClient::connect(&format!("ws://127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut broadcast_rx = client.subscribe();
        let mut tap = client.subscribe_methods(&["Fetch.requestPaused"]);
        ready_tx.send(()).unwrap();

        let wait = std::time::Duration::from_secs(5);
        for expected in (0..7000).step_by(7) {
            let event = tokio::time::timeout(wait, tap.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(event.method, "Fetch.requestPaused");
            assert_eq!(event.params["n"], expected);
        }
        assert!(matches!(
            broadcast_rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));

        drop(client);
        server.abort();
    }
}
