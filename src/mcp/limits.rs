//! Deterministic input bounds for the stdio transport and tool arguments
//! (D7A hardening). Oversized stdin LINES are discarded by a streaming
//! adapter BEFORE the JSON codec ever buffers them, so memory stays
//! bounded by the adapter's fixed 8 KiB buffer regardless of line length;
//! argument-level fields carry their own typed caps. A dropped oversized
//! line never reaches the protocol layer — the server stays live and the
//! next valid line is processed normally.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// Maximum accepted JSON-RPC line: bytes before the terminating newline.
/// A line whose byte length exceeds this is dropped whole; the server
/// remains usable and stdout stays protocol-clean.
pub const MAX_MCP_LINE_BYTES: usize = 1024 * 1024;
/// Maximum `sql` argument for query/execute.
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 256 * 1024;
/// Maximum echoed `requestState` (opaque tokens are 43 base64url chars).
pub const MAX_REQUEST_STATE_BYTES: usize = 1024;
/// Maximum serialized `inputResponses` object.
pub const MAX_INPUT_RESPONSES_BYTES: usize = 64 * 1024;

/// Cap on discarded-line notices printed to stderr so a hostile sender
/// cannot spam the log; discarding itself continues unbounded.
const MAX_DROP_NOTICES: u64 = 8;

const CHUNK: usize = 8 * 1024;

/// `AsyncRead` adapter enforcing a per-line byte limit. The current line
/// is accumulated into a buffer of exactly `limit + 1` bytes BEFORE any
/// of it is emitted, so an oversized line is discarded WHOLE — including
/// its in-limit prefix, which must never reach the JSON codec (a
/// parseable prefix of an oversized line would otherwise execute). Memory
/// is bounded by the fixed limit-sized buffer no matter how long the
/// incoming line is; the excess beyond the buffer streams past through a
/// small scratch window and is dropped.
///
/// A line of exactly `limit` bytes passes with its terminator (the
/// buffer holds limit + 1 to observe the byte after the limit).
pub struct LineLimited<R> {
    inner: R,
    /// Line accumulation buffer: capacity limit + 1.
    buf: Box<[u8]>,
    /// Bytes accumulated for the current line (plus any carry-over bytes
    /// of following lines already read from upstream).
    fill: usize,
    /// Prefix of buf[0..fill] already scanned with no newline found.
    scanned: usize,
    /// Total bytes of the line being drained (fill when draining began).
    total: usize,
    phase: Phase,
    /// Scratch window used while discarding an oversized remainder.
    scratch: Box<[u8]>,
    limit: usize,
    dropped: u64,
}

#[derive(Clone, Copy)]
enum Phase {
    /// Accumulating the next line into `buf`.
    Filling,
    /// Emitting buf[drain..total] of a complete accepted line.
    Draining { drain: usize },
    /// Discarding the remainder of an oversized line up to its newline.
    Discarding,
    /// Upstream EOF reached; buffered tail (if any) already drained.
    Eof,
}

impl<R: AsyncRead> LineLimited<R> {
    pub fn new(inner: R) -> Self {
        Self::with_limit(inner, MAX_MCP_LINE_BYTES)
    }

    pub fn with_limit(inner: R, limit: usize) -> Self {
        // The discard scratch never exceeds the line buffer so that any
        // carry-over bytes after a discarded line's newline always fit.
        let scratch_len = CHUNK.min(limit + 1);
        Self {
            inner,
            buf: vec![0u8; limit + 1].into_boxed_slice(),
            fill: 0,
            scanned: 0,
            total: 0,
            phase: Phase::Filling,
            scratch: vec![0u8; scratch_len].into_boxed_slice(),
            limit,
            dropped: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LineLimited<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // tokio never polls with an empty ReadBuf; a zero-capacity buffer
        // is documented as a no-op success.
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        loop {
            match this.phase {
                Phase::Eof => return Poll::Ready(Ok(())),
                Phase::Draining { drain } => {
                    let n = (this.total - drain).min(out.remaining());
                    // total > drain always here: Draining is only entered
                    // with a non-empty accepted line.
                    out.put_slice(&this.buf[drain..drain + n]);
                    if drain + n == this.total {
                        // Carry over any bytes of following lines that
                        // arrived in the same upstream read.
                        let leftover = this.fill - this.total;
                        if leftover > 0 {
                            this.buf.copy_within(this.total..this.fill, 0);
                        }
                        this.fill = leftover;
                        this.scanned = 0;
                        this.phase = Phase::Filling;
                    } else {
                        this.phase = Phase::Draining { drain: drain + n };
                    }
                    return Poll::Ready(Ok(()));
                }
                Phase::Discarding => {
                    let mut rb = ReadBuf::new(this.scratch.as_mut());
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                this.phase = Phase::Eof;
                                continue;
                            }
                            match rb.filled().iter().position(|b| *b == b'\n') {
                                Some(i) => {
                                    // Rest of the oversized line dropped;
                                    // carry over any bytes of the next
                                    // lines that arrived in this chunk.
                                    let leftover = n - (i + 1);
                                    if leftover > 0 {
                                        this.scratch.copy_within(i + 1..n, 0);
                                        this.buf[..leftover]
                                            .copy_from_slice(&this.scratch[..leftover]);
                                    }
                                    this.fill = leftover;
                                    this.scanned = 0;
                                    this.phase = Phase::Filling;
                                }
                                None => continue,
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Phase::Filling => {
                    // First accept any complete line already buffered
                    // (e.g. carried over behind a line accepted from the
                    // same upstream read) — it must NOT wait for more
                    // bytes to arrive before it is forwarded.
                    if this.scanned < this.fill {
                        if let Some(i) = this.buf[this.scanned..this.fill]
                            .iter()
                            .position(|b| *b == b'\n')
                        {
                            this.total = this.scanned + i + 1;
                            this.phase = Phase::Draining { drain: 0 };
                            continue;
                        }
                        this.scanned = this.fill;
                    }
                    if this.fill > this.limit {
                        // More than `limit` bytes with no newline: the
                        // line exceeds the limit — drop it whole.
                        this.dropped += 1;
                        if this.dropped <= MAX_DROP_NOTICES {
                            eprintln!(
                                "[sequel-mcp] dropped oversized stdin line (limit {} bytes)",
                                this.limit
                            );
                        }
                        this.fill = 0;
                        this.scanned = 0;
                        this.phase = Phase::Discarding;
                        continue;
                    }
                    let mut rb = ReadBuf::new(&mut this.buf[this.fill..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                // Upstream EOF mid-line: drain any buffered
                                // tail (the codec will reject a truncated
                                // line), then signal EOF.
                                if this.fill > 0 {
                                    this.total = this.fill;
                                    this.phase = Phase::Draining { drain: 0 };
                                } else {
                                    this.phase = Phase::Eof;
                                }
                                continue;
                            }
                            this.fill += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

/// The bounded stdio transport pair: stdin passes through the line limit
/// adapter; stdout is protocol-only.
pub fn limited_stdio() -> (LineLimited<tokio::io::Stdin>, tokio::io::Stdout) {
    (LineLimited::new(tokio::io::stdin()), tokio::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn run_adapter(input: Vec<u8>, limit: usize) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(8 * CHUNK);
        let mut adapter = LineLimited::with_limit(server, limit);
        let writer = tokio::spawn(async move {
            client.write_all(&input).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut out = Vec::new();
        adapter.read_to_end(&mut out).await.unwrap();
        writer.await.unwrap();
        out
    }

    #[tokio::test]
    async fn small_lines_pass_through_verbatim() {
        let input = b"{\"a\":1}\n{\"b\":2}\n".to_vec();
        let out = run_adapter(input.clone(), 64).await;
        assert_eq!(out, input);
    }

    #[tokio::test]
    async fn line_at_exact_limit_passes_with_terminator() {
        let body = "x".repeat(63);
        let input = format!("{body}\nnext\n").into_bytes();
        let out = run_adapter(input.clone(), 64).await;
        assert_eq!(out, input, "line of exactly limit bytes passes");
    }

    #[tokio::test]
    async fn oversized_line_is_dropped_and_stream_recovers() {
        // limit 64: a 200-byte line is dropped whole, lines around it pass.
        let before = "ok1\n";
        let big = format!("{}\n", "y".repeat(200));
        let after = "ok2\n";
        let input = format!("{before}{big}{after}").into_bytes();
        let out = run_adapter(input, 64).await;
        assert_eq!(out, b"ok1\nok2\n".to_vec());
    }

    #[tokio::test]
    async fn no_newline_oversized_then_newline_then_valid() {
        let input = format!("{}\nvalid\n", "z".repeat(500)).into_bytes();
        let out = run_adapter(input, 64).await;
        assert_eq!(out, b"valid\n".to_vec());
    }

    #[tokio::test]
    async fn many_oversized_lines_in_sequence() {
        let mut input = String::new();
        for i in 0..5 {
            input.push_str(&format!("{}{}\n", "w".repeat(100), i));
        }
        input.push_str("done\n");
        let out = run_adapter(input.into_bytes(), 64).await;
        assert_eq!(out, b"done\n".to_vec());
    }

    #[tokio::test]
    async fn slow_byte_by_byte_oversized_sender_stays_bounded() {
        // Feed an oversized line in tiny chunks with a readable pause —
        // the adapter must still discard it and pass the next line.
        let (mut client, server) = tokio::io::duplex(64);
        let mut adapter = LineLimited::with_limit(server, 32);
        let writer = tokio::spawn(async move {
            for _ in 0..200 {
                client.write_all(b"q").await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            client.write_all(b"\nrecover\n").await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut out = Vec::new();
        adapter.read_to_end(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, b"recover\n".to_vec());
    }

    #[tokio::test]
    async fn carried_over_line_is_forwarded_without_new_input() {
        // Two lines arriving in ONE upstream read: the second must be
        // forwarded without waiting for further input (regression for a
        // stall where a buffered complete line waited for the next read).
        let (mut client, server) = tokio::io::duplex(64);
        let mut adapter = LineLimited::with_limit(server, 64);
        client.write_all(b"first\nsecond\n").await.unwrap();
        let mut out1 = [0u8; 64];
        let n1 = tokio::time::timeout(Duration::from_secs(2), adapter.read(&mut out1))
            .await
            .expect("first line must not stall")
            .unwrap();
        assert_eq!(&out1[..n1], b"first\n");
        let mut out2 = [0u8; 64];
        let n2 = tokio::time::timeout(Duration::from_secs(2), adapter.read(&mut out2))
            .await
            .expect("carried-over line must not wait for new input")
            .unwrap();
        assert_eq!(&out2[..n2], b"second\n");
        let _ = &mut client;
    }

    #[tokio::test]
    async fn chunk_boundary_lines_are_framed_correctly() {
        // Lines spanning multiple internal refill boundaries.
        let mut input = String::new();
        for i in 0..40 {
            input.push_str(&format!("line-{i:02}-{}\n", "p".repeat(500)));
        }
        let out = run_adapter(input.clone().into_bytes(), 1024).await;
        assert_eq!(out, input.into_bytes());
    }
}
