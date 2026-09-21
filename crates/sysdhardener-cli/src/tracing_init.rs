//! Stderr-only tracing subscriber installation.
//!
//! The CLI must never write the recommendation report to stdout; the
//! report is a file artifact. Lifecycle, decision, gap, and bounded
//! raw-event logs all flow through `tracing` to a single subscriber
//! that writes **only** to `stderr`. The subscriber is built once at
//! process start; subsequent calls are a no-op so a future seam
//! (e.g. a panic hook) can re-install without double-registering.
//!
//! Verbosity is controlled by an explicit level passed from the
//! parsed CLI (`--verbose trace|debug|info|warn|error|off`); when
//! the level is `Default` (the binary default), the subscriber falls
//! back to `RUST_LOG` for parity with the rest of the Rust
//! ecosystem. The fallback is `info` when `RUST_LOG` is unset so the
//! default run is not silent.

use std::path::{Path, PathBuf};
use std::sync::Once;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// The verbosity level the binary maps from `--verbose`. The
/// `Default` variant defers to `RUST_LOG` (and to `info` when
/// `RUST_LOG` is unset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    /// Fall back to `RUST_LOG`; `info` when unset.
    #[default]
    Default,
    /// All events, including raw per-event TRACE lines.
    Trace,
    /// Decision and aggregate DEBUG lines.
    Debug,
    /// Lifecycle INFO lines only.
    Info,
    /// Gap warnings only.
    Warn,
    /// Errors only.
    Error,
    /// Silence the subscriber.
    Off,
}

impl Verbosity {
    /// Render the variant as a `tracing` filter directive.
    #[must_use]
    pub(crate) const fn as_filter_directive(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Trace => Some("trace"),
            Self::Debug => Some("debug"),
            Self::Info => Some("info"),
            Self::Warn => Some("warn"),
            Self::Error => Some("error"),
            Self::Off => Some("off"),
        }
    }
}

/// Result of installing the tracing subscriber.
#[derive(Debug)]
pub struct TracingHandle {
    /// The verbosity the subscriber was installed with.
    pub verbosity: Verbosity,
    /// The filter directive the subscriber is using, after the
    /// `RUST_LOG` fallback resolved.
    pub filter_directive: String,
    /// Whether the subscriber fell back to `info` because an
    /// explicit `RUST_LOG` value was present but invalid.
    pub fell_back_from_invalid_rust_log: bool,
    /// Optional file receiving raw event TRACE lines.
    pub trace_file: Option<PathBuf>,
}

/// Install the `tracing` subscriber, optionally routing raw events to a dedicated file.
pub fn install_subscriber(verbosity: Verbosity, trace_file: Option<&Path>) -> TracingHandle {
    static INSTALLED: Once = Once::new();
    let (directive, fell_back_from_invalid_rust_log): (String, bool) =
        verbosity.as_filter_directive().map_or_else(
            || {
                let (directive, fell_back) = resolve_default_directive();
                (directive, fell_back)
            },
            |directive| (directive.to_owned(), false),
        );
    let directive_for_handle = directive.clone();
    let trace_file_path = trace_file.map(Path::to_path_buf);
    let trace_file_handle = trace_file_path.clone();

    INSTALLED.call_once(move || {
        let (stderr_filter_str, file_filter_str) = match verbosity {
            Verbosity::Trace => (
                "trace,sysdhardener.raw_event=off".to_owned(),
                "sysdhardener.raw_event=trace".to_owned(),
            ),
            _ => (directive.clone(), "sysdhardener.raw_event=trace".to_owned()),
        };

        let stderr_filter =
            EnvFilter::try_new(&stderr_filter_str).unwrap_or_else(|_| EnvFilter::new("info"));
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_ansi(false)
            .with_level(true)
            .with_file(false)
            .with_line_number(false)
            .without_time()
            .with_filter(stderr_filter);

        let file_layer = trace_file_path
            .and_then(|p| {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&p)
                    .ok()
            })
            .map(|f| {
                let file_filter = EnvFilter::try_new(&file_filter_str)
                    .unwrap_or_else(|_| EnvFilter::new("trace"));
                tracing_subscriber::fmt::layer()
                    .with_writer(f)
                    .with_target(true)
                    .with_ansi(false)
                    .with_level(true)
                    .with_file(false)
                    .with_line_number(false)
                    .without_time()
                    .with_filter(file_filter)
            });

        let subscriber = tracing_subscriber::registry()
            .with(stderr_layer)
            .with(file_layer);
        let _ = subscriber.try_init();
    });

    TracingHandle {
        verbosity,
        filter_directive: directive_for_handle,
        fell_back_from_invalid_rust_log,
        trace_file: trace_file_handle,
    }
}

/// Resolve the default `RUST_LOG` directive, falling back to `info`
/// when the environment variable is unset, empty, or otherwise invalid.
fn resolve_default_directive() -> (String, bool) {
    std::env::var("RUST_LOG").map_or_else(
        |_| ("info".to_owned(), false),
        |raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || EnvFilter::try_new(trimmed).is_err() {
                ("info".to_owned(), true)
            } else {
                (trimmed.to_owned(), false)
            }
        },
    )
}

/// Resolve the verbosity dial from slice of CLI values.
pub fn resolve_verbosity(verbose: &[String]) -> (Verbosity, Option<&str>) {
    verbose.first().map_or((Verbosity::Default, None), |raw| {
        parse_verbosity(raw.as_str())
    })
}

/// Map a CLI string to a typed [`Verbosity`].
pub fn parse_verbosity(raw: &str) -> (Verbosity, Option<&str>) {
    match raw.to_ascii_lowercase().as_str() {
        "default" | "" => (Verbosity::Default, None),
        "trace" => (Verbosity::Trace, None),
        "debug" => (Verbosity::Debug, None),
        "info" => (Verbosity::Info, None),
        "warn" | "warning" => (Verbosity::Warn, None),
        "error" => (Verbosity::Error, None),
        "off" | "silent" | "quiet" => (Verbosity::Off, None),
        _ => (Verbosity::Default, Some(raw)),
    }
}
