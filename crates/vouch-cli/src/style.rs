// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Terminal styling helpers — ANSI color and bold/dim.
//!
//! Color output auto-disables when stdout is not a TTY and respects the
//! `NO_COLOR` environment variable (<https://no-color.org/>).
//! Override with `--color=always` or `--color=never`.

use std::io::IsTerminal;

/// Global flag — set once at startup by [`init`].
static COLOR_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Color output preference (maps to `--color` CLI flag).
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum ColorChoice {
    /// Enable color when stdout is a TTY and `NO_COLOR` is unset.
    #[default]
    Auto,
    /// Always emit ANSI color codes.
    Always,
    /// Never emit ANSI color codes.
    Never,
}

/// Initialize global color state. Call once after CLI parsing.
pub(crate) fn init(choice: ColorChoice) {
    let enabled = match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    };
    let _ = COLOR_ENABLED.set(enabled);
}

/// Whether color is currently enabled.
fn is_enabled() -> bool {
    COLOR_ENABLED.get().copied().unwrap_or(false)
}

// ANSI escape sequences
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const BOLD_RED: &str = "\x1b[1;31m";

/// Wrap text in an ANSI style sequence (or return plain text if color is off).
fn styled(codes: &str, text: &str) -> String {
    if is_enabled() {
        format!("{codes}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Green text.
pub(crate) fn green(text: &str) -> String {
    styled(GREEN, text)
}

/// Red text.
pub(crate) fn red(text: &str) -> String {
    styled(RED, text)
}

/// Yellow text.
pub(crate) fn yellow(text: &str) -> String {
    styled(YELLOW, text)
}

/// Dim (faint) text.
pub(crate) fn dim(text: &str) -> String {
    styled(DIM, text)
}

/// Bold green text.
pub(crate) fn bold_green(text: &str) -> String {
    styled(BOLD_GREEN, text)
}

/// Bold red text.
pub(crate) fn bold_red(text: &str) -> String {
    styled(BOLD_RED, text)
}
