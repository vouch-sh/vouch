// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shell completion generation.

use clap::Args;
use clap_complete::{Shell, generate};
use std::io;

/// Generate shell completions.
#[derive(Args)]
pub(crate) struct CompletionsArgs {
    /// The shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Generate shell completions and output to stdout.
pub(crate) fn run(args: &CompletionsArgs, cmd: &mut clap::Command) {
    generate(args.shell, cmd, "vouch", &mut io::stdout());
}
