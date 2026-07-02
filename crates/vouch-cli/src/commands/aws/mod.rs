// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS subcommands.

use clap::Subcommand;
use vouch_cli::tr;

pub(crate) mod console;

/// AWS subcommands.
#[derive(Subcommand)]
pub(crate) enum AwsCommands {
    /// Open the AWS Management Console in your browser.
    #[command(about = tr!("cmd-aws-console-about"))]
    Console(console::ConsoleArgs),
}
