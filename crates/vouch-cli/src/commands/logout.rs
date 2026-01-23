//! Log out and clear session

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;

pub async fn run(config: &Config) -> Result<()> {
    let mut config = config.clone();
    config.clear_session()?;

    println!("{}", "✓ Logged out".green());
    Ok(())
}
