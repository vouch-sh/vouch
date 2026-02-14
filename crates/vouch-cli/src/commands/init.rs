// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Init command - output a shell hook for ambient auth status awareness.
//!
//! Usage: `eval "$(vouch init bash)"` in ~/.bashrc
//!
//! The hook runs a fast agent IPC check on each prompt and sets
//! VOUCH_AUTHENTICATED, VOUCH_EMAIL, and VOUCH_EXPIRES_IN environment variables.

use anyhow::Result;

/// Shell to generate a hook for.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

/// Run the init command - print a shell hook to stdout.
pub fn run(shell: &Shell) -> Result<()> {
    match shell {
        Shell::Bash => print_bash_hook(),
        Shell::Zsh => print_zsh_hook(),
        Shell::Fish => print_fish_hook(),
    }
    Ok(())
}

fn print_bash_hook() {
    print!(
        r#"_vouch_hook() {{
  local status
  status="$(vouch status --json 2>/dev/null)"
  if [ -n "$status" ]; then
    VOUCH_AUTHENTICATED="$(printf '%s' "$status" | grep -o '"authenticated":[a-z]*' | cut -d: -f2)"
    if [ "$VOUCH_AUTHENTICATED" = "true" ]; then
      VOUCH_AUTHENTICATED=1
      VOUCH_EMAIL="$(printf '%s' "$status" | grep -o '"email":"[^"]*"' | cut -d'"' -f4)"
      VOUCH_EXPIRES_IN="$(printf '%s' "$status" | grep -o '"expires_in_seconds":[0-9]*' | cut -d: -f2)"
      export VOUCH_AUTHENTICATED VOUCH_EMAIL VOUCH_EXPIRES_IN
    else
      VOUCH_AUTHENTICATED=0
      unset VOUCH_EMAIL VOUCH_EXPIRES_IN
      export VOUCH_AUTHENTICATED
    fi
  fi
}}
if [[ ! "$PROMPT_COMMAND" == *"_vouch_hook"* ]]; then
  PROMPT_COMMAND="_vouch_hook;$PROMPT_COMMAND"
fi
"#
    );
}

fn print_zsh_hook() {
    print!(
        r#"_vouch_hook() {{
  local status
  status="$(vouch status --json 2>/dev/null)"
  if [[ -n "$status" ]]; then
    VOUCH_AUTHENTICATED="$(printf '%s' "$status" | grep -o '"authenticated":[a-z]*' | cut -d: -f2)"
    if [[ "$VOUCH_AUTHENTICATED" = "true" ]]; then
      export VOUCH_AUTHENTICATED=1
      export VOUCH_EMAIL="$(printf '%s' "$status" | grep -o '"email":"[^"]*"' | cut -d'"' -f4)"
      export VOUCH_EXPIRES_IN="$(printf '%s' "$status" | grep -o '"expires_in_seconds":[0-9]*' | cut -d: -f2)"
    else
      export VOUCH_AUTHENTICATED=0
      unset VOUCH_EMAIL VOUCH_EXPIRES_IN
    fi
  fi
}}
autoload -Uz add-zsh-hook
add-zsh-hook precmd _vouch_hook
"#
    );
}

fn print_fish_hook() {
    print!(
        r#"function _vouch_hook --on-event fish_prompt
  set -l status_json (vouch status --json 2>/dev/null)
  if test -n "$status_json"
    set -l auth (echo $status_json | string match -r '"authenticated":(\w+)' | tail -1)
    if test "$auth" = "true"
      set -gx VOUCH_AUTHENTICATED 1
      set -gx VOUCH_EMAIL (echo $status_json | string match -r '"email":"([^"]*)"' | tail -1)
      set -gx VOUCH_EXPIRES_IN (echo $status_json | string match -r '"expires_in_seconds":(\d+)' | tail -1)
    else
      set -gx VOUCH_AUTHENTICATED 0
      set -e VOUCH_EMAIL
      set -e VOUCH_EXPIRES_IN
    end
  end
end
"#
    );
}
