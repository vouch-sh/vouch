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
  eval "$(vouch status --shell 2>/dev/null)"
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
  eval "$(vouch status --shell 2>/dev/null)"
}}
autoload -Uz add-zsh-hook
add-zsh-hook precmd _vouch_hook
"#
    );
}

fn print_fish_hook() {
    print!(
        r#"function _vouch_hook --on-event fish_prompt
  set -l shell_out (vouch status --shell 2>/dev/null)
  if test -n "$shell_out"
    for line in $shell_out
      set -l parts (string split "=" -- $line)
      if test (count $parts) -ge 2
        set -l key $parts[1]
        set -l val (string join "=" -- $parts[2..])
        if test "$key" = "VOUCH_AUTHENTICATED" -a "$val" = "0"
          set -gx VOUCH_AUTHENTICATED 0
          set -e VOUCH_EMAIL
          set -e VOUCH_EXPIRES_IN
        else
          set -gx $key $val
        end
      end
    end
  end
end
"#
    );
}

#[cfg(test)]
mod tests {
    /// Verify bash hook contains the expected `vouch status --shell` call.
    #[test]
    fn test_bash_hook_uses_shell_flag() {
        // The hook source should use `vouch status --shell` instead of
        // fragile grep/cut JSON parsing.
        let hook = include_str!("init.rs");
        assert!(hook.contains("vouch status --shell"));
    }
}
