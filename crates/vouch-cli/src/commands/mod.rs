// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI command implementations.

pub(crate) mod aws;
pub(crate) mod completions;
pub(crate) mod credential;
#[cfg(not(target_os = "windows"))]
pub(crate) mod diag;
pub(crate) mod doctor;
pub(crate) mod enroll;
pub(crate) mod env;
pub(crate) mod exec;
pub(crate) mod init;
pub(crate) mod keys;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod posture;
pub(crate) mod register;
pub(crate) mod setup;
pub(crate) mod status;

/// Credential type to inject into the subprocess environment.
#[derive(Clone, Debug, clap::ValueEnum)]
pub(crate) enum CredentialType {
    /// AWS temporary credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
    Aws,
    /// GitHub token (GITHUB_TOKEN, GH_TOKEN).
    Github,
    /// CodeArtifact authorization token (CODEARTIFACT_AUTH_TOKEN).
    Codeartifact,
    /// RDS IAM auth token (PGPASSWORD, PGHOST, PGPORT, PGUSER, PGSSLMODE).
    Rds,
    /// Redshift database credentials (PGPASSWORD, PGUSER, PGSSLMODE).
    Redshift,
    /// Anthropic (Claude) federation token (ANTHROPIC_AUTH_TOKEN).
    ///
    /// Workload path: the minted token acts as a service account, intended
    /// for CI/headless automation, not interactive Claude Code sessions.
    Anthropic,
    /// OpenAI federation token (OPENAI_API_KEY).
    ///
    /// Workload path: the minted token acts as a service account, intended
    /// for CI/headless automation. Note: the OpenAI SDK reads
    /// `OPENAI_API_KEY` only — there is no `OPENAI_AUTH_TOKEN` variant, so
    /// this deliberately diverges from the Anthropic naming convention.
    Openai,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    /// Regression for #452: `vouch exec --type openai` returned
    /// `error: invalid value 'openai' for '--type <CREDENTIAL_TYPE>'`
    /// because `Openai` was missing from the enum. Lock the parse.
    #[test]
    fn test_credential_type_parses_openai() {
        let v = CredentialType::from_str("openai", true);
        assert!(matches!(v, Ok(CredentialType::Openai)));
    }

    /// Lock the full set of accepted `--type` values so any future addition
    /// or rename surfaces in review.
    #[test]
    fn test_credential_type_value_enum_set() {
        let mut names: Vec<String> = CredentialType::value_variants()
            .iter()
            .filter_map(|v| v.to_possible_value())
            .map(|pv| pv.get_name().to_string())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "anthropic",
                "aws",
                "codeartifact",
                "github",
                "openai",
                "rds",
                "redshift",
            ]
        );
    }
}
