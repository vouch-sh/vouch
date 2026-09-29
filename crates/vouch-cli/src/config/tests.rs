// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use secrecy::ExposeSecret;

// -----------------------------------------------------------------
// Hostname extraction
// -----------------------------------------------------------------

#[test]
fn test_hostname_standard_https() {
    assert_eq!(
        hostname_from_url("https://us.vouch.sh").unwrap(),
        "us.vouch.sh"
    );
}

#[test]
fn test_hostname_standard_http() {
    assert_eq!(
        hostname_from_url("http://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_hostname_with_non_standard_port() {
    assert_eq!(
        hostname_from_url("http://localhost:3000").unwrap(),
        "localhost:3000"
    );
}

#[test]
fn test_hostname_explicit_standard_port() {
    assert_eq!(
        hostname_from_url("https://us.vouch.sh:443").unwrap(),
        "us.vouch.sh"
    );
}

#[test]
fn test_hostname_with_path() {
    assert_eq!(
        hostname_from_url("https://dev.vouch.sh/api/v1").unwrap(),
        "dev.vouch.sh"
    );
}

#[test]
fn test_hostname_invalid_url() {
    assert!(hostname_from_url("not-a-url").is_err());
}

// -----------------------------------------------------------------
// New format round-trip
// -----------------------------------------------------------------

#[test]
fn test_new_format_round_trip() {
    let json = r#"{
        "current_server": "us.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "tok-us",
                "client_id": "cid-us",
                "dpop_key_id": "kid-us"
            },
            "dev.vouch.sh": {
                "server_url": "https://dev.vouch.sh",
                "token": "tok-dev",
                "client_id": "cid-dev"
            }
        },
        "codeartifact": {
            "default": "prod",
            "domain_profiles": {
                "prod": {
                    "domain": "my-domain",
                    "domain_owner": "123456789012",
                    "region": "us-east-1"
                }
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    assert_eq!(config.current_server.as_deref(), Some("us.vouch.sh"));
    assert_eq!(config.servers.len(), 2);

    // Current server accessors work.
    assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
    assert!(config.token().is_some());
    assert_eq!(config.client_id(), Some("cid-us"));
    assert_eq!(config.dpop_key_id(), Some("kid-us"));

    // CodeArtifact is global.
    let ca = config.codeartifact().expect("codeartifact should exist");
    assert_eq!(ca.default.as_deref(), Some("prod"));
    assert_eq!(ca.domain_profiles.len(), 1);

    // Round-trip to JSON and back.
    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string_pretty(&file2).unwrap();
    let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
    let config2 = Config::from(file3);

    assert_eq!(config2.current_server, config.current_server);
    assert_eq!(config2.servers.len(), config.servers.len());
}

// -----------------------------------------------------------------
// Legacy migration
// -----------------------------------------------------------------

#[test]
fn test_legacy_flat_config_migrates() {
    let json = r#"{
        "server_url": "https://vouch.example.com",
        "token": "legacy-token",
        "client_id": "legacy-cid",
        "registration_access_token": "legacy-rat",
        "registration_client_uri": "https://vouch.example.com/reg/123",
        "dpop_key_id": "legacy-kid",
        "codeartifact": {
            "default": "prod",
            "domain_profiles": {
                "prod": {
                    "domain": "d",
                    "domain_owner": "o",
                    "region": "r"
                }
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    // Legacy fields migrated into a server entry.
    assert_eq!(config.current_server.as_deref(), Some("vouch.example.com"));
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.server_url(), Some("https://vouch.example.com"));
    assert!(config.token().is_some());
    assert_eq!(config.client_id(), Some("legacy-cid"));
    assert_eq!(config.dpop_key_id(), Some("legacy-kid"));
    assert!(config.registration_access_token().is_some());
    assert_eq!(
        config.registration_client_uri(),
        Some("https://vouch.example.com/reg/123")
    );

    // CodeArtifact preserved.
    assert!(config.codeartifact().is_some());

    // After round-trip, the legacy flat fields are gone.
    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string(&file2).unwrap();
    assert!(json2.contains("servers"));
    // Legacy top-level fields should NOT be present.
    let reparsed: serde_json::Value = serde_json::from_str(&json2).unwrap();
    assert!(reparsed.get("server_url").is_none());
    assert!(reparsed.get("token").is_none());
    assert!(reparsed.get("client_id").is_none());
}

#[test]
fn test_legacy_email_field_ignored() {
    let json = r#"{
        "server_url": "https://vouch.example.com",
        "token": "test-token",
        "email": "alice@example.com"
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    assert_eq!(config.server_url(), Some("https://vouch.example.com"));
}

// -----------------------------------------------------------------
// Multi-server config
// -----------------------------------------------------------------

#[test]
fn test_multi_server_isolation() {
    let mut config = Config::default();

    // Set up server 1.
    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok-us");
    config.set_client_id("cid-us");

    // Set up server 2.
    config.set_server_url("https://dev.vouch.sh");
    config.set_token("tok-dev");
    config.set_client_id("cid-dev");

    // Current context is server 2.
    assert_eq!(config.server_url(), Some("https://dev.vouch.sh"));
    assert_eq!(config.client_id(), Some("cid-dev"));

    // Switch back to server 1.
    config.set_server_url("https://us.vouch.sh");
    assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
    assert_eq!(config.client_id(), Some("cid-us"));

    // Both entries exist.
    assert_eq!(config.servers.len(), 2);
}

// -----------------------------------------------------------------
// Empty config
// -----------------------------------------------------------------

#[test]
fn test_empty_config_serializes_to_empty_object() {
    let config = Config::default();
    let file = ConfigFile::from(&config);
    let json = serde_json::to_string(&file).unwrap();
    assert_eq!(json, "{}");
}

#[test]
fn test_empty_json_deserializes() {
    let file: ConfigFile = serde_json::from_str("{}").unwrap();
    let config = Config::from(file);
    assert!(config.server_url().is_none());
    assert!(config.token().is_none());
    assert!(config.codeartifact().is_none());
}

#[test]
fn test_explicit_null_values_deserialize_as_none() {
    let json = r#"{
        "current_server": null,
        "servers": {},
        "codeartifact": null
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    assert!(config.server_url().is_none());
    assert!(config.token().is_none());
    assert!(config.codeartifact().is_none());
}

// -----------------------------------------------------------------
// CodeArtifact (unchanged global behavior)
// -----------------------------------------------------------------

#[test]
fn test_codeartifact_round_trip() {
    let json = r#"{
        "current_server": "us.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "test-token"
            }
        },
        "codeartifact": {
            "default": "prod",
            "domain_profiles": {
                "prod": {
                    "domain": "my-domain",
                    "domain_owner": "123456789012",
                    "region": "us-east-1"
                },
                "staging": {
                    "domain": "staging-domain",
                    "domain_owner": "987654321098",
                    "region": "eu-west-1"
                }
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let ca = config
        .codeartifact()
        .expect("codeartifact config should exist");
    assert_eq!(ca.default.as_deref(), Some("prod"));
    assert_eq!(ca.domain_profiles.len(), 2);

    let prod = ca
        .domain_profiles
        .get("prod")
        .expect("prod profile should exist");
    assert_eq!(prod.domain, "my-domain");
}

#[test]
fn test_config_without_codeartifact() {
    let json = r#"{
        "current_server": "test.vouch.sh",
        "servers": {
            "test.vouch.sh": {
                "server_url": "https://test.vouch.sh",
                "token": "t"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    assert!(config.codeartifact().is_none());

    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string(&file2).unwrap();
    assert!(!json2.contains("codeartifact"));
}

#[test]
fn test_set_codeartifact_profile_sets_default_for_first() {
    let mut config = Config::default();

    config.set_codeartifact_profile(
        "myteam",
        CodeArtifactProfile {
            domain: "team-domain".into(),
            domain_owner: "111111111111".into(),
            region: "us-west-2".into(),
            aws_profile: None,
        },
    );

    let ca = config
        .codeartifact()
        .expect("should have codeartifact config");
    assert_eq!(ca.default.as_deref(), Some("myteam"));
    assert_eq!(ca.domain_profiles.len(), 1);
}

// -----------------------------------------------------------------
// FAPI 2.0 field tests
// -----------------------------------------------------------------

#[test]
fn test_fapi_fields_round_trip() {
    let json = r#"{
        "current_server": "vouch.example.com",
        "servers": {
            "vouch.example.com": {
                "server_url": "https://vouch.example.com",
                "client_id": "my-client-123",
                "registration_access_token": "reg-token-abc",
                "registration_client_uri": "https://vouch.example.com/register/my-client-123",
                "dpop_key_id": "abc123thumbprint"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    assert_eq!(config.client_id(), Some("my-client-123"));
    assert_eq!(
        config.registration_client_uri(),
        Some("https://vouch.example.com/register/my-client-123")
    );
    assert_eq!(config.dpop_key_id(), Some("abc123thumbprint"));
    assert!(config.registration_access_token().is_some());

    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string(&file2).unwrap();
    assert!(json2.contains("my-client-123"));
    assert!(json2.contains("abc123thumbprint"));
}

#[test]
fn test_fapi_fields_absent_when_no_server() {
    let config = Config::default();
    assert!(config.client_id().is_none());
    assert!(config.registration_access_token().is_none());
    assert!(config.registration_client_uri().is_none());
    assert!(config.dpop_key_id().is_none());
}

#[test]
fn test_set_client_id() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_client_id("test-client");
    assert_eq!(config.client_id(), Some("test-client"));
}

#[test]
fn test_set_dpop_key_id() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_dpop_key_id("my-kid");
    assert_eq!(config.dpop_key_id(), Some("my-kid"));
}

#[test]
fn test_set_registration_access_token() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_registration_access_token("secret-reg-token");
    assert!(config.registration_access_token().is_some());
}

#[test]
fn test_set_registration_client_uri() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_registration_client_uri("https://example.com/reg/123");
    assert_eq!(
        config.registration_client_uri(),
        Some("https://example.com/reg/123")
    );
}

#[test]
fn test_clear_fapi() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_client_id("c1");
    config.set_dpop_key_id("k1");
    config.set_registration_access_token("t1");
    config.set_registration_client_uri("https://example.com/reg");

    config.clear_fapi();

    assert!(config.client_id().is_none());
    assert!(config.dpop_key_id().is_none());
    assert!(config.registration_access_token().is_none());
    assert!(config.registration_client_uri().is_none());
}

#[test]
fn test_clear_fapi_does_not_clear_token() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_token("session-token");
    config.set_client_id("c1");

    config.clear_fapi();

    assert!(config.token().is_some());
    assert!(config.client_id().is_none());
}

/// RFC 7592 §5: "As the registration access tokens are relatively long-term
/// credentials, and since the registration access token is a Bearer Token and
/// acts as the sole authentication for use at the client configuration
/// endpoint, it MUST be protected by the developer or client as described in
/// the OAuth 2.0 Bearer Token Usage specification [RFC6750]."
///
/// RFC 6750's bearer-token threat mitigations name keeping tokens out of logs;
/// the redacting `Debug` is what enforces it for a CLI that prints config
/// structs. Only that one mitigation is asserted here.
#[test]
fn test_registration_access_token_redacted_in_debug() {
    let mut config = Config::default();
    config.set_server_url("https://example.com");
    config.set_registration_access_token("super-secret-reg-token");

    let debug_str = format!("{config:?}");
    assert!(!debug_str.contains("super-secret-reg-token"));

    // Also verify ServerConfig Debug redacts secrets.
    let sc = config.servers.get("example.com").expect("server entry");
    let sc_debug = format!("{sc:?}");
    assert!(sc_debug.contains("[REDACTED]"));
    assert!(!sc_debug.contains("super-secret-reg-token"));
}

// -----------------------------------------------------------------
// Regression: setting server_url also creates context
// -----------------------------------------------------------------

#[test]
fn test_set_server_url_creates_context() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok");
    assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
    assert!(config.token().is_some());
}

// -----------------------------------------------------------------
// AwsOrgsConfig: new-format round-trip + migration
// -----------------------------------------------------------------

#[test]
fn test_aws_orgs_config_new_format_round_trip() {
    let json = r#"{
        "aws": {
            "organizations": [
                {
                    "management_role": "arn:aws:iam::111:role/VouchManagement",
                    "identity_center": {
                        "application_arn": "arn:aws:sso::111:application/ssoins-x/apl-y",
                        "region": "us-east-1"
                    }
                }
            ]
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let aws = config.aws().expect("aws config should exist");
    assert_eq!(aws.organizations.len(), 1);

    let org = &aws.organizations[0];
    assert_eq!(org.management_role, "arn:aws:iam::111:role/VouchManagement");
    let idc = org.identity_center.as_ref().expect("identity_center");
    assert_eq!(
        idc.application_arn,
        "arn:aws:sso::111:application/ssoins-x/apl-y"
    );
    assert_eq!(idc.region, "us-east-1");

    // Round-trip through JSON must preserve the new format.
    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string_pretty(&file2).unwrap();
    assert!(json2.contains("organizations"));
    assert!(!json2.contains("sso_sessions"));

    let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
    let config2 = Config::from(file3);
    let aws2 = config2.aws().expect("aws config survives round-trip");
    assert_eq!(aws2.organizations.len(), 1);
    assert_eq!(
        aws2.organizations[0].management_role,
        "arn:aws:iam::111:role/VouchManagement"
    );
}

#[test]
fn test_aws_orgs_config_no_identity_center() {
    let json = r#"{
        "aws": {
            "organizations": [
                { "management_role": "arn:aws:iam::222:role/Mgmt" }
            ]
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    let aws = config.aws().expect("aws config should exist");
    assert_eq!(aws.organizations.len(), 1);
    assert!(aws.organizations[0].identity_center.is_none());
}

#[test]
fn test_aws_orgs_config_migrates_legacy_sso_sessions() {
    // A config written by the old code, with two sso_sessions entries.
    let json = r#"{
        "aws": {
            "sso_sessions": {
                "smoketurner": {
                    "management_role": "arn:aws:iam::111:role/VouchManagement",
                    "member_role_name": "VouchAccess",
                    "member_role_path": "/teams/sec/"
                },
                "other-session": {
                    "management_role": "arn:aws:iam::222:role/Mgmt"
                }
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let aws = config
        .aws()
        .expect("aws config should exist after migration");
    assert_eq!(aws.organizations.len(), 2);

    // Both management_roles must be present; name key + role fields dropped.
    let mgmt_roles: Vec<&str> = aws
        .organizations
        .iter()
        .map(|o| o.management_role.as_str())
        .collect();
    assert!(mgmt_roles.contains(&"arn:aws:iam::111:role/VouchManagement"));
    assert!(mgmt_roles.contains(&"arn:aws:iam::222:role/Mgmt"));

    // After migration, serializing writes the new format.
    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string(&file2).unwrap();
    assert!(json2.contains("organizations"));
    assert!(!json2.contains("sso_sessions"));
    assert!(!json2.contains("member_role_name"));
}

#[test]
fn test_aws_empty_organizations_omitted_from_json() {
    // Start from default — no aws section.
    let config = Config::default();
    assert!(config.aws().is_none());

    let file = ConfigFile::from(&config);
    let json = serde_json::to_string(&file).unwrap();

    // Empty organizations list is skipped; entire aws block may be omitted.
    assert!(!json.contains("organizations"));
}

#[test]
fn test_append_aws_org_adds_new() {
    let mut config = Config::default();
    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::111:role/Mgmt".to_string(),
        identity_center: None,
    });
    assert_eq!(config.aws().unwrap().organizations.len(), 1);

    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::222:role/Mgmt".to_string(),
        identity_center: None,
    });
    assert_eq!(config.aws().unwrap().organizations.len(), 2);
}

#[test]
fn test_append_aws_org_replaces_existing() {
    let mut config = Config::default();
    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::111:role/Mgmt".to_string(),
        identity_center: None,
    });

    // Same management role → replace.
    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::111:role/Mgmt".to_string(),
        identity_center: Some(AwsIdentityCenter {
            application_arn: "arn:aws:sso::111:application/x/y".to_string(),
            region: "us-east-1".to_string(),
        }),
    });
    let orgs = &config.aws().unwrap().organizations;
    assert_eq!(orgs.len(), 1);
    assert!(orgs[0].identity_center.is_some());
}

#[test]
fn test_append_aws_org_preserves_identity_center_on_merge() {
    // First call: store org with IdC configured.
    let mut config = Config::default();
    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::111:role/Mgmt".to_string(),
        identity_center: Some(AwsIdentityCenter {
            application_arn: "arn:aws:sso::111:application/x/y".to_string(),
            region: "us-east-1".to_string(),
        }),
    });

    // Second call: same management role but no IdC (re-run without --identity-center-application).
    // The existing IdC must be preserved.
    config.append_aws_org(AwsOrganization {
        management_role: "arn:aws:iam::111:role/Mgmt".to_string(),
        identity_center: None,
    });

    let orgs = &config.aws().unwrap().organizations;
    assert_eq!(orgs.len(), 1);
    let idc = orgs[0].identity_center.as_ref().expect("IdC preserved");
    assert_eq!(idc.application_arn, "arn:aws:sso::111:application/x/y");
    assert_eq!(idc.region, "us-east-1");
}

// -----------------------------------------------------------------
// AiProvidersConfig round-trip + accessors
// -----------------------------------------------------------------

#[test]
fn test_ai_providers_config_round_trip() {
    let json = r#"{
        "current_server": "us.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "t"
            }
        },
        "ai": {
            "anthropic": {
                "federation_rule_id": "fdrl_abc",
                "organization_id": "00000000-0000-0000-0000-000000000000",
                "service_account_id": "svac_xyz",
                "workspace_id": "wrkspc_q",
                "audience": "https://api.anthropic.com"
            },
            "openai": {
                "identity_provider_id": "wip_123",
                "service_account_id": "sa_456"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let ai = config.ai().expect("ai section should exist");
    let anthropic = ai.anthropic.as_ref().expect("anthropic");
    assert_eq!(anthropic.federation_rule_id, "fdrl_abc");
    assert_eq!(anthropic.workspace_id, "wrkspc_q");
    assert_eq!(
        anthropic.audience.as_deref(),
        Some("https://api.anthropic.com")
    );
    assert!(anthropic.token_endpoint.is_none());

    let openai = ai.openai.as_ref().expect("openai");
    assert_eq!(openai.identity_provider_id, "wip_123");
    assert_eq!(openai.service_account_id, "sa_456");

    // Round-trip through JSON preserves everything.
    let file2 = ConfigFile::from(&config);
    let json2 = serde_json::to_string(&file2).unwrap();
    let file3: ConfigFile = serde_json::from_str(&json2).unwrap();
    let config3 = Config::from(file3);
    let ai3 = config3.ai().expect("ai survives round-trip");
    assert_eq!(
        ai3.anthropic.as_ref().unwrap().federation_rule_id,
        "fdrl_abc"
    );
}

#[test]
fn test_set_ai_anthropic_and_openai_independent() {
    let mut config = Config::default();

    config.set_ai_anthropic(AnthropicFederation {
        federation_rule_id: "fdrl_a".to_string(),
        organization_id: "org".to_string(),
        service_account_id: "svac".to_string(),
        workspace_id: "wrkspc".to_string(),
        audience: None,
        token_endpoint: None,
    });
    assert!(config.ai().unwrap().anthropic.is_some());
    assert!(config.ai().unwrap().openai.is_none());

    config.set_ai_openai(OpenAiFederation {
        identity_provider_id: "wip".to_string(),
        service_account_id: "sa".to_string(),
        audience: None,
        token_endpoint: None,
    });
    // Setting OpenAI must NOT clear the existing Anthropic config.
    assert!(config.ai().unwrap().anthropic.is_some());
    assert!(config.ai().unwrap().openai.is_some());
}

#[test]
fn test_config_without_aws_section_loads_fine() {
    let json = r#"{
        "current_server": "us.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "test-token"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    assert!(config.aws().is_none());
    assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
}

// -----------------------------------------------------------------
// Stale registration detection
// -----------------------------------------------------------------

/// When a config's registration_client_uri points to localhost:3000 but the
/// current server is us.vouch.sh, the hostnames must differ so the caller
/// can detect and discard the stale registration.
#[test]
fn test_hostname_from_url_stale_registration_mismatch() {
    let stale_host = hostname_from_url("http://localhost:3000/reg/abc").unwrap();
    let current_host = hostname_from_url("https://us.vouch.sh").unwrap();
    assert_ne!(
        stale_host, current_host,
        "stale registration URI hostname must differ from current server hostname"
    );
    assert_eq!(stale_host, "localhost:3000");
    assert_eq!(current_host, "us.vouch.sh");
}

/// When both URIs resolve to the same server the hostnames are equal,
/// so the registration is still valid.
#[test]
fn test_hostname_from_url_valid_registration_match() {
    let reg_host = hostname_from_url("https://us.vouch.sh/register/my-client-123").unwrap();
    let current_host = hostname_from_url("https://us.vouch.sh").unwrap();
    assert_eq!(reg_host, current_host);
}

// -----------------------------------------------------------------
// Hostname extraction edge cases
// -----------------------------------------------------------------

#[test]
fn test_hostname_trailing_slash() {
    assert_eq!(
        hostname_from_url("https://us.vouch.sh/").unwrap(),
        "us.vouch.sh"
    );
}

#[test]
fn test_hostname_with_path_components() {
    assert_eq!(
        hostname_from_url("https://us.vouch.sh/oauth/token").unwrap(),
        "us.vouch.sh"
    );
}

/// https://host:443 — standard port for https, so port is stripped.
#[test]
fn test_hostname_https_explicit_443_stripped() {
    assert_eq!(
        hostname_from_url("https://us.vouch.sh:443").unwrap(),
        "us.vouch.sh"
    );
}

/// http://host:80 — standard port for http, so port is stripped.
#[test]
fn test_hostname_http_explicit_80_stripped() {
    assert_eq!(
        hostname_from_url("http://example.com:80").unwrap(),
        "example.com"
    );
}

/// http://host:443 — 443 is non-standard for http, so port is kept.
#[test]
fn test_hostname_http_port_443_kept() {
    assert_eq!(
        hostname_from_url("http://example.com:443").unwrap(),
        "example.com:443"
    );
}

/// https://host:80 — 80 is non-standard for https, so port is kept.
#[test]
fn test_hostname_https_port_80_kept() {
    assert_eq!(
        hostname_from_url("https://example.com:80").unwrap(),
        "example.com:80"
    );
}

// -----------------------------------------------------------------
// Legacy migration edge cases
// -----------------------------------------------------------------

/// Legacy config with only a token and no server_url must not crash.
/// The config should load with no active server context.
#[test]
fn test_legacy_no_server_url_does_not_crash() {
    let json = r#"{"token": "orphaned-token"}"#;
    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    // No server context was established; all accessors return None.
    assert!(config.server_url().is_none());
    assert!(config.token().is_none());
    assert!(config.current_server.is_none());
    assert!(config.servers.is_empty());
}

/// Legacy config with an unparseable server_url must not crash.
/// The migration silently skips it and produces an empty config.
#[test]
fn test_legacy_unparseable_server_url_does_not_crash() {
    let json = r#"{"server_url": "not-a-url", "token": "some-token"}"#;
    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);
    // Migration skips the bad URL; nothing should crash.
    assert!(config.server_url().is_none());
    assert!(config.token().is_none());
    assert!(config.servers.is_empty());
}

/// Legacy config with a non-standard port in server_url must migrate correctly
/// and produce a `host:port` key (e.g. `localhost:3000`).
#[test]
fn test_legacy_server_url_non_standard_port_migrates() {
    let json = r#"{
        "server_url": "http://localhost:3000",
        "token": "dev-token",
        "client_id": "dev-client"
    }"#;
    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    assert_eq!(config.current_server.as_deref(), Some("localhost:3000"));
    assert_eq!(config.server_url(), Some("http://localhost:3000"));
    assert!(config.token().is_some());
    assert_eq!(config.client_id(), Some("dev-client"));
    assert_eq!(config.servers.len(), 1);
}

// -----------------------------------------------------------------
// Multi-server isolation: clear_token and clear_fapi
// -----------------------------------------------------------------

/// Clearing the token for one server must not affect a second server's token.
#[test]
fn test_clear_token_only_affects_current_server() {
    let mut config = Config::default();

    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok-us");

    config.set_server_url("https://dev.vouch.sh");
    config.set_token("tok-dev");

    // Clear token for dev server.
    config.clear_token();
    assert!(config.token().is_none(), "dev token should be cleared");

    // Switch to us server — its token must be untouched.
    config.set_server_url("https://us.vouch.sh");
    assert!(
        config.token().is_some(),
        "us.vouch.sh token should still exist"
    );
}

/// Clearing FAPI fields for one server must not affect a second server.
#[test]
fn test_clear_fapi_only_affects_current_server() {
    let mut config = Config::default();

    config.set_server_url("https://us.vouch.sh");
    config.set_client_id("cid-us");
    config.set_dpop_key_id("kid-us");
    config.set_registration_client_uri("https://us.vouch.sh/reg/1");

    config.set_server_url("https://dev.vouch.sh");
    config.set_client_id("cid-dev");
    config.set_dpop_key_id("kid-dev");
    config.set_registration_client_uri("http://localhost:3000/reg/2");

    // Clear FAPI for dev server.
    config.clear_fapi();
    assert!(config.client_id().is_none(), "dev client_id should be gone");
    assert!(
        config.dpop_key_id().is_none(),
        "dev dpop_key_id should be gone"
    );

    // Switch to us server — its FAPI fields must be intact.
    config.set_server_url("https://us.vouch.sh");
    assert_eq!(config.client_id(), Some("cid-us"));
    assert_eq!(config.dpop_key_id(), Some("kid-us"));
    assert_eq!(
        config.registration_client_uri(),
        Some("https://us.vouch.sh/reg/1")
    );
}

// -----------------------------------------------------------------
// No-op behaviour when there is no current server context
// -----------------------------------------------------------------

/// set_token without a prior set_server_url must be a silent no-op:
/// no server entry is created and no panic occurs.
#[test]
fn test_set_token_without_server_context_is_noop() {
    let mut config = Config::default();
    config.set_token("orphan-token");

    assert!(config.token().is_none());
    assert!(config.servers.is_empty());
}

/// All FAPI mutators are no-ops without server context.
#[test]
fn test_all_mutators_noop_without_server_context() {
    let mut config = Config::default();
    config.set_client_id("orphan");
    config.set_registration_access_token("orphan");
    config.set_registration_client_uri("orphan");
    config.set_dpop_key_id("orphan");
    config.clear_token();
    config.clear_fapi();

    assert!(config.servers.is_empty());
    assert!(config.client_id().is_none());
    assert!(config.token().is_none());
}

// -----------------------------------------------------------------
// Token value verification (not just is_some)
// -----------------------------------------------------------------

#[test]
fn test_token_value_preserved() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_token("exact-token-value");

    let token = config.token().expect("token should exist");
    assert_eq!(token.expose_secret(), "exact-token-value");
}

#[test]
fn test_registration_access_token_value_preserved() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_registration_access_token("exact-rat-value");

    let rat = config
        .registration_access_token()
        .expect("RAT should exist");
    assert_eq!(rat.expose_secret(), "exact-rat-value");
}

// -----------------------------------------------------------------
// Full round-trip preserves secret values
// -----------------------------------------------------------------

#[test]
fn test_round_trip_preserves_secret_values() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_token("my-jwt-token");
    config.set_registration_access_token("my-reg-token");

    // Serialize to ConfigFile and back.
    let file = ConfigFile::from(&config);
    let json = serde_json::to_string_pretty(&file).unwrap();
    let file2: ConfigFile = serde_json::from_str(&json).unwrap();
    let config2 = Config::from(file2);

    let t = config2.token().expect("token after round-trip");
    assert_eq!(t.expose_secret(), "my-jwt-token");

    let rat = config2
        .registration_access_token()
        .expect("RAT after round-trip");
    assert_eq!(rat.expose_secret(), "my-reg-token");
}

// -----------------------------------------------------------------
// Idempotent set_server_url
// -----------------------------------------------------------------

/// Calling set_server_url twice with the same URL does not
/// duplicate entries or lose state.
#[test]
fn test_set_server_url_idempotent() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok1");
    config.set_client_id("cid1");

    // Call again with the same URL.
    config.set_server_url("https://us.vouch.sh");

    assert_eq!(config.servers.len(), 1);
    assert!(config.token().is_some());
    assert_eq!(config.client_id(), Some("cid1"));
}

// -----------------------------------------------------------------
// Defensive: current_server points to nonexistent key
// -----------------------------------------------------------------

/// If the config file has a current_server that doesn't match
/// any entry in servers, all accessors return None gracefully.
#[test]
fn test_current_server_nonexistent_key() {
    let json = r#"{
        "current_server": "ghost.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "tok"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    // current_server doesn't match any key → None.
    assert!(config.server_url().is_none());
    assert!(config.token().is_none());
    assert!(config.client_id().is_none());
    // But the data is still there if we switch context.
    assert_eq!(config.servers.len(), 1);
}

// -----------------------------------------------------------------
// Mixed legacy + new format: servers wins, legacy ignored
// -----------------------------------------------------------------

/// When both `servers` and legacy flat fields exist, the `servers`
/// map takes precedence and legacy fields are ignored.
#[test]
fn test_mixed_legacy_and_new_format_servers_wins() {
    let json = r#"{
        "current_server": "us.vouch.sh",
        "servers": {
            "us.vouch.sh": {
                "server_url": "https://us.vouch.sh",
                "token": "new-token",
                "client_id": "new-cid"
            }
        },
        "server_url": "https://old.vouch.sh",
        "token": "old-token",
        "client_id": "old-cid"
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    // servers was non-empty, so legacy migration is skipped.
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.server_url(), Some("https://us.vouch.sh"));
    let t = config.token().expect("token should exist");
    assert_eq!(t.expose_secret(), "new-token");
    assert_eq!(config.client_id(), Some("new-cid"));
}

// -----------------------------------------------------------------
// Server URL update (same hostname, URL changes)
// -----------------------------------------------------------------

/// Calling set_server_url with a different URL that resolves to
/// the same hostname updates the stored URL but keeps existing
/// per-server state.
#[test]
fn test_set_server_url_updates_url_same_hostname() {
    let mut config = Config::default();
    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok");
    config.set_client_id("cid");

    // Call with a trailing-slash variant — same hostname.
    config.set_server_url("https://us.vouch.sh/");

    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.server_url(), Some("https://us.vouch.sh/"));
    assert!(config.token().is_some());
    assert_eq!(config.client_id(), Some("cid"));
}

// -----------------------------------------------------------------
// Multi-server full FAPI state survives context switches
// -----------------------------------------------------------------

#[test]
fn test_multi_server_all_fapi_fields_survive_switch() {
    let mut config = Config::default();

    // Populate server A with all FAPI fields.
    config.set_server_url("https://us.vouch.sh");
    config.set_token("tok-us");
    config.set_client_id("cid-us");
    config.set_dpop_key_id("kid-us");
    config.set_registration_access_token("rat-us");
    config.set_registration_client_uri("https://us.vouch.sh/reg/1");

    // Populate server B.
    config.set_server_url("https://eu.vouch.sh");
    config.set_token("tok-eu");
    config.set_client_id("cid-eu");
    config.set_dpop_key_id("kid-eu");

    // Switch back to A and verify every field.
    config.set_server_url("https://us.vouch.sh");
    assert_eq!(config.token().expect("us token").expose_secret(), "tok-us");
    assert_eq!(config.client_id(), Some("cid-us"));
    assert_eq!(config.dpop_key_id(), Some("kid-us"));
    assert_eq!(
        config
            .registration_access_token()
            .expect("us RAT")
            .expose_secret(),
        "rat-us"
    );
    assert_eq!(
        config.registration_client_uri(),
        Some("https://us.vouch.sh/reg/1")
    );

    // Switch to B and verify.
    config.set_server_url("https://eu.vouch.sh");
    assert_eq!(config.token().expect("eu token").expose_secret(), "tok-eu");
    assert_eq!(config.client_id(), Some("cid-eu"));
    assert_eq!(config.dpop_key_id(), Some("kid-eu"));
    assert!(config.registration_access_token().is_none());
    assert!(config.registration_client_uri().is_none());
}

// -----------------------------------------------------------------
// Legacy migration: token value is correct
// -----------------------------------------------------------------

#[test]
fn test_legacy_migration_preserves_token_value() {
    let json = r#"{
        "server_url": "https://vouch.example.com",
        "token": "legacy-jwt-token-123"
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let t = config.token().expect("migrated token");
    assert_eq!(t.expose_secret(), "legacy-jwt-token-123");
}

// -----------------------------------------------------------------
// Legacy migration: registration_access_token value
// -----------------------------------------------------------------

#[test]
fn test_legacy_migration_preserves_rat_value() {
    let json = r#"{
        "server_url": "https://vouch.example.com",
        "registration_access_token": "legacy-rat-secret"
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    let rat = config.registration_access_token().expect("migrated RAT");
    assert_eq!(rat.expose_secret(), "legacy-rat-secret");
}

// -----------------------------------------------------------------
// New format: server entry with empty/missing fields
// -----------------------------------------------------------------

#[test]
fn test_server_entry_with_no_optional_fields() {
    let json = r#"{
        "current_server": "bare.vouch.sh",
        "servers": {
            "bare.vouch.sh": {
                "server_url": "https://bare.vouch.sh"
            }
        }
    }"#;

    let file: ConfigFile = serde_json::from_str(json).unwrap();
    let config = Config::from(file);

    assert_eq!(config.server_url(), Some("https://bare.vouch.sh"));
    assert!(config.token().is_none());
    assert!(config.client_id().is_none());
    assert!(config.dpop_key_id().is_none());
    assert!(config.registration_access_token().is_none());
    assert!(config.registration_client_uri().is_none());
}

// -----------------------------------------------------------------
// modify_at error contexts
// -----------------------------------------------------------------

/// A save-phase failure inside `modify_at` must surface the write
/// context, never a load-focused message: `vouch setup docker` once
/// wrapped `Config::modify` errors with "failed to load config - run
/// 'vouch enroll' first", misdiagnosing disk-full/permission errors
/// as a missing enrollment.
#[test]
fn modify_save_failure_reports_write_error_not_load_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("vouch");
    std::fs::create_dir_all(&cfg_dir).expect("create config dir");
    let cfg_path = cfg_dir.join("config.json");

    // Replace the config directory with a regular file after the load has
    // succeeded so the failure is isolated to the save phase. A file in
    // the directory's place (rather than chmod 0o555) fails even as root.
    let result = Config::modify_at(&cfg_path, |cfg| {
        cfg.set_docker_registry_profile(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com",
            "vouch-demo",
        );
        std::fs::remove_dir_all(&cfg_dir).expect("remove config dir");
        std::fs::write(&cfg_dir, b"not a directory").expect("shadow dir with file");
    });

    let msg = format!("{:#}", result.expect_err("save should fail"));
    assert!(
        msg.contains("failed to write config"),
        "expected save-phase context, got: {msg}"
    );
    assert!(
        !msg.contains("failed to load config"),
        "save-phase error must not say 'failed to load config': {msg}"
    );
    assert!(
        !msg.contains("enroll' first"),
        "save-phase error must not suggest enrolling: {msg}"
    );
}

/// A load-phase failure inside `modify_at` must surface the parse context
/// from `load_from` itself; callers need no wrapper of their own.
#[test]
fn modify_load_failure_reports_parse_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("vouch");
    std::fs::create_dir_all(&cfg_dir).expect("create config dir");
    let cfg_path = cfg_dir.join("config.json");
    std::fs::write(&cfg_path, "{ not valid json").expect("write corrupt config");

    let result = Config::modify_at(&cfg_path, |cfg| {
        cfg.set_docker_registry_profile("ghcr.io", "vouch-demo");
    });

    let msg = format!("{:#}", result.expect_err("load should fail"));
    assert!(
        msg.contains("failed to parse config"),
        "expected load-phase parse context, got: {msg}"
    );
    assert!(
        !msg.contains("enroll' first"),
        "load-phase error must not suggest enrolling: {msg}"
    );
}

// -----------------------------------------------------------------
// RFC 7592 §5 — client-side protection of the registration access token
// -----------------------------------------------------------------

/// RFC 7592 §5, applying the same "MUST be protected by the developer or
/// client" obligation to the token's on-disk copy: it must not be readable by
/// other users on the machine.
#[cfg(unix)]
#[test]
fn saved_config_holding_a_registration_token_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("vouch").join("config.json");

    let mut config = Config::default();
    config.set_server_url("https://vouch.example.com");
    config.set_registration_access_token("vouch_reg_on_disk_secret");
    config.save_to(&cfg_path).expect("save config");

    let mode = std::fs::metadata(&cfg_path)
        .expect("config metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "a config file holding a registration access token must be owner-only, got {mode:o}"
    );
}
