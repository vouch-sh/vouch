# Resource Indicators (RFC 8707)

This chapter describes Vouch's implementation of OAuth 2.0 Resource Indicators for audience-restricted tokens.

When a client includes the `resource` parameter in the authorization request, the resulting access token's `aud` claim is set to the target resource server URI instead of the `client_id`. This enables audience-restricted tokens — tokens that can only be used at the intended resource server, preventing token misdirection across services.

- Resource URIs must be absolute URIs without fragment components
- Resource URIs must be pre-registered on the OAuth client (closed by default)
- A single `resource` value per request is supported
- The `resource` parameter can be included at authorization time and optionally repeated at token exchange time (it cannot be widened, only confirmed)
- Discovery metadata advertises `resource_indicators_supported: true`
