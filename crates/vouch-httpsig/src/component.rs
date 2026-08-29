// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 component identifiers and resolution.
//!
//! Components are the building blocks of HTTP message signatures. They identify
//! which parts of an HTTP message are included in the signature base.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::HttpSigError;
use crate::sfv::types::{SfvBareItem, SfvDictMember, SfvItem, SfvParams};

/// Derived components (Section 2.2 of RFC 9421).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerivedComponent {
    /// `@method` — the HTTP request method (uppercase).
    Method,
    /// `@target-uri` — the full target URI of the request.
    TargetUri,
    /// `@authority` — the authority (host[:port]) of the target URI.
    Authority,
    /// `@scheme` — the scheme of the target URI.
    Scheme,
    /// `@request-target` — the request target (path + query).
    RequestTarget,
    /// `@path` — the path component of the target URI.
    Path,
    /// `@query` — the query component of the target URI.
    Query,
    /// `@query-param` — a specific query parameter (requires `name` param).
    QueryParam { name: String },
    /// `@status` — the HTTP response status code.
    Status,
}

/// Parameters that can be applied to a component identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentParams {
    /// Structured field (`;sf`) — treat the field value as a structured field.
    pub sf: bool,
    /// Dictionary member key (`;key="name"`) — extract a specific key from an SFV Dictionary.
    pub key: Option<String>,
    /// Query parameter name (`;name="x"`) — used by `@query-param` (RFC 9421 §2.2.8).
    pub name: Option<String>,
    /// Binary-wrapped (`;bs`) — base64-encode the field value.
    pub bs: bool,
    /// Request-bound (`;req`) — resolve from the related request.
    pub req: bool,
    /// Trailer (`;tr`) — resolve from trailers.
    pub tr: bool,
}

/// A component identifier: either a field name or a derived component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComponentIdentifier {
    /// An HTTP field (header) by name.
    Field {
        name: String,
        params: ComponentParams,
    },
    /// A derived component (prefixed with `@`).
    Derived {
        component: DerivedComponent,
        params: ComponentParams,
    },
}

impl ComponentIdentifier {
    /// The bare component name, without parameters.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Field { name, .. } => name.clone(),
            Self::Derived { component, .. } => derived_component_name(component),
        }
    }

    /// Whether this covered component satisfies a requirement for `required`.
    ///
    /// Compares by name: a requirement for `@path` is met by the signature's
    /// `@path` regardless of the parameters either carries.
    #[must_use]
    pub fn covers(&self, required: &Self) -> bool {
        self.name() == required.name()
    }

    /// Create a derived `@method` component.
    #[must_use]
    pub fn method() -> Self {
        Self::Derived {
            component: DerivedComponent::Method,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@authority` component.
    #[must_use]
    pub fn authority() -> Self {
        Self::Derived {
            component: DerivedComponent::Authority,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@path` component.
    #[must_use]
    pub fn path() -> Self {
        Self::Derived {
            component: DerivedComponent::Path,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@query` component.
    #[must_use]
    pub fn query() -> Self {
        Self::Derived {
            component: DerivedComponent::Query,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@target-uri` component.
    #[must_use]
    pub fn target_uri() -> Self {
        Self::Derived {
            component: DerivedComponent::TargetUri,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@scheme` component.
    #[must_use]
    pub fn scheme() -> Self {
        Self::Derived {
            component: DerivedComponent::Scheme,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@request-target` component.
    #[must_use]
    pub fn request_target() -> Self {
        Self::Derived {
            component: DerivedComponent::RequestTarget,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@status` component.
    #[must_use]
    pub fn status() -> Self {
        Self::Derived {
            component: DerivedComponent::Status,
            params: ComponentParams::default(),
        }
    }

    /// Create a derived `@query-param` component.
    #[must_use]
    pub fn query_param(name: &str) -> Self {
        Self::Derived {
            component: DerivedComponent::QueryParam {
                name: name.to_string(),
            },
            params: ComponentParams::default(),
        }
    }

    /// Create an HTTP field component.
    #[must_use]
    pub fn field(name: &str) -> Self {
        Self::Field {
            name: name.to_ascii_lowercase(),
            params: ComponentParams::default(),
        }
    }

    /// Serialize this component identifier to an SFV Item for use in
    /// the `@signature-params` inner list.
    #[must_use]
    pub fn to_sfv_item(&self) -> SfvItem {
        let (name, component_params) = match self {
            Self::Field { name, params } => (name.as_str(), params),
            Self::Derived { component, params } => (derived_name(component), params),
        };

        let mut sfv_params = SfvParams::new();
        if component_params.sf {
            sfv_params.insert("sf".into(), None);
        }
        // RFC 9421 Section 2.2.8: @query-param uses ;name=, not ;key=
        if let Self::Derived {
            component: DerivedComponent::QueryParam { name: qp_name },
            ..
        } = self
        {
            sfv_params.insert("name".into(), Some(SfvBareItem::String(qp_name.clone())));
        } else if let Some(key) = &component_params.key {
            sfv_params.insert("key".into(), Some(SfvBareItem::String(key.clone())));
        }
        if component_params.bs {
            sfv_params.insert("bs".into(), None);
        }
        if component_params.req {
            sfv_params.insert("req".into(), None);
        }
        if component_params.tr {
            sfv_params.insert("tr".into(), None);
        }

        SfvItem {
            value: SfvBareItem::String(name.to_string()),
            params: sfv_params,
        }
    }

    /// Parse a component identifier from an SFV Item.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::InvalidComponent`] if the item cannot be parsed.
    pub fn from_sfv_item(item: &SfvItem) -> Result<Self, HttpSigError> {
        let name = match &item.value {
            SfvBareItem::String(s) => s.as_str(),
            _ => {
                return Err(HttpSigError::InvalidComponent(
                    "component identifier must be a string".into(),
                ));
            }
        };

        let params = parse_component_params(&item.params)?;

        if let Some(stripped) = name.strip_prefix('@') {
            let component = parse_derived_name(stripped, &params)?;
            Ok(Self::Derived { component, params })
        } else {
            Ok(Self::Field {
                name: name.to_ascii_lowercase(),
                params,
            })
        }
    }

    /// Resolve the value of this component from an HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingComponent`] if the component cannot be resolved.
    pub fn resolve_from_request<T>(&self, req: &http::Request<T>) -> Result<String, HttpSigError> {
        match self {
            Self::Field { name, params } => {
                reject_trailers(params)?;
                resolve_field(req.headers(), name, params)
            }
            Self::Derived { component, .. } => resolve_derived_from_request(component, req),
        }
    }

    /// Resolve the value of this component from an HTTP response.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingComponent`] if the component cannot be resolved.
    pub fn resolve_from_response<T, U>(
        &self,
        resp: &http::Response<T>,
        req: Option<&http::Request<U>>,
    ) -> Result<String, HttpSigError> {
        match self {
            Self::Field { name, params } => {
                reject_trailers(params)?;
                if params.req {
                    let request = req.ok_or_else(|| {
                        HttpSigError::MissingComponent(
                            "req flag set but no request provided".into(),
                        )
                    })?;
                    resolve_field(request.headers(), name, params)
                } else {
                    resolve_field(resp.headers(), name, params)
                }
            }
            Self::Derived { component, params } => {
                if params.req {
                    let request = req.ok_or_else(|| {
                        HttpSigError::MissingComponent(
                            "req flag set but no request provided".into(),
                        )
                    })?;
                    resolve_derived_from_request(component, request)
                } else {
                    resolve_derived_from_response(component, resp)
                }
            }
        }
    }

    /// Serialize this component identifier to the string form used in
    /// the signature base (the left side of the `:` line).
    #[must_use]
    pub fn serialize_id(&self) -> String {
        crate::sfv::serialize::serialize_item(&self.to_sfv_item())
    }
}

/// Get the canonical name of a derived component (e.g., `"@method"`).
#[must_use]
pub fn derived_component_name(component: &DerivedComponent) -> String {
    derived_name(component).to_string()
}

fn derived_name(component: &DerivedComponent) -> &'static str {
    match component {
        DerivedComponent::Method => "@method",
        DerivedComponent::TargetUri => "@target-uri",
        DerivedComponent::Authority => "@authority",
        DerivedComponent::Scheme => "@scheme",
        DerivedComponent::RequestTarget => "@request-target",
        DerivedComponent::Path => "@path",
        DerivedComponent::Query => "@query",
        DerivedComponent::QueryParam { .. } => "@query-param",
        DerivedComponent::Status => "@status",
    }
}

fn parse_derived_name(
    name: &str,
    params: &ComponentParams,
) -> Result<DerivedComponent, HttpSigError> {
    match name {
        "method" => Ok(DerivedComponent::Method),
        "target-uri" => Ok(DerivedComponent::TargetUri),
        "authority" => Ok(DerivedComponent::Authority),
        "scheme" => Ok(DerivedComponent::Scheme),
        "request-target" => Ok(DerivedComponent::RequestTarget),
        "path" => Ok(DerivedComponent::Path),
        "query" => Ok(DerivedComponent::Query),
        "query-param" => {
            let qp_name = params.name.as_ref().ok_or_else(|| {
                HttpSigError::InvalidComponent("@query-param requires ;name parameter".into())
            })?;
            Ok(DerivedComponent::QueryParam {
                name: qp_name.clone(),
            })
        }
        "status" => Ok(DerivedComponent::Status),
        _ => Err(HttpSigError::InvalidComponent(format!(
            "unknown derived component: @{name}"
        ))),
    }
}

fn parse_component_params(sfv: &SfvParams) -> Result<ComponentParams, HttpSigError> {
    let mut params = ComponentParams::default();

    if sfv.contains_key("sf") {
        params.sf = true;
    }
    if let Some(Some(SfvBareItem::String(k))) = sfv.get("key") {
        params.key = Some(k.clone());
    }
    // @query-param uses ;name= (RFC 9421 §2.2.8) — stored separately from ;key=
    if let Some(Some(SfvBareItem::String(n))) = sfv.get("name") {
        params.name = Some(n.clone());
    }
    if sfv.contains_key("bs") {
        params.bs = true;
    }
    if sfv.contains_key("req") {
        params.req = true;
    }
    if sfv.contains_key("tr") {
        params.tr = true;
    }

    Ok(params)
}

/// Reject `;tr` (trailer) components — the `http` crate does not model trailers.
fn reject_trailers(params: &ComponentParams) -> Result<(), HttpSigError> {
    if params.tr {
        return Err(HttpSigError::InvalidComponent(
            "trailer fields (;tr) are not supported — \
             the http crate does not model HTTP trailers"
                .into(),
        ));
    }
    Ok(())
}

/// Resolve an HTTP field value from headers, applying `;sf`, `;key`, and `;bs` parameters.
fn resolve_field(
    headers: &http::HeaderMap,
    name: &str,
    params: &ComponentParams,
) -> Result<String, HttpSigError> {
    // name is already lowercased by ComponentIdentifier::field()
    let lower = name;

    // §2.1.3: Binary-wrapped (;bs) — each field line individually base64-encoded
    if params.bs {
        return resolve_field_bs(headers, lower);
    }

    let raw = resolve_field_raw(headers, lower)?;

    // §2.1.1 + §2.1.2: Structured Field with optional key extraction
    if params.sf || params.key.is_some() {
        return resolve_field_sf(headers, lower, params);
    }

    Ok(raw)
}

/// Get the raw combined field value (no SFV processing).
fn resolve_field_raw(headers: &http::HeaderMap, lower_name: &str) -> Result<String, HttpSigError> {
    let mut iter = headers.get_all(lower_name).iter();

    let first = iter.next().and_then(|v| v.to_str().ok()).ok_or_else(|| {
        HttpSigError::MissingComponent(format!("header '{lower_name}' not found"))
    })?;

    // Fast path: single-value header (the overwhelmingly common case)
    let second = iter.next();
    if second.is_none() {
        return Ok(first.trim().to_string());
    }

    // Multi-value: combine with ", " per RFC 9421 §2.1
    let mut result = String::from(first.trim());
    if let Some(v) = second.and_then(|v| v.to_str().ok()) {
        result.push_str(", ");
        result.push_str(v.trim());
    }
    for val in iter {
        if let Ok(v) = val.to_str() {
            result.push_str(", ");
            result.push_str(v.trim());
        }
    }
    Ok(result)
}

/// §2.1.1 / §2.1.2: Resolve a field as a Structured Field, optionally extracting
/// a dictionary member by key.
///
/// When `;key` is present, the field is parsed as an SFV Dictionary and the
/// specified member is extracted and serialized.
///
/// When only `;sf` is present (no `;key`), the field is parsed as SFV and
/// re-serialized to canonicalize whitespace and formatting.
fn resolve_field_sf(
    headers: &http::HeaderMap,
    lower_name: &str,
    params: &ComponentParams,
) -> Result<String, HttpSigError> {
    let raw = resolve_field_raw(headers, lower_name)?;

    if let Some(key) = &params.key {
        // §2.1.2: Parse as Dictionary, extract member by key
        let dict = crate::sfv::parse::parse_dictionary(&raw).map_err(|e| {
            HttpSigError::InvalidComponent(format!(
                "failed to parse '{lower_name}' as SFV Dictionary for ;key=\"{key}\": {e}"
            ))
        })?;

        let member = dict.get(key).ok_or_else(|| {
            HttpSigError::MissingComponent(format!(
                "dictionary key '{key}' not found in header '{lower_name}'"
            ))
        })?;

        Ok(serialize_dict_member_value(member))
    } else {
        // §2.1.1: Parse as SFV and re-serialize for canonicalization.
        // Try Dictionary first, then List, then Item.
        if let Ok(dict) = crate::sfv::parse::parse_dictionary(&raw) {
            return Ok(crate::sfv::serialize::serialize_dictionary(&dict));
        }
        if let Ok(list) = crate::sfv::parse::parse_list(&raw) {
            return Ok(crate::sfv::serialize::serialize_list(&list));
        }
        if let Ok(item) = crate::sfv::parse::parse_item(&raw) {
            return Ok(crate::sfv::serialize::serialize_item(&item));
        }

        Err(HttpSigError::InvalidComponent(format!(
            "failed to parse '{lower_name}' as any SFV type for ;sf"
        )))
    }
}

/// Serialize an SFV dictionary member value (Item or Inner List) to a string.
fn serialize_dict_member_value(member: &SfvDictMember) -> String {
    match member {
        SfvDictMember::Item(item) => crate::sfv::serialize::serialize_item(item),
        SfvDictMember::InnerList(list) => {
            crate::sfv::serialize::serialize_inner_list_to_string(list)
        }
    }
}

/// §2.1.3: Binary-wrapped (;bs) — each field line is individually
/// base64-encoded as an SFV Byte Sequence, then combined with ", ".
fn resolve_field_bs(headers: &http::HeaderMap, lower_name: &str) -> Result<String, HttpSigError> {
    let values: Vec<&http::HeaderValue> = headers.get_all(lower_name).iter().collect();

    if values.is_empty() {
        return Err(HttpSigError::MissingComponent(format!(
            "header '{lower_name}' not found"
        )));
    }

    let encoded: Vec<String> = values
        .iter()
        .map(|v| {
            // RFC 9421 Section 2.1.3 step 3.1: strip leading/trailing whitespace
            // from the field value before encoding (step 3.3). OWS is defined as
            // SP and HTAB (RFC 9110 §5.6.3); trim at the byte level so this works
            // for both UTF-8 and non-UTF-8 field values.
            let b64 = STANDARD.encode(trim_ascii_ows(v.as_bytes()));
            format!(":{b64}:")
        })
        .collect();

    Ok(encoded.join(", "))
}

/// Strip leading/trailing HTTP optional whitespace (OWS: SP and HTAB) from a
/// byte slice. Operates on raw bytes so it is valid for non-UTF-8 values.
fn trim_ascii_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i.saturating_add(1));
    bytes.get(start..end).unwrap_or(&[])
}

/// Resolve a derived component value from an HTTP request.
fn resolve_derived_from_request<T>(
    component: &DerivedComponent,
    req: &http::Request<T>,
) -> Result<String, HttpSigError> {
    match component {
        DerivedComponent::Method => Ok(req.method().as_str().to_string()),
        DerivedComponent::TargetUri => {
            // Reconstruct from scheme + authority + path + query
            let scheme = extract_scheme(req)?;
            let authority = extract_authority(req)?;
            let path = extract_path(req);
            let query = req.uri().query().map(|q| format!("?{q}"));
            Ok(format!(
                "{scheme}://{authority}{path}{}",
                query.unwrap_or_default()
            ))
        }
        DerivedComponent::Authority => extract_authority(req),
        DerivedComponent::Scheme => extract_scheme(req),
        DerivedComponent::RequestTarget => {
            let path = extract_path(req);
            match req.uri().query() {
                Some(q) => Ok(format!("{path}?{q}")),
                None => Ok(path),
            }
        }
        DerivedComponent::Path => Ok(extract_path(req)),
        DerivedComponent::Query => {
            // RFC 9421 Section 2.2.7: absent query = "?"
            match req.uri().query() {
                Some(q) => Ok(format!("?{q}")),
                None => Ok("?".into()),
            }
        }
        DerivedComponent::QueryParam { name } => {
            let query = req.uri().query().ok_or_else(|| {
                HttpSigError::MissingComponent(format!(
                    "no query string for @query-param;name=\"{name}\""
                ))
            })?;
            // Parse query parameters and find the matching one
            for pair in query.split('&') {
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                if url_decode(k) == *name {
                    return Ok(url_decode(v));
                }
            }
            Err(HttpSigError::MissingComponent(format!(
                "query parameter '{name}' not found"
            )))
        }
        DerivedComponent::Status => Err(HttpSigError::InvalidComponent(
            "@status is only valid for responses".into(),
        )),
    }
}

/// Resolve a derived component value from an HTTP response.
fn resolve_derived_from_response<T>(
    component: &DerivedComponent,
    resp: &http::Response<T>,
) -> Result<String, HttpSigError> {
    match component {
        DerivedComponent::Status => Ok(resp.status().as_u16().to_string()),
        _ => Err(HttpSigError::InvalidComponent(format!(
            "{} is only valid for requests (use ;req for response context)",
            derived_name(component)
        ))),
    }
}

/// Extract the scheme from a request URI.
fn extract_scheme<T>(req: &http::Request<T>) -> Result<String, HttpSigError> {
    req.uri()
        .scheme_str()
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| HttpSigError::MissingComponent("URI has no scheme".into()))
}

/// Extract the authority from a request, lowercased, with default ports omitted.
///
/// Tries `req.uri().host()` first (HTTP/2 or absolute-form requests), then
/// falls back to the `Host` header (HTTP/1.1 origin-form requests) per
/// RFC 9421 §2.2.3 and RFC 9110 §7.2.
fn extract_authority<T>(req: &http::Request<T>) -> Result<String, HttpSigError> {
    // Try URI first (HTTP/2 or absolute-form requests)
    if let Some(host) = req.uri().host() {
        let host = host.to_ascii_lowercase();
        let scheme = req.uri().scheme_str().unwrap_or("https");
        let port = req.uri().port_u16();

        // Omit default ports per RFC 9421
        let is_default_port = matches!(
            (scheme, port),
            ("http", Some(80)) | ("https", Some(443)) | (_, None)
        );

        return if is_default_port {
            Ok(host)
        } else if let Some(p) = port {
            Ok(format!("{host}:{p}"))
        } else {
            Ok(host)
        };
    }

    // Fall back to Host header (HTTP/1.1 origin-form requests).
    // RFC 9421 §2.2.3 requires authority normalization: lowercase + strip
    // default ports. Some HTTP/1.1 clients emit `Host: example.com:443` with
    // an explicit default port; the URI-derived path above strips it, so this
    // path must too — otherwise the signer (URI path) and verifier (Host
    // fallback path) disagree on the authority component and signature
    // verification fails.
    //
    // Stripping is scheme-aware to match the URI-derived path: `:443` is only
    // a default port for `https`, `:80` only for `http`. When the URI has no
    // scheme (origin-form HTTP/1.1), we default to `https` to mirror path A's
    // `unwrap_or("https")` behavior — this is correct for the dominant
    // deployment (HTTPS on 443). Non-standard combinations (HTTPS on 80, HTTP
    // on 443) rely on the scheme being available via `req.uri().scheme_str()`
    // — typically only present for absolute-form or HTTP/2 requests.
    let host_header = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            HttpSigError::MissingComponent("URI has no authority and no Host header".into())
        })?;

    let scheme = req.uri().scheme_str().unwrap_or("https");
    let normalized = host_header.trim().to_ascii_lowercase();
    let stripped = match scheme {
        "https" => normalized
            .strip_suffix(":443")
            .map(str::to_string)
            .unwrap_or(normalized),
        "http" => normalized
            .strip_suffix(":80")
            .map(str::to_string)
            .unwrap_or(normalized),
        _ => normalized,
    };
    Ok(stripped)
}

/// Extract the path from a request URI. Empty path becomes "/".
fn extract_path<T>(req: &http::Request<T>) -> String {
    let path = req.uri().path();
    if path.is_empty() {
        "/".into()
    } else {
        path.into()
    }
}

/// RFC 3986 percent-decoding for query parameter names/values.
///
/// Note: `+` is NOT decoded as space — that is `application/x-www-form-urlencoded`
/// (RFC 1866), not RFC 3986. RFC 9421 §2.2.8 references RFC 3986 percent-encoding.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while let Some(&c) = bytes.get(i) {
        if c == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex_val);
            let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(char::from(h << 4 | l));
                i = i.saturating_add(3);
                continue;
            }
        }
        result.push(char::from(c));
        i = i.saturating_add(1);
    }

    result
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    // RFC 9421 §2.2.1: @method is the request method, uppercased.
    #[test]
    fn test_method_resolution() {
        let req = make_request("POST", "https://example.com/path", &[]);
        let cid = ComponentIdentifier::method();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "POST");
    }

    // RFC 9421 §2.2.3: @authority is the request authority.
    #[test]
    fn test_authority_resolution() {
        let req = make_request("GET", "https://example.com/path", &[]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: a non-default port stays in the authority.
    #[test]
    fn test_authority_with_port() {
        let req = make_request("GET", "https://example.com:8443/path", &[]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com:8443");
    }

    // RFC 9421 §2.2.3: normalized per HTTP §4.2.3: the default https port is elided.
    #[test]
    fn test_authority_omits_default_https_port() {
        let req = make_request("GET", "https://example.com:443/path", &[]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: normalized per HTTP §4.2.3: the default http port is elided.
    #[test]
    fn test_authority_omits_default_http_port() {
        let req = make_request("GET", "http://example.com:80/path", &[]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: origin-form request: authority comes from the Host field.
    #[test]
    fn test_authority_from_host_header() {
        // Path-only URI (HTTP/1.1 origin-form) — falls back to Host header
        let req = make_request("POST", "/v1/credentials/ssh", &[("host", "example.com")]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: Host-derived authority keeps a non-default port.
    #[test]
    fn test_authority_from_host_header_with_port() {
        let req = make_request("POST", "/v1/credentials/ssh", &[("host", "localhost:3000")]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "localhost:3000");
    }

    // RFC 9421 §2.2.3: Host-derived authority is normalized the same way as the URI-derived one.
    #[test]
    fn test_authority_host_header_strips_default_https_port() {
        // Some HTTP/1.1 clients emit Host with explicit :443. The URI-derived
        // path strips it; the Host fallback must too, or the signer's authority
        // ("example.com") will not match the verifier's ("example.com:443").
        // With no URI scheme available, fallback defaults to "https".
        let req = make_request(
            "POST",
            "/v1/credentials/ssh",
            &[("host", "example.com:443")],
        );
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: the component value MUST be normalized per HTTP §4.2.3 (lowercase host).
    #[test]
    fn test_authority_host_header_lowercase_and_strip() {
        let req = make_request("POST", "/v1/foo", &[("host", "Example.COM:443")]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com");
    }

    // RFC 9421 §2.2.3: only the scheme's own default port is elided.
    #[test]
    fn test_authority_host_header_keeps_non_default_port() {
        // Scheme defaults to "https" when URI has none; :80 is not the
        // default port for https, so it must NOT be stripped.
        let req = make_request("POST", "/v1/foo", &[("host", "example.com:80")]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com:80");
    }

    // RFC 9421 §2.2.3: an arbitrary port is preserved.
    #[test]
    fn test_authority_host_header_keeps_arbitrary_port() {
        let req = make_request("POST", "/v1/foo", &[("host", "example.com:8443")]);
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "example.com:8443");
    }

    // RFC 9421 §2.2.3: signer and verifier derive the same authority from
    // either source.
    #[test]
    fn test_authority_uri_and_host_header_agree_on_default_port() {
        // Cross-check: client signs via URI path with default port stripped,
        // server verifies via Host header path with default port stripped.
        // Both should produce the same authority string.
        let client_req = make_request("POST", "https://dev.vouch.sh/v1/credentials/ssh", &[]);
        let server_req = make_request(
            "POST",
            "/v1/credentials/ssh",
            &[("host", "dev.vouch.sh:443")],
        );
        let cid = ComponentIdentifier::authority();
        let client_authority = cid.resolve_from_request(&client_req).unwrap();
        let server_authority = cid.resolve_from_request(&server_req).unwrap();
        assert_eq!(client_authority, server_authority);
        assert_eq!(client_authority, "dev.vouch.sh");
    }

    // RFC 9421 §2.2.3: absolute-form request: the URI supplies the authority.
    #[test]
    fn test_authority_uri_preferred_over_host() {
        // Full URI takes precedence over Host header
        let req = make_request(
            "GET",
            "https://from-uri.com/path",
            &[("host", "from-header.com")],
        );
        let cid = ComponentIdentifier::authority();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "from-uri.com");
    }

    // RFC 9421 §2.2.6: @path is the absolute path portion of the target URI.
    #[test]
    fn test_path_resolution() {
        let req = make_request("GET", "https://example.com/foo/bar", &[]);
        let cid = ComponentIdentifier::path();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "/foo/bar");
    }

    // RFC 9421 §2.2.6: an empty path is normalized to a single slash.
    #[test]
    fn test_path_empty_becomes_slash() {
        let req = make_request("GET", "https://example.com", &[]);
        let cid = ComponentIdentifier::path();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "/");
    }

    // RFC 9421 §2.2.7: @query is the query string including the leading question mark.
    #[test]
    fn test_query_resolution() {
        let req = make_request("GET", "https://example.com/path?a=1&b=2", &[]);
        let cid = ComponentIdentifier::query();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "?a=1&b=2");
    }

    // RFC 9421 §2.2.7: an absent query is represented as a bare question mark.
    #[test]
    fn test_query_absent_becomes_question_mark() {
        let req = make_request("GET", "https://example.com/path", &[]);
        let cid = ComponentIdentifier::query();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "?");
    }

    // RFC 9421 §2.2.4: @scheme MUST be normalized to lowercase for the signature base.
    #[test]
    fn test_scheme_resolution() {
        let req = make_request("GET", "https://example.com/path", &[]);
        let cid = ComponentIdentifier::scheme();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "https");
    }

    // RFC 9421 §2.2.2: @target-uri is the full absolute target URI.
    #[test]
    fn test_target_uri_resolution() {
        let req = make_request("GET", "https://example.com/path?q=1", &[]);
        let cid = ComponentIdentifier::target_uri();
        assert_eq!(
            cid.resolve_from_request(&req).unwrap(),
            "https://example.com/path?q=1"
        );
    }

    // RFC 9421 §2.2.5: @request-target is the request target as sent on the wire.
    #[test]
    fn test_request_target_resolution() {
        let req = make_request("GET", "https://example.com/path?q=1", &[]);
        let cid = ComponentIdentifier::request_target();
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "/path?q=1");
    }

    // RFC 9421 §2.1: a field component resolves to that field's value.
    #[test]
    fn test_field_resolution() {
        let req = make_request(
            "GET",
            "https://example.com/",
            &[("content-type", "application/json")],
        );
        let cid = ComponentIdentifier::field("content-type");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "application/json");
    }

    // RFC 9421 §2.1: field names are matched case-insensitively.
    #[test]
    fn test_field_case_insensitive() {
        let req = make_request(
            "GET",
            "https://example.com/",
            &[("Content-Type", "text/plain")],
        );
        let cid = ComponentIdentifier::field("content-type");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "text/plain");
    }

    // RFC 9421 §2.1: a named field absent from the message is an error in
    // signature base generation.
    #[test]
    fn test_field_missing_returns_error() {
        let req = make_request("GET", "https://example.com/", &[]);
        let cid = ComponentIdentifier::field("x-missing");
        assert!(cid.resolve_from_request(&req).is_err());
    }

    // RFC 9421 §2.2.8: @query-param resolves the named query parameter.
    #[test]
    fn test_query_param_resolution() {
        let req = make_request("GET", "https://example.com/path?name=value&other=2", &[]);
        let cid = ComponentIdentifier::query_param("name");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "value");
    }

    // RFC 9421 §2.2.8: query parameters are parsed per the HTML URL rules,
    // which leave malformed percent-escapes intact.
    #[test]
    fn test_url_decode_preserves_malformed_percent_encoding() {
        assert_eq!(url_decode("%2G"), "%2G");
        assert_eq!(url_decode("foo%2"), "foo%2");
        assert_eq!(url_decode("%ZZhello"), "%ZZhello");
    }

    // RFC 9421 §2.2.8: valid percent-escapes are decoded before inclusion.
    #[test]
    fn test_url_decode_decodes_valid_percent_encoding() {
        assert_eq!(url_decode("name%20with%20space"), "name with space");
    }

    // RFC 9421 §2.2.9: @status is the response status code.
    #[test]
    fn test_status_from_response() {
        let resp = http::Response::builder().status(200).body(()).unwrap();
        let cid = ComponentIdentifier::status();
        assert_eq!(
            cid.resolve_from_response::<(), ()>(&resp, None).unwrap(),
            "200"
        );
    }

    #[test]
    fn test_sfv_item_roundtrip() {
        let cid = ComponentIdentifier::field("content-type");
        let item = cid.to_sfv_item();
        let parsed = ComponentIdentifier::from_sfv_item(&item).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn test_serialize_id() {
        let cid = ComponentIdentifier::method();
        assert_eq!(cid.serialize_id(), "\"@method\"");
    }

    #[test]
    fn test_serialize_id_field() {
        let cid = ComponentIdentifier::field("content-type");
        assert_eq!(cid.serialize_id(), "\"content-type\"");
    }

    // ;sf tests

    // RFC 9421 §2.1.1: with ;sf the field value MUST be re-serialized using
    // the strict structured-field rules.
    #[test]
    fn test_sf_canonicalizes_item() {
        // SFV Item with extra whitespace in params gets canonicalized
        let req = make_request("GET", "https://example.com/", &[("x-val", "42")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                sf: true,
                ..ComponentParams::default()
            },
        };
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "42");
    }

    // RFC 9421 §2.1.1: with ;sf a Dictionary field is re-serialized canonically.
    #[test]
    fn test_sf_canonicalizes_dictionary() {
        let req = make_request("GET", "https://example.com/", &[("x-dict", "a=1, b=2")]);
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams {
                sf: true,
                ..ComponentParams::default()
            },
        };
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "a=1, b=2");
    }

    // ;key tests

    // RFC 9421 §2.1.2: with ;key the component value is the named Dictionary member.
    #[test]
    fn test_key_extracts_dict_member() {
        let req = make_request(
            "GET",
            "https://example.com/",
            &[("x-dict", "a=1, b=2, c=3")],
        );
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams {
                key: Some("b".into()),
                ..ComponentParams::default()
            },
        };
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "2");
    }

    // RFC 9421 §2.1.2: a Dictionary key named as a covered component but
    // absent MUST cause an error.
    #[test]
    fn test_key_missing_returns_error() {
        let req = make_request("GET", "https://example.com/", &[("x-dict", "a=1, b=2")]);
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams {
                key: Some("z".into()),
                ..ComponentParams::default()
            },
        };
        assert!(cid.resolve_from_request(&req).is_err());
    }

    // RFC 9421 §2.1.2: a Boolean-true Dictionary member serializes as the bare key.
    #[test]
    fn test_key_extracts_boolean_true_member() {
        let req = make_request("GET", "https://example.com/", &[("x-dict", "a, b=2")]);
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams {
                key: Some("a".into()),
                ..ComponentParams::default()
            },
        };
        // Boolean true dict member serializes as "?1"
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "?1");
    }

    // ;bs tests

    // RFC 9421 §2.1.3: with ;bs the component value is the byte-sequence-wrapped field value.
    #[test]
    fn test_bs_encodes_single_value() {
        let req = make_request("GET", "https://example.com/", &[("x-val", "hello")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        // "hello" base64 = "aGVsbG8="
        assert_eq!(result, ":aGVsbG8=:");
    }

    // RFC 9421 §2.1.3: with ;bs each field value is wrapped separately and combined into a List.
    #[test]
    fn test_bs_encodes_multiple_values() {
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("x-multi", "first")
            .header("x-multi", "second")
            .body(())
            .unwrap();
        let _ = &mut req; // suppress unused warning
        let cid = ComponentIdentifier::Field {
            name: "x-multi".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        // Each field line individually encoded, combined with ", "
        // "first" = "Zmlyc3Q=", "second" = "c2Vjb25k"
        assert_eq!(result, ":Zmlyc3Q=:, :c2Vjb25k:");
        assert!(result.contains(", "));
        assert!(result.starts_with(':'));
    }

    // RFC 9421 §2.1.3 step 3.1: with ;bs leading/trailing OWS (SP) is stripped
    // before base64 encoding. "  hello  " must encode "hello", not "  hello  ".
    #[test]
    fn test_bs_trims_leading_trailing_spaces() {
        let req = make_request("GET", "https://example.com/", &[("x-val", "  hello  ")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        // base64 of "hello" = "aGVsbG8="; base64 of "  hello  " = "ICBoZWxsbyAg"
        assert_eq!(result, ":aGVsbG8=:");
    }

    // RFC 9421 §2.1.3 step 3.1: HTAB is HTTP optional whitespace (OWS) and must
    // be trimmed alongside SP.
    #[test]
    fn test_bs_trims_leading_trailing_tabs() {
        let req = make_request("GET", "https://example.com/", &[("x-val", "\thello\t")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        assert_eq!(result, ":aGVsbG8=:");
    }

    // RFC 9421 §2.1.3: only leading/trailing OWS is stripped; internal
    // whitespace is preserved as part of the field value (step 3.3 encodes
    // the resulting value).
    #[test]
    fn test_bs_preserves_internal_whitespace() {
        let req = make_request(
            "GET",
            "https://example.com/",
            &[("x-val", "  hello  world  ")],
        );
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        let b64 = result
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        assert_eq!(STANDARD.decode(b64).unwrap(), b"hello  world");
    }

    // RFC 9421 §2.1.3: for multiple field lines, each is trimmed independently
    // before encoding and combined with ", ".
    #[test]
    fn test_bs_trims_each_multiline_value() {
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("x-multi", "  first  ")
            .header("x-multi", "  second  ")
            .body(())
            .unwrap();
        let _ = &mut req;
        let cid = ComponentIdentifier::Field {
            name: "x-multi".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        assert_eq!(result, ":Zmlyc3Q=:, :c2Vjb25k:");
    }

    // RFC 9421 §2.1.3 step 3.1: a value that is entirely OWS yields an empty
    // Byte Sequence (base64 of "" = "").
    #[test]
    fn test_bs_all_whitespace_value() {
        let req = make_request("GET", "https://example.com/", &[("x-val", "   \t  ")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        // base64 of "" is "", so the wrapped Byte Sequence is "::" (two colons).
        assert_eq!(result, "::");
    }

    // RFC 9421 §2.1.3: ;bs preserves non-UTF-8 / binary field values byte-for-byte
    // (minus leading/trailing OWS). The trimming is byte-level, not UTF-8 level.
    #[test]
    fn test_bs_non_utf8_value() {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header(
                "x-bin",
                http::HeaderValue::from_bytes(b" \xff\xfe bin ").unwrap(),
            )
            .body(())
            .unwrap();
        let cid = ComponentIdentifier::Field {
            name: "x-bin".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        let b64 = result
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        assert_eq!(STANDARD.decode(b64).unwrap(), b"\xff\xfe bin");
    }

    // RFC 9421 §2.1.3 example: a header with internal commas is encoded
    // verbatim (no list-splitting) per field line.
    #[test]
    fn test_bs_rfc_example_with_commas() {
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .header("example-header", "value, with, lots")
            .header("example-header", "of, commas")
            .body(())
            .unwrap();
        let _ = &mut req;
        let cid = ComponentIdentifier::Field {
            name: "example-header".into(),
            params: ComponentParams {
                bs: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req).unwrap();
        // Matches the RFC 9421 §2.1.3 example base.
        assert_eq!(result, ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:");
    }

    // ;tr tests

    // RFC 9421 §2.1.4: trailer fields are only available with the ;tr parameter.
    #[test]
    fn test_tr_returns_error() {
        let req = make_request("GET", "https://example.com/", &[("x-val", "1")]);
        let cid = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams {
                tr: true,
                ..ComponentParams::default()
            },
        };
        let result = cid.resolve_from_request(&req);
        assert!(result.is_err());
    }

    // ;req on derived components

    // RFC 9421 §2.4: with ;req a response signature covers the request's component value.
    #[test]
    fn test_req_on_derived_in_response() {
        let req = make_request("POST", "https://example.com/foo", &[]);
        let resp = http::Response::builder().status(200).body(()).unwrap();

        // @method;req should resolve from the request
        let cid = ComponentIdentifier::Derived {
            component: DerivedComponent::Method,
            params: ComponentParams {
                req: true,
                ..ComponentParams::default()
            },
        };
        assert_eq!(
            cid.resolve_from_response(&resp, Some(&req)).unwrap(),
            "POST"
        );
    }

    // RFC 9421 §2.4: with ;req the request's @authority is covered by the response signature.
    #[test]
    fn test_req_on_authority_in_response() {
        let req = make_request("GET", "https://example.com/path", &[]);
        let resp = http::Response::builder().status(200).body(()).unwrap();

        let cid = ComponentIdentifier::Derived {
            component: DerivedComponent::Authority,
            params: ComponentParams {
                req: true,
                ..ComponentParams::default()
            },
        };
        assert_eq!(
            cid.resolve_from_response(&resp, Some(&req)).unwrap(),
            "example.com"
        );
    }
}
