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
    /// `@query-param` — a single query parameter, named by the `;name`
    /// parameter (RFC 9421 §2.2.8).
    QueryParam,
    /// `@status` — the HTTP response status code.
    Status,
}

/// A parameter on a component identifier.
///
/// RFC 9421 §2.1 and §2.2.8 define the complete set. §2.5 requires an error for
/// "a parameter that is unknown or does not apply to the component identifier
/// to which it is attached", so anything outside this enum has no
/// representation — [`ComponentIdentifier::from_sfv_item`] rejects it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ComponentParam {
    /// `;sf` — serialize the field value with the strict Structured Field
    /// rules (§2.1.1).
    Sf,
    /// `;key="…"` — select one member of a Dictionary field (§2.1.2).
    Key(String),
    /// `;name="…"` — select one query parameter, for `@query-param` (§2.2.8).
    Name(String),
    /// `;bs` — wrap each field value as a Byte Sequence (§2.1.3).
    Bs,
    /// `;req` — resolve against the request that triggered a response (§2.4).
    Req,
    /// `;tr` — take the value from the trailers rather than the headers (§2.1.4).
    Tr,
}

impl ComponentParam {
    /// The SFV key this parameter serializes under.
    fn key_name(&self) -> &'static str {
        match self {
            Self::Sf => "sf",
            Self::Key(_) => "key",
            Self::Name(_) => "name",
            Self::Bs => "bs",
            Self::Req => "req",
            Self::Tr => "tr",
        }
    }
}

/// The parameters on a component identifier, in the order the signer wrote them.
///
/// Order is load-bearing. RFC 9421 §2.5 step 2.2 puts the serialized component
/// identifier — parameters included — into the signature base, and RFC 8941
/// §4.1.1.2 serializes parameters in the order they occur. A verifier that
/// re-emits them in an order of its own computes a different signature base
/// than the signer did and rejects a valid signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentParams {
    params: Vec<ComponentParam>,
}

impl ComponentParams {
    /// An empty parameter set.
    #[must_use]
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Append a parameter, keeping the order it was added in.
    pub fn push(&mut self, param: ComponentParam) {
        self.params.push(param);
    }

    /// Iterate the parameters in the order they were written.
    pub fn iter(&self) -> impl Iterator<Item = &ComponentParam> {
        self.params.iter()
    }

    /// Whether `;sf` is present.
    #[must_use]
    pub fn sf(&self) -> bool {
        self.params.contains(&ComponentParam::Sf)
    }

    /// Whether `;bs` is present.
    #[must_use]
    pub fn bs(&self) -> bool {
        self.params.contains(&ComponentParam::Bs)
    }

    /// Whether `;req` is present.
    #[must_use]
    pub fn req(&self) -> bool {
        self.params.contains(&ComponentParam::Req)
    }

    /// Whether `;tr` is present.
    #[must_use]
    pub fn tr(&self) -> bool {
        self.params.contains(&ComponentParam::Tr)
    }

    /// The `;key` Dictionary member name, if present.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.params.iter().find_map(|param| match param {
            ComponentParam::Key(key) => Some(key.as_str()),
            ComponentParam::Sf
            | ComponentParam::Name(_)
            | ComponentParam::Bs
            | ComponentParam::Req
            | ComponentParam::Tr => None,
        })
    }

    /// The `;name` query parameter name, if present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.params.iter().find_map(|param| match param {
            ComponentParam::Name(name) => Some(name.as_str()),
            ComponentParam::Sf
            | ComponentParam::Key(_)
            | ComponentParam::Bs
            | ComponentParam::Req
            | ComponentParam::Tr => None,
        })
    }
}

impl FromIterator<ComponentParam> for ComponentParams {
    fn from_iter<I: IntoIterator<Item = ComponentParam>>(iter: I) -> Self {
        Self {
            params: iter.into_iter().collect(),
        }
    }
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

    /// Create a derived `@query-param` component for the named parameter.
    #[must_use]
    pub fn query_param(name: &str) -> Self {
        Self::Derived {
            component: DerivedComponent::QueryParam,
            params: ComponentParams::from_iter([ComponentParam::Name(name.to_string())]),
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
        for param in component_params.iter() {
            // RFC 8941 §4.1.1.2 serializes a Boolean-true parameter by omitting
            // its value, so the flag parameters are written bare.
            let value = match param {
                ComponentParam::Key(value) | ComponentParam::Name(value) => {
                    Some(SfvBareItem::String(value.clone()))
                }
                ComponentParam::Sf
                | ComponentParam::Bs
                | ComponentParam::Req
                | ComponentParam::Tr => None,
            };
            sfv_params.insert(param.key_name().into(), value);
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
    /// Returns [`HttpSigError::InvalidComponent`] if the item cannot be parsed,
    /// names a derived component this implementation does not know, or carries
    /// a parameter that is unknown, inapplicable, or incompatible with another
    /// (RFC 9421 §2.5).
    pub fn from_sfv_item(item: &SfvItem) -> Result<Self, HttpSigError> {
        let name = match &item.value {
            SfvBareItem::String(s) => s.as_str(),
            SfvBareItem::Integer(_)
            | SfvBareItem::Decimal(_)
            | SfvBareItem::Token(_)
            | SfvBareItem::ByteSequence(_)
            | SfvBareItem::Boolean(_) => {
                return Err(HttpSigError::InvalidComponent(
                    "component identifier must be a string".into(),
                ));
            }
        };

        let Some(stripped) = name.strip_prefix('@') else {
            let params = parse_component_params(&item.params, ParamContext::Field)?;
            return Ok(Self::Field {
                name: name.to_ascii_lowercase(),
                params,
            });
        };

        let component = parse_derived_name(stripped)?;
        let context = if component == DerivedComponent::QueryParam {
            ParamContext::QueryParam
        } else {
            ParamContext::Derived
        };
        let params = parse_component_params(&item.params, context)?;

        // RFC 9421 §2.2.8: "The REQUIRED name parameter of each component
        // identifier contains the encoded nameString of a single query
        // parameter as a String value."
        if component == DerivedComponent::QueryParam && params.name().is_none() {
            return Err(HttpSigError::InvalidComponent(
                "@query-param requires the ';name' parameter".into(),
            ));
        }

        Ok(Self::Derived { component, params })
    }

    /// Resolve the value of this component from an HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError::MissingComponent`] if the component cannot be resolved.
    pub fn resolve_from_request<T>(&self, req: &http::Request<T>) -> Result<String, HttpSigError> {
        match self {
            Self::Field { name, params } => {
                reject_req_on_request(params)?;
                reject_trailers(params)?;
                resolve_field(req.headers(), name, params)
            }
            Self::Derived { component, params } => {
                reject_req_on_request(params)?;
                resolve_derived_from_request(component, params, req)
            }
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
                if params.req() {
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
                if params.req() {
                    let request = req.ok_or_else(|| {
                        HttpSigError::MissingComponent(
                            "req flag set but no request provided".into(),
                        )
                    })?;
                    resolve_derived_from_request(component, params, request)
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

    /// A canonical, order-insensitive key for RFC 9421 §2 component-identifier
    /// equality.
    ///
    /// RFC 9421 §2: "The order of parameters is not significant when comparing
    /// two component identifiers for equality checks", so `"foo";bar;baz` and
    /// `"foo";baz;bar` are equivalent and — per §2.5 step 2.1 — cannot both
    /// appear in one covered-components list. `serialize_id` preserves the
    /// parameter order the signer wrote (§2.5 step 2.2, RFC 8941 §4.1.1.2),
    /// which the signature base needs, so it cannot serve as this comparison
    /// key: two order-permuted equivalents serialize differently. This method
    /// returns the bare component name together with a normalized (sorted)
    /// view of the parameter set, which two §2-equivalent identifiers share
    /// regardless of parameter order.
    #[must_use]
    pub(crate) fn dedup_key(&self) -> (String, Vec<ComponentParam>) {
        let (name, params) = match self {
            Self::Field { name, params } => (name.clone(), params),
            Self::Derived { component, params } => (derived_name(component).to_string(), params),
        };
        let mut sorted: Vec<ComponentParam> = params.iter().cloned().collect();
        sorted.sort_unstable();
        (name, sorted)
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
        DerivedComponent::QueryParam => "@query-param",
        DerivedComponent::Status => "@status",
    }
}

fn parse_derived_name(name: &str) -> Result<DerivedComponent, HttpSigError> {
    match name {
        "method" => Ok(DerivedComponent::Method),
        "target-uri" => Ok(DerivedComponent::TargetUri),
        "authority" => Ok(DerivedComponent::Authority),
        "scheme" => Ok(DerivedComponent::Scheme),
        "request-target" => Ok(DerivedComponent::RequestTarget),
        "path" => Ok(DerivedComponent::Path),
        "query" => Ok(DerivedComponent::Query),
        "query-param" => Ok(DerivedComponent::QueryParam),
        "status" => Ok(DerivedComponent::Status),
        _ => Err(HttpSigError::InvalidComponent(format!(
            "unknown derived component: @{name}"
        ))),
    }
}

/// Which parameters a component identifier is allowed to carry.
///
/// RFC 9421 §2.5 requires an error for a parameter that is "unknown or does not
/// apply to the component identifier to which it is attached", so the allowed
/// set depends on what the identifier names.
#[derive(Debug, Clone, Copy)]
enum ParamContext {
    /// An HTTP field: `;sf`, `;key`, `;bs`, `;tr` (§2.1), plus `;req` (§2.4).
    Field,
    /// `@query-param`: `;name` (§2.2.8), plus `;req` (§2.4).
    QueryParam,
    /// Any other derived component: `;req` only (§2.4).
    Derived,
}

impl ParamContext {
    fn allows(self, param: &ComponentParam) -> bool {
        match param {
            // §2.1 lists sf, key, bs, and tr under "Any HTTP field component
            // identifiers MAY have the following parameters"; none of them has
            // a meaning for a derived component.
            ComponentParam::Sf
            | ComponentParam::Key(_)
            | ComponentParam::Bs
            | ComponentParam::Tr => matches!(self, Self::Field),
            ComponentParam::Name(_) => matches!(self, Self::QueryParam),
            // §2.4: ";req" applies to fields and to derived components alike.
            ComponentParam::Req => true,
        }
    }
}

/// Parse and validate the parameters on one component identifier.
fn parse_component_params(
    sfv: &SfvParams,
    context: ParamContext,
) -> Result<ComponentParams, HttpSigError> {
    let mut params = ComponentParams::new();

    for (key, value) in sfv.iter() {
        let param = match key.as_str() {
            "sf" => {
                expect_flag(key, value)?;
                ComponentParam::Sf
            }
            "bs" => {
                expect_flag(key, value)?;
                ComponentParam::Bs
            }
            "req" => {
                expect_flag(key, value)?;
                ComponentParam::Req
            }
            "tr" => {
                expect_flag(key, value)?;
                ComponentParam::Tr
            }
            "key" => ComponentParam::Key(expect_string(key, value)?),
            "name" => ComponentParam::Name(expect_string(key, value)?),
            // §2.5: "If the component identifier has a parameter that is not
            // understood, produce an error."
            _ => {
                return Err(HttpSigError::InvalidComponent(format!(
                    "unknown component parameter ';{key}'"
                )));
            }
        };

        if !context.allows(&param) {
            return Err(HttpSigError::InvalidComponent(format!(
                "component parameter ';{key}' does not apply to this component identifier"
            )));
        }

        params.push(param);
    }

    // §2.5: "If the component identifier has parameters that are mutually
    // incompatible with one another, such as bs and sf, produce an error."
    // §2.1 names the pair: bs "is not compatible with the use of the sf or key
    // parameters, which require the parsed data structures of the field values
    // after combination."
    if params.bs() && (params.sf() || params.key().is_some()) {
        return Err(HttpSigError::InvalidComponent(
            "component parameter ';bs' is incompatible with ';sf' and ';key'".into(),
        ));
    }

    Ok(params)
}

/// Accept a Boolean-flag parameter, which RFC 8941 §4.1.1.2 writes bare because
/// a `true` value is serialized by omitting it.
fn expect_flag(key: &str, value: &Option<SfvBareItem>) -> Result<(), HttpSigError> {
    match value {
        None | Some(SfvBareItem::Boolean(true)) => Ok(()),
        Some(
            SfvBareItem::Boolean(false)
            | SfvBareItem::Integer(_)
            | SfvBareItem::Decimal(_)
            | SfvBareItem::String(_)
            | SfvBareItem::Token(_)
            | SfvBareItem::ByteSequence(_),
        ) => Err(HttpSigError::InvalidComponent(format!(
            "component parameter ';{key}' is a Boolean flag and takes no value"
        ))),
    }
}

/// Accept a String-valued parameter.
fn expect_string(key: &str, value: &Option<SfvBareItem>) -> Result<String, HttpSigError> {
    match value {
        Some(SfvBareItem::String(text)) => Ok(text.clone()),
        None
        | Some(
            SfvBareItem::Boolean(_)
            | SfvBareItem::Integer(_)
            | SfvBareItem::Decimal(_)
            | SfvBareItem::Token(_)
            | SfvBareItem::ByteSequence(_),
        ) => Err(HttpSigError::InvalidComponent(format!(
            "component parameter ';{key}' must be a string"
        ))),
    }
}

/// RFC 9421 §2.5: "If the component identifier contains the req parameter and
/// the target message is a request, produce an error."
fn reject_req_on_request(params: &ComponentParams) -> Result<(), HttpSigError> {
    if params.req() {
        return Err(HttpSigError::InvalidComponent(
            "the ';req' parameter is not allowed when the target message is a request".into(),
        ));
    }
    Ok(())
}

/// Reject `;tr` (trailer) components — the `http` crate does not model trailers.
fn reject_trailers(params: &ComponentParams) -> Result<(), HttpSigError> {
    if params.tr() {
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
    if params.bs() {
        return resolve_field_bs(headers, lower);
    }

    // §2.1.1 + §2.1.2: Structured Field with optional key extraction
    if params.sf() || params.key().is_some() {
        return resolve_field_sf(headers, lower, params);
    }

    resolve_field_raw(headers, lower)
}

/// Get the raw combined field value (no SFV processing).
///
/// RFC 9421 §2.1 combines the instances of a field by "concatenating the values
/// using a single comma and a single space as a separator", after stripping
/// leading and trailing whitespace from each.
///
/// Every instance takes part. A value outside the visible-ASCII range the
/// signature base admits fails the whole resolution rather than being left out:
/// dropping one would let the signature claim to cover a field while binding
/// only part of it, so an intermediary could append a value the signature never
/// saw. §2.1 states the requirement — "all non-ASCII field values MUST be
/// encoded to ASCII before being added to the signature base" — and names the
/// remedy in the same breath: "The bs parameter, as described in Section 2.1.3,
/// provides a method for wrapping such problematic field values."
fn resolve_field_raw(headers: &http::HeaderMap, lower_name: &str) -> Result<String, HttpSigError> {
    let mut result = String::new();
    let mut found = false;

    for value in headers.get_all(lower_name) {
        let value = value.to_str().map_err(|_| {
            HttpSigError::InvalidComponent(format!(
                "header '{lower_name}' has a value outside the visible-ASCII range \
                 that the signature base admits; cover it with the ';bs' parameter instead"
            ))
        })?;

        if found {
            result.push_str(", ");
        }
        found = true;
        // OWS is SP and HTAB (RFC 9110 §5.6.3).
        result.push_str(value.trim_matches([' ', '\t']));
    }

    if found {
        Ok(result)
    } else {
        Err(HttpSigError::MissingComponent(format!(
            "header '{lower_name}' not found"
        )))
    }
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

    if let Some(key) = params.key() {
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
    params: &ComponentParams,
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
        DerivedComponent::QueryParam => {
            let name = params.name().ok_or_else(|| {
                HttpSigError::InvalidComponent("@query-param requires the ';name' parameter".into())
            })?;
            let query = req.uri().query().ok_or_else(|| {
                HttpSigError::MissingComponent(format!(
                    "no query string for @query-param;name=\"{name}\""
                ))
            })?;
            resolve_query_param(query, name)
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

/// RFC 9421 §2.2.8: resolve the component value of one named query parameter.
///
/// The query is read with the "application/x-www-form-urlencoded parsing"
/// algorithm the section requires, and the name being matched and the value
/// returned are then put back through the "percent-encode after encoding"
/// process, which is what makes the result the ASCII string the signature base
/// needs. Skipping that second step lets a decoded value carry a newline or a
/// non-ASCII byte into the base — the RFC prints exactly that outcome as its
/// counterexample and calls the resulting base "invalid".
fn resolve_query_param(query: &str, name: &str) -> Result<String, HttpSigError> {
    let mut found: Option<String> = None;

    for pair in query.split('&') {
        // URL Standard §5.1 skips empty sequences, so "a=1&&b=2" has two pairs.
        if pair.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = match pair.split_once('=') {
            Some((raw_name, raw_value)) => (raw_name, raw_value),
            None => (pair, ""),
        };

        if form_urlencoded_component(raw_name) != name {
            continue;
        }

        // §2.2.8: "If a parameter name occurs multiple times in a request, the
        // named query parameter MUST NOT be included."
        if found.is_some() {
            return Err(HttpSigError::InvalidComponent(format!(
                "query parameter '{name}' occurs more than once and cannot be covered"
            )));
        }
        found = Some(form_urlencoded_component(raw_value));
    }

    // §2.2.8: "If a query parameter is named as a covered component but it does
    // not occur in the query parameters, this MUST cause an error in the
    // signature base generation."
    found.ok_or_else(|| {
        HttpSigError::MissingComponent(format!("query parameter '{name}' not found"))
    })
}

/// Decode one `application/x-www-form-urlencoded` name or value and re-encode
/// it, which is the two-step process RFC 9421 §2.2.8 specifies.
fn form_urlencoded_component(raw: &str) -> String {
    let decoded = form_urlencoded_decode(raw);
    // URL Standard §5.1 finishes each component with a UTF-8 decode without
    // BOM, which substitutes replacement characters rather than failing.
    percent_encode_form(String::from_utf8_lossy(&decoded).as_bytes())
}

/// URL Standard §5.1 "application/x-www-form-urlencoded parsing": `+` stands
/// for a space, and `%XX` sequences decode to the byte they name.
fn form_urlencoded_decode(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while let Some(&byte) = bytes.get(i) {
        if byte == b'%'
            && let Some(hi) = bytes.get(i.saturating_add(1)).copied().and_then(hex_val)
            && let Some(lo) = bytes.get(i.saturating_add(2)).copied().and_then(hex_val)
        {
            decoded.push(hi << 4 | lo);
            i = i.saturating_add(3);
            continue;
        }
        decoded.push(if byte == b'+' { b' ' } else { byte });
        i = i.saturating_add(1);
    }

    decoded
}

/// URL Standard §5.2 "percent-encode after encoding" with the urlencoded
/// percent-encode set: ASCII alphanumerics and `*`, `-`, `.`, `_` pass through,
/// every other byte becomes `%XX` with uppercase hex digits.
///
/// A space becomes `%20` rather than `+`. RFC 9421 §2.2.8's own example renders
/// the query `bar=with+plus+whitespace` as the component value
/// `with%20plus%20whitespace`.
fn percent_encode_form(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());

    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }

    encoded
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
    // which leave malformed percent-escapes intact. `%` is outside the
    // urlencoded percent-encode set, so re-encoding escapes it as %25.
    #[test]
    fn test_query_param_preserves_malformed_percent_encoding() {
        assert_eq!(form_urlencoded_component("%2G"), "%252G");
        assert_eq!(form_urlencoded_component("foo%2"), "foo%252");
        assert_eq!(form_urlencoded_component("%ZZhello"), "%25ZZhello");
    }

    // RFC 9421 §2.2.8 step 1: valid percent-escapes are decoded, then step 2
    // re-encodes the result, so a percent-escaped space survives as %20.
    #[test]
    fn test_query_param_decodes_then_reencodes() {
        assert_eq!(
            form_urlencoded_component("name%20with%20space"),
            "name%20with%20space"
        );
    }

    // RFC 9421 §2.2.8: "The query parameters MUST be parsed according to
    // Section 5.1 ('application/x-www-form-urlencoded parsing') of [HTMLURL]",
    // which maps `+` to a space. The RFC's example renders the query
    // `bar=with+plus+whitespace` as the value `with%20plus%20whitespace`.
    #[test]
    fn test_query_param_plus_is_a_space() {
        let req = make_request(
            "GET",
            "https://example.com/parameters?bar=with+plus+whitespace",
            &[],
        );
        let cid = ComponentIdentifier::query_param("bar");
        assert_eq!(
            cid.resolve_from_request(&req).unwrap(),
            "with%20plus%20whitespace"
        );
    }

    // RFC 9421 §2.2.8 step 2: the decoded value is re-encoded with the
    // "percent-encode after encoding" process, so a value holding a newline
    // enters the signature base as %0A. Without that step the RFC's own
    // counterexample applies: the base "contains characters that violate the
    // constraints on component names and values and is therefore invalid".
    #[test]
    fn test_query_param_reencodes_newline() {
        let req = make_request(
            "GET",
            "https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value",
            &[],
        );
        let cid = ComponentIdentifier::query_param("var");
        assert_eq!(
            cid.resolve_from_request(&req).unwrap(),
            "this%20is%20a%20big%0Amultiline%20value"
        );
    }

    // RFC 9421 §2.2.8: "The REQUIRED name parameter of each component
    // identifier contains the encoded nameString of a single query parameter",
    // so a name is matched in its encoded form. This is the RFC's own example.
    #[test]
    fn test_query_param_matches_encoded_name() {
        let req = make_request(
            "GET",
            "https://example.com/parameters?fa%C3%A7ade%22%3A%20=something",
            &[],
        );
        let cid = ComponentIdentifier::query_param("fa%C3%A7ade%22%3A%20");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "something");
    }

    // RFC 9421 §2.2.8: "Named query parameters with an empty valueString have
    // an empty string as the component value."
    #[test]
    fn test_query_param_empty_value() {
        let req = make_request("GET", "https://example.com/path?qux=", &[]);
        let cid = ComponentIdentifier::query_param("qux");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "");
    }

    // RFC 9421 §2.2.8: "If a parameter name occurs multiple times in a request,
    // the named query parameter MUST NOT be included."
    #[test]
    fn test_query_param_duplicate_name_is_an_error() {
        let req = make_request("GET", "https://example.com/path?a=1&a=2", &[]);
        let cid = ComponentIdentifier::query_param("a");
        assert!(cid.resolve_from_request(&req).is_err());
    }

    // RFC 9421 §2.2.8: "If a query parameter is named as a covered component
    // but it does not occur in the query parameters, this MUST cause an error
    // in the signature base generation."
    #[test]
    fn test_query_param_absent_is_an_error() {
        let req = make_request("GET", "https://example.com/path?a=1", &[]);
        let cid = ComponentIdentifier::query_param("b");
        assert!(cid.resolve_from_request(&req).is_err());
    }

    // RFC 9421 §2.2.8: the parameter is required, so an @query-param
    // identifier without ;name cannot be parsed.
    #[test]
    fn test_query_param_requires_name_parameter() {
        let item = crate::sfv::parse::parse_item("\"@query-param\"").unwrap();
        assert!(ComponentIdentifier::from_sfv_item(&item).is_err());
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
            params: ComponentParams::from_iter([ComponentParam::Sf]),
        };
        assert_eq!(cid.resolve_from_request(&req).unwrap(), "42");
    }

    // RFC 9421 §2.1.1: with ;sf a Dictionary field is re-serialized canonically.
    #[test]
    fn test_sf_canonicalizes_dictionary() {
        let req = make_request("GET", "https://example.com/", &[("x-dict", "a=1, b=2")]);
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams::from_iter([ComponentParam::Sf]),
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
            params: ComponentParams::from_iter([ComponentParam::Key("b".into())]),
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
            params: ComponentParams::from_iter([ComponentParam::Key("z".into())]),
        };
        assert!(cid.resolve_from_request(&req).is_err());
    }

    // RFC 9421 §2.1.2: a Boolean-true Dictionary member serializes as the bare key.
    #[test]
    fn test_key_extracts_boolean_true_member() {
        let req = make_request("GET", "https://example.com/", &[("x-dict", "a, b=2")]);
        let cid = ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams::from_iter([ComponentParam::Key("a".into())]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Bs]),
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
            params: ComponentParams::from_iter([ComponentParam::Tr]),
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
            params: ComponentParams::from_iter([ComponentParam::Req]),
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
            params: ComponentParams::from_iter([ComponentParam::Req]),
        };
        assert_eq!(
            cid.resolve_from_response(&resp, Some(&req)).unwrap(),
            "example.com"
        );
    }

    // component parameter validation

    fn parse_identifier(input: &str) -> Result<ComponentIdentifier, HttpSigError> {
        ComponentIdentifier::from_sfv_item(&crate::sfv::parse::parse_item(input)?)
    }

    // RFC 9421 §2.5: "If the component identifier has a parameter that is not
    // understood, produce an error."
    #[test]
    fn test_unknown_parameter_is_rejected() {
        assert!(parse_identifier("\"@method\";foo=\"bar\"").is_err());
        assert!(parse_identifier("\"content-type\";unknown").is_err());
    }

    // RFC 9421 §2.5: a parameter that "does not apply to the component
    // identifier to which it is attached" is equally an error. §2.1 offers sf,
    // key, bs, and tr for HTTP fields only.
    #[test]
    fn test_field_parameter_on_derived_component_is_rejected() {
        assert!(parse_identifier("\"@method\";sf").is_err());
        assert!(parse_identifier("\"@path\";key=\"a\"").is_err());
        assert!(parse_identifier("\"@authority\";bs").is_err());
        assert!(parse_identifier("\"@query\";tr").is_err());
    }

    // RFC 9421 §2.2.8 defines ;name for @query-param; no HTTP field takes it.
    #[test]
    fn test_name_parameter_on_field_is_rejected() {
        assert!(parse_identifier("\"content-type\";name=\"a\"").is_err());
    }

    // RFC 9421 §2.4: ";req" applies to fields and derived components alike.
    #[test]
    fn test_req_parameter_is_accepted_on_both_kinds() {
        assert!(parse_identifier("\"content-type\";req").is_ok());
        assert!(parse_identifier("\"@method\";req").is_ok());
    }

    // RFC 9421 §2.5: "If the component identifier has parameters that are
    // mutually incompatible with one another, such as bs and sf, produce an
    // error." §2.1: bs "is not compatible with the use of the sf or key
    // parameters".
    #[test]
    fn test_bs_with_sf_or_key_is_rejected() {
        assert!(parse_identifier("\"x-dict\";bs;sf").is_err());
        assert!(parse_identifier("\"x-dict\";sf;bs").is_err());
        assert!(parse_identifier("\"x-dict\";bs;key=\"a\"").is_err());
        assert!(parse_identifier("\"x-dict\";key=\"a\";bs").is_err());
    }

    // RFC 8941 §4.1.1.2 serializes a Boolean-true parameter by omitting the
    // value, so a flag parameter is written bare; ";bs=?1" means the same
    // thing, and anything else is not a flag at all.
    #[test]
    fn test_flag_parameter_value_handling() {
        assert!(parse_identifier("\"x-val\";bs=?1").is_ok());
        assert!(parse_identifier("\"x-val\";bs=?0").is_err());
        assert!(parse_identifier("\"x-val\";bs=\"yes\"").is_err());
        assert!(parse_identifier("\"x-val\";bs=1").is_err());
    }

    // RFC 9421 §2.1.2 and §2.2.8 both define their selector as a String value.
    #[test]
    fn test_string_parameter_value_handling() {
        assert!(parse_identifier("\"x-dict\";key=\"a\"").is_ok());
        assert!(parse_identifier("\"x-dict\";key").is_err());
        assert!(parse_identifier("\"x-dict\";key=1").is_err());
        assert!(parse_identifier("\"@query-param\";name=42").is_err());
    }

    // RFC 9421 §2.5 step 2.2 serializes the component identifier into the
    // signature base, and RFC 8941 §4.1.1.2 emits parameters in the order they
    // occur, so the verifier has to keep the signer's order rather than impose
    // one. Reordering here would change the base and reject a valid signature.
    #[test]
    fn test_parameter_order_is_preserved() {
        for input in [
            "\"x-dict\";key=\"a\";req",
            "\"x-dict\";req;key=\"a\"",
            "\"x-val\";tr;req",
            "\"x-val\";req;tr",
        ] {
            assert_eq!(parse_identifier(input).unwrap().serialize_id(), input);
        }
    }

    // RFC 9421 §2.5: "If the component identifier contains the req parameter
    // and the target message is a request, produce an error."
    #[test]
    fn test_req_on_a_request_is_rejected() {
        let req = make_request("GET", "https://example.com/p", &[("x-val", "1")]);

        let field = ComponentIdentifier::Field {
            name: "x-val".into(),
            params: ComponentParams::from_iter([ComponentParam::Req]),
        };
        assert!(field.resolve_from_request(&req).is_err());

        let derived = ComponentIdentifier::Derived {
            component: DerivedComponent::Method,
            params: ComponentParams::from_iter([ComponentParam::Req]),
        };
        assert!(derived.resolve_from_request(&req).is_err());
    }

    // field combination

    // RFC 9421 §2.1: fields "sent as multiple fields MUST be combined by
    // concatenating the values using a single comma and a single space as a
    // separator".
    #[test]
    fn test_multiple_field_values_are_all_combined() {
        let mut req = make_request("GET", "https://example.com/", &[]);
        for value in ["max-age=60", "must-revalidate", "no-store"] {
            req.headers_mut()
                .append("cache-control", value.parse().unwrap());
        }
        let cid = ComponentIdentifier::field("cache-control");
        assert_eq!(
            cid.resolve_from_request(&req).unwrap(),
            "max-age=60, must-revalidate, no-store"
        );
    }

    // RFC 9421 §2.1 step 2: "Strip leading and trailing whitespace from each
    // item in the list", which for an HTTP field value means SP and HTAB.
    #[test]
    fn test_field_values_are_trimmed_before_combining() {
        let mut req = make_request("GET", "https://example.com/", &[]);
        for value in ["  max-age=60  ", "\tmust-revalidate\t"] {
            req.headers_mut()
                .append("cache-control", value.parse().unwrap());
        }
        let cid = ComponentIdentifier::field("cache-control");
        assert_eq!(
            cid.resolve_from_request(&req).unwrap(),
            "max-age=60, must-revalidate"
        );
    }

    // RFC 9421 §2.1: an empty field has the empty string as its component
    // value, and it still occupies its place in the combination.
    #[test]
    fn test_empty_field_value_still_takes_its_place() {
        let mut req = make_request("GET", "https://example.com/", &[("x-multi", "")]);
        req.headers_mut()
            .append("x-multi", "second".parse().unwrap());
        let cid = ComponentIdentifier::field("x-multi");
        assert_eq!(cid.resolve_from_request(&req).unwrap(), ", second");
    }

    // RFC 9421 §2.1 requires every instance of the field to take part in the
    // combined value, and "all non-ASCII field values MUST be encoded to ASCII
    // before being added to the signature base". A value that cannot be has to
    // fail the resolution: dropping it would leave the signature covering the
    // field in name while binding only part of it. §2.1 directs such fields to
    // the ";bs" parameter, which still covers them faithfully.
    #[test]
    fn test_non_ascii_field_value_is_an_error_not_a_silent_drop() {
        let mut req = make_request("GET", "https://example.com/", &[("x-multi", "first")]);
        req.headers_mut().append(
            "x-multi",
            http::HeaderValue::from_bytes(&[0xC3, 0x28]).unwrap(),
        );

        let cid = ComponentIdentifier::field("x-multi");
        assert!(cid.resolve_from_request(&req).is_err());

        // The same field is still coverable the way §2.1.3 intends.
        let wrapped = ComponentIdentifier::Field {
            name: "x-multi".into(),
            params: ComponentParams::from_iter([ComponentParam::Bs]),
        };
        assert_eq!(
            wrapped.resolve_from_request(&req).unwrap(),
            ":Zmlyc3Q=:, :wyg=:"
        );
    }
}
