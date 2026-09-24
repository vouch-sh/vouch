// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exclusive XML Canonicalization (exc-c14n).
//!
//! Implements W3C Exclusive XML Canonicalization 1.0:
//! <https://www.w3.org/TR/xml-exc-c14n/>
//!
//! Used by XML-DSig to canonicalize `<ds:SignedInfo>` and signed elements
//! before hashing and signature verification.
//!
//! # roxmltree API Dependencies
//!
//! This module depends on the following roxmltree 0.21.1 API surface:
//! - `Node::tag_name()` -- returns `ExpandedName` with `.namespace()` and `.name()`
//! - `Node::namespaces()` -- returns namespace declarations on THIS node only
//!   (not inherited ones). `Namespace::name()` returns `Option<&str>` where
//!   `None` means default namespace.
//! - `Node::attributes()` -- all attributes on a node
//! - `Node::children()` -- direct children
//! - `Node::is_element()`, `Node::is_text()`, `Node::is_comment()`
//! - `Node::text()` -- text content for text nodes
//! - `Node::parent()` -- parent node (for prefix resolution walk)
//!
//! # Prefix Resolution
//!
//! roxmltree does not expose the original prefix on `tag_name()` or on an
//! attribute's name, only the resolved namespace URI. Exc-c14n renders a
//! namespace declaration by the prefix a name was written with, so
//! [`element_prefix`] and [`attr_prefix`] read that prefix from the source text
//! at the node's or attribute's byte range (the `positions` feature). Only when
//! the written prefix does not resolve to the name's URI do they fall back to
//! walking namespace declarations from the element up through its ancestors,
//! preferring the declaration closest to the element; a `tracing::warn` is
//! emitted when that fallback finds several prefixes for one URI at one depth.
//!
//! Element and attribute prefix resolution differ: an element in the default
//! namespace is emitted unprefixed (the default binding is a valid "prefix" for
//! an element name), but an unprefixed attribute never takes the default namespace
//! per XML Names. The attribute fallback, [`find_attr_prefix_for_uri`], therefore
//! excludes the default binding and resolves to the closest non-empty (prefixed)
//! binding, so an element co-declaring the same URI as both `xmlns="urn:X"` and
//! `xmlns:a="urn:X"` with a `a:attr="v"` attribute canonicalizes as `a:attr` with
//! `xmlns:a="urn:X"` rendered -- matching libxml2/xmlsec1 byte-for-byte.
//!
//! # CDATA Sections
//!
//! CDATA sections are converted to text nodes by roxmltree during parsing, which
//! is correct per c14n spec section 2.1 (CDATA must be replaced by character content).
//!
//! # Whitespace Preservation
//!
//! roxmltree preserves all text nodes by default. Inter-element whitespace (newlines
//! and spaces between tags) is treated as text content and preserved in canonical
//! output, which is correct per the c14n spec.

use std::collections::{BTreeMap, BTreeSet};

/// Exclusive XML Canonicalization (exc-c14n) of a subtree.
///
/// Implements W3C Exclusive XML Canonicalization 1.0 for the given node and
/// its descendants. Used by XML-DSig to canonicalize `<ds:SignedInfo>` and
/// signed elements before hashing.
///
/// `inclusive_prefixes` is the `InclusiveNamespaces PrefixList` from the
/// `<ec:InclusiveNamespaces>` element in the transform. Azure AD/Entra
/// includes `PrefixList="#default saml ds xs xsi"`. Pass `&[]` if no
/// `InclusiveNamespaces` element is present.
///
/// Per W3C exc-c14n spec section 4, InclusiveNamespaces prefixes are treated
/// as "visibly utilized" but the "already rendered by ancestor" optimization
/// still applies -- a prefix is only emitted once per ancestor chain, not
/// repeated on every descendant.
///
/// Returns empty string for non-element nodes.
#[must_use]
pub(crate) fn exclusive_c14n(node: roxmltree::Node<'_, '_>, inclusive_prefixes: &[&str]) -> String {
    if !node.is_element() {
        return String::new();
    }
    let mut output = String::with_capacity(512);
    let rendered_ns: BTreeMap<String, String> = BTreeMap::new();
    canonicalize_node(node, &mut output, inclusive_prefixes, &rendered_ns);
    output
}

/// Recursively canonicalize an element node and its children.
///
/// `rendered_ns` is the spec's `ns_rendered` dictionary: for every prefix it
/// holds the binding most recently emitted by an ancestor (inserts replace,
/// per exc-c14n section 3.1). If a prefix is re-declared with a different URI
/// by a descendant, its entry is overwritten and the declaration re-emitted.
fn canonicalize_node(
    node: roxmltree::Node<'_, '_>,
    output: &mut String,
    inclusive_prefixes: &[&str],
    rendered_ns: &BTreeMap<String, String>,
) {
    if !node.is_element() {
        return;
    }

    // Step 1: Emit opening `<` and qualified name.
    output.push('<');
    let qname = node_qualified_name(node);
    output.push_str(&qname);

    // Step 2-4: Collect and emit namespace declarations.
    let ns_to_render = collect_namespaces(node, inclusive_prefixes, rendered_ns);

    // Track what this element renders so children can skip re-rendering.
    let mut new_rendered_ns = rendered_ns.clone();

    // Sort: default namespace (empty prefix) before prefixed ones, then lexicographic.
    // We sort by (prefix, uri) -- empty string sorts before any prefix.
    let mut sorted_ns: Vec<(String, String)> = ns_to_render.into_iter().collect();
    sorted_ns.sort_by(|a, b| a.0.cmp(&b.0));

    // Step 3: Handle default namespace undeclaration (`xmlns=""`).
    //
    // Per exc-c14n §3 point 4 / §3.1 step 3.3.1, `xmlns=""` is emitted on this
    // element iff ALL of the following hold:
    //   1. the default namespace is visibly utilized by this element (i.e. it
    //      is rendered with no prefix) OR the `#default` token is present in
    //      InclusiveNamespaces PrefixList. The "no prefix" restriction is the
    //      special case exc-c14n adds *only* when `#default` is absent; when
    //      `#default` is present the ordinary Canonical XML 1.0 `xmlns=""`
    //      rules apply and the gate is bypassed -- so a *prefixed* element
    //      that explicitly undeclares an ancestor-rendered non-empty default
    //      namespace still renders `xmlns=""` on itself.
    //   2. the element has no namespace node declaring a value for the default
    //      namespace (i.e. its in-scope default is empty), and
    //   3. the nearest output ancestor rendered a non-empty default namespace
    //      (`ns_rendered[""]` is non-empty).
    //
    // The undeclaration is inserted into `sorted_ns` (empty prefix sorts before
    // every other prefix) rather than appended after the emission loop, so an
    // element that emits both `xmlns=""` and one or more `xmlns:foo`
    // declarations on the same start tag matches libxml2/xmlsec1 byte-for-byte.
    let elem_default_ns = node.default_namespace().unwrap_or("");
    let ancestor_default_ns = rendered_ns.get("").map_or("", String::as_str);

    // Condition 1: the element visibly utilizes the default namespace iff it
    // is rendered with no prefix. This mirrors `node_qualified_name` exactly
    // so the gate agrees with the emitted tag name: an element with no
    // namespace, the xml namespace, or whose prefix resolves to "" is emitted
    // unprefixed and therefore visibly uses the default namespace. Per
    // §3.1 3.3.1 cond. 1, `#default` in InclusiveNamespaces PrefixList forces
    // visibly-utilizes regardless of prefix.
    let elem_ns_uri = node.tag_name().namespace().unwrap_or("");
    let default_in_prefixlist = inclusive_prefixes.contains(&"#default");
    let elem_uses_default_ns = elem_ns_uri.is_empty()
        || elem_ns_uri == "http://www.w3.org/XML/1998/namespace"
        || element_prefix(node).is_none_or(str::is_empty)
        || default_in_prefixlist;

    // Undeclare if: the element visibly utilizes the default namespace, its
    // in-scope default is empty, an output ancestor rendered a non-empty
    // default, and we haven't already emitted a default-namespace declaration
    // on this element (which happens when it explicitly declares xmlns="uri").
    let already_emitted_default = sorted_ns.iter().any(|(p, _)| p.is_empty());
    if elem_uses_default_ns
        && !already_emitted_default
        && elem_default_ns.is_empty()
        && !ancestor_default_ns.is_empty()
    {
        sorted_ns.push((String::new(), String::new()));
        sorted_ns.sort_by(|a, b| a.0.cmp(&b.0));
    }

    for (prefix, uri) in &sorted_ns {
        if prefix.is_empty() {
            // Renders both a real default-namespace declaration
            // (`xmlns="uri"`, uri non-empty) and the `xmlns=""` undeclaration
            // (uri empty) inserted by the Step 3 logic above.
            output.push_str(" xmlns=\"");
            output.push_str(uri);
            output.push('"');
        } else {
            output.push_str(" xmlns:");
            output.push_str(prefix);
            output.push_str("=\"");
            output.push_str(uri);
            output.push('"');
        }
        new_rendered_ns.insert(prefix.clone(), uri.clone());
    }

    // Step 5-6: Collect and sort attributes.
    let mut attrs: Vec<_> = node.attributes().collect();
    // Sort: namespace URI first, then local name. Empty URI sorts before any URI.
    attrs.sort_by(|a, b| {
        let ns_a = a.namespace().unwrap_or("");
        let ns_b = b.namespace().unwrap_or("");
        // Never sort xml: namespace attributes alongside regular attributes --
        // xml: prefix is implicitly bound and its attributes are rendered as-is.
        ns_a.cmp(ns_b).then_with(|| a.name().cmp(b.name()))
    });

    for attr in &attrs {
        let attr_ns = attr.namespace().unwrap_or("");
        // Skip xmlns declarations -- these are in node.namespaces(), not here.
        if attr_ns == "http://www.w3.org/2000/xmlns/" {
            continue;
        }
        output.push(' ');
        if !attr_ns.is_empty() && attr_ns != "http://www.w3.org/XML/1998/namespace" {
            // Attributes cannot use the default namespace (unprefixed attributes
            // never take it per XML Names), so resolve the prefix with the
            // default-namespace binding excluded. Selecting the empty (default)
            // prefix here would emit a bare-colon `:attr` name and drop the
            // `xmlns:prefix` declaration the attribute depends on, diverging from
            // libxml2/xmlsec1 (the engine every mainstream SAML IdP signs with).
            if let Some(p) = attr_prefix(node, attr) {
                output.push_str(p);
                output.push(':');
            }
        } else if attr_ns == "http://www.w3.org/XML/1998/namespace" {
            // xml: prefix is implicitly bound -- emit as xml:localname
            output.push_str("xml:");
        }
        output.push_str(attr.name());
        output.push_str("=\"");
        output.push_str(&escape_attribute(attr.value()));
        output.push('"');
    }

    // Step 7: Emit `>`.
    output.push('>');

    // Step 8: Recurse into children.
    for child in node.children() {
        if child.is_element() {
            canonicalize_node(child, output, inclusive_prefixes, &new_rendered_ns);
        } else if child.is_text()
            && let Some(text) = child.text()
        {
            output.push_str(&escape_text(text));
        }
        // Comments are omitted per exc-c14n (without-comments variant).
        // Processing instructions are not expected in SAML; skip them.
    }

    // Step 9: Emit closing tag. Empty elements are NEVER self-closed.
    output.push_str("</");
    output.push_str(&qname);
    output.push('>');
}

/// Collect the set of `(prefix, uri)` namespace pairs to render on this element.
///
/// Algorithm per W3C exc-c14n spec section 2.3:
///
/// 1. Collect namespaces of visibly utilized prefixes on this element and its
///    attributes (but NOT the implicit `xml:` prefix).
/// 2. Add namespaces for InclusiveNamespaces prefixes that are in scope
///    (declared on this element or ancestors), silently skipping out-of-scope ones.
/// 3. Exclude pairs whose prefix's CURRENT ancestor binding already equals
///    the same URI (dictionary lookup, so a rebinding is always re-emitted).
/// 4. Never emit the `xml:` namespace declaration.
fn collect_namespaces(
    node: roxmltree::Node<'_, '_>,
    inclusive_prefixes: &[&str],
    rendered_ns: &BTreeMap<String, String>,
) -> BTreeSet<(String, String)> {
    let mut result: BTreeSet<(String, String)> = BTreeSet::new();

    // Visibly utilized: the element's own namespace (if it has a prefix).
    if let Some(ns_uri) = node.tag_name().namespace()
        && !ns_uri.is_empty()
        && ns_uri != "http://www.w3.org/XML/1998/namespace"
    {
        let prefix = element_prefix(node).unwrap_or("").to_string();
        // Only add if this is a non-default-namespace prefixed element.
        // Default namespace elements (no prefix) are handled by the xmlns="" logic.
        if !prefix.is_empty() || {
            // Element uses default namespace -- add it if not empty.
            !ns_uri.is_empty()
        } {
            result.insert((prefix, ns_uri.to_string()));
        }
    }

    // Visibly utilized: namespaces of all attributes (except xml: and xmlns:).
    for attr in node.attributes() {
        let attr_ns = attr.namespace().unwrap_or("");
        if attr_ns.is_empty()
            || attr_ns == "http://www.w3.org/XML/1998/namespace"
            || attr_ns == "http://www.w3.org/2000/xmlns/"
        {
            continue;
        }
        // Attributes never use the default namespace: resolve with the default
        // binding excluded so the attribute's prefixed binding is recorded (and
        // the matching `xmlns:prefix` declaration is rendered). Otherwise an
        // element co-declaring the same URI as both default and prefixed would
        // record ("", uri) here, dropping `xmlns:prefix` as already rendered by
        // the default binding -- a byte-for-byte divergence from libxml2/xmlsec1.
        // roxmltree rejects an undeclared prefix, so `None` does not occur.
        // Skip to match the emitter, which renders no declaration here.
        let Some(prefix) = attr_prefix(node, &attr) else {
            continue;
        };
        result.insert((prefix.to_string(), attr_ns.to_string()));
    }

    // InclusiveNamespaces PrefixList: force listed prefixes if in scope.
    // Per W3C exc-c14n spec section 4, the "already rendered" check still applies.
    for &prefix in inclusive_prefixes {
        // "#default" refers to the default namespace (empty prefix).
        let lookup_prefix = if prefix == "#default" { "" } else { prefix };
        if let Some(uri) = resolve_prefix_in_scope(node, lookup_prefix)
            && !uri.is_empty()
        {
            result.insert((lookup_prefix.to_string(), uri.to_string()));
        }
        // If the prefix is not in scope, silently skip it.
    }

    // Exclude pairs whose prefix's current ancestor binding is the same URI.
    // The dictionary lookup (not exact-pair membership) matters: once a prefix
    // has been re-bound, an older historical binding must be re-emitted.
    result
        .into_iter()
        .filter(|(prefix, uri)| rendered_ns.get(prefix) != Some(uri))
        .collect()
}

/// Find the prefix bound to a given namespace URI, searching from this node upward.
///
/// Returns the prefix as a `&str` (empty for default namespace), or `None` if
/// the URI is not bound in the current scope.
///
/// For elements: searches namespace declarations on this node first, then walks
/// ancestors. This ensures the closest declaration wins (handles shadowing).
///
/// This is the fallback for [`element_prefix`], used only when the element's
/// written prefix cannot be read from the source. When multiple prefixes are
/// bound to the same URI in the same scope, the prefix declared first (closest
/// to the element) is returned, and a warning is emitted.
fn find_prefix_for_uri<'a>(node: roxmltree::Node<'_, 'a>, uri: &str) -> Option<&'a str> {
    let mut candidates: Vec<(&'a str, usize)> = Vec::new();
    let mut depth = 0usize;

    let mut current = Some(node);
    while let Some(n) = current {
        for ns in n.namespaces() {
            if ns.uri() == uri {
                let prefix = ns.name().unwrap_or("");
                // Never return the xml prefix via this path.
                // xml: is implicitly bound; it must never appear in ns declarations output.
                if prefix != "xml" {
                    candidates.push((prefix, depth));
                }
            }
        }
        current = n.parent();
        depth = depth.saturating_add(1);
    }

    if candidates.is_empty() {
        return None;
    }

    // Prefer the closest declaration (smallest depth = closest to element).
    candidates.sort_by_key(|&(_, d)| d);

    if candidates.len() > 1
        && let Some(&(_, min_depth)) = candidates.first()
    {
        // Only warn if multiple DIFFERENT prefixes map to the same URI at the same depth.
        let same_depth: Vec<_> = candidates
            .iter()
            .filter(|&&(_, d)| d == min_depth)
            .collect();
        if same_depth.len() > 1
            && let Some(&&(first_prefix, _)) = same_depth.first()
        {
            tracing::warn!(
                uri,
                "multiple prefixes bound to same namespace URI at same depth; \
                 using first one ({}). This is a known limitation of the c14n \
                 implementation.",
                first_prefix
            );
        }
    }

    candidates.first().map(|&(prefix, _)| prefix)
}

/// Find a non-empty (prefixed) namespace binding for a URI, searching from
/// this node upward.
///
/// This is the attribute-prefix resolver. Per XML Names, unprefixed attributes
/// never take the default namespace, so the default-namespace binding (empty
/// prefix) is never a valid prefix for a namespaced attribute. Unlike
/// [`find_prefix_for_uri`], this skips the default binding entirely and returns
/// the closest non-empty (prefixed) binding -- the one the attribute's prefix
/// must be drawn from even when the same URI is ALSO bound to the default
/// namespace on this element (e.g. `xmlns="urn:X" xmlns:a="urn:X"` with
/// `a:attr="v"`).
///
/// Returns `Some(prefix)` for the closest non-empty binding, or `None` if no
/// non-empty binding is in scope (which, for a validly-prefixed attribute, never
/// occurs: roxmltree only assigns a namespace to a `prefix:local` attribute
/// when a prefixed binding exists).
///
/// This is the fallback for [`attr_prefix`], used only when the attribute's
/// written prefix cannot be read from the source. When multiple non-empty
/// prefixes are bound to the same URI at the same depth, the one declared
/// first (closest to the element) is returned and a `tracing::warn` is emitted.
fn find_attr_prefix_for_uri<'a>(node: roxmltree::Node<'_, 'a>, uri: &str) -> Option<&'a str> {
    let mut candidates: Vec<(&'a str, usize)> = Vec::new();
    let mut depth = 0usize;

    let mut current = Some(node);
    while let Some(n) = current {
        for ns in n.namespaces() {
            if ns.uri() == uri {
                let prefix = ns.name().unwrap_or("");
                // Attributes cannot use the default namespace (empty prefix),
                // and the xml: prefix is implicitly bound (never declared).
                if !prefix.is_empty() && prefix != "xml" {
                    candidates.push((prefix, depth));
                }
            }
        }
        current = n.parent();
        depth = depth.saturating_add(1);
    }

    if candidates.is_empty() {
        return None;
    }

    // Prefer the closest declaration (smallest depth = closest to element).
    candidates.sort_by_key(|&(_, d)| d);

    if candidates.len() > 1
        && let Some(&(_, min_depth)) = candidates.first()
    {
        // Only warn if multiple DIFFERENT non-empty prefixes map to the same
        // URI at the same depth (the genuinely ambiguous case for attributes).
        let same_depth: Vec<_> = candidates
            .iter()
            .filter(|&&(_, d)| d == min_depth)
            .collect();
        if same_depth.len() > 1
            && let Some(&&(first_prefix, _)) = same_depth.first()
        {
            tracing::warn!(
                uri,
                "multiple non-empty prefixes bound to same namespace URI at same \
                 depth for an attribute; using first one ({}). This is a known \
                 limitation of the c14n implementation.",
                first_prefix
            );
        }
    }

    candidates.first().map(|&(prefix, _)| prefix)
}

/// Resolve a prefix to its URI by searching the element and its ancestors.
///
/// Returns `Some(uri)` if the prefix is in scope, `None` if not declared.
/// Empty string prefix resolves the default namespace.
fn resolve_prefix_in_scope<'a>(node: roxmltree::Node<'a, 'a>, prefix: &str) -> Option<&'a str> {
    let mut current = Some(node);
    while let Some(n) = current {
        for ns in n.namespaces() {
            let ns_prefix = ns.name().unwrap_or("");
            if ns_prefix == prefix {
                return Some(ns.uri());
            }
        }
        current = n.parent();
    }
    None
}

/// Return the qualified name of an element node.
///
/// If the element has a namespace with a non-empty prefix, returns `"prefix:localname"`.
/// If the element is in a default namespace (no prefix), returns just `"localname"`.
/// If the element has no namespace, returns just `"localname"`.
///
/// Note: The `xml:` prefix is never returned by `find_prefix_for_uri`.
/// Element names with the xml namespace would be extremely unusual (elements in
/// http://www.w3.org/XML/1998/namespace). In practice this never occurs in SAML.
fn node_qualified_name(node: roxmltree::Node<'_, '_>) -> String {
    let local = node.tag_name().name();
    let ns_uri = match node.tag_name().namespace() {
        Some(uri) if !uri.is_empty() => uri,
        _ => return local.to_string(),
    };

    // xml namespace elements have no prefix in output (never declared).
    if ns_uri == "http://www.w3.org/XML/1998/namespace" {
        return local.to_string();
    }

    match element_prefix(node) {
        Some("") | None => local.to_string(), // default namespace or unresolvable
        Some(prefix) => format!("{prefix}:{local}"),
    }
}

/// Return the prefix the element was written with, or `""` when it uses the
/// default namespace.
///
/// roxmltree drops the prefix when it resolves `tag_name()`, so a URI search
/// cannot tell `<a:signed>` from `<signed>` when one URI is bound as both
/// `xmlns` and `xmlns:a`. exc-c14n §3 item 3 renders a namespace node only
/// if "it is visibly utilized by its parent element", and §1.1 ties default
/// namespace utilization to the element having no prefix. The prefix is read
/// from the start tag at `node.range()` and used only when it resolves to the
/// element's namespace URI.
fn element_prefix<'a>(node: roxmltree::Node<'_, 'a>) -> Option<&'a str> {
    let ns_uri = node.tag_name().namespace().unwrap_or("");
    let source_prefix = node
        .document()
        .input_text()
        .get(node.range())
        .and_then(|src| src.strip_prefix('<'))
        .map(|src| {
            src.split(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .next()
                .unwrap_or("")
        })
        .and_then(|qname| qname.split_once(':'))
        .map(|(prefix, _)| prefix)
        .filter(|prefix| node.lookup_namespace_uri(Some(prefix)) == Some(ns_uri));
    match source_prefix {
        Some(prefix) => Some(prefix),
        None if node.default_namespace() == Some(ns_uri) => Some(""),
        None => find_prefix_for_uri(node, ns_uri),
    }
}

/// Return the prefix an attribute was written with.
///
/// exc-c14n §1.1: "An element E in a document subset visibly utilizes a
/// namespace declaration, i.e. a namespace prefix P and bound value V, if E
/// or an attribute node in the document subset with parent E has a qualified
/// name in which P is the namespace prefix." When one URI is bound to two
/// prefixes in scope, a URI search cannot tell `b:attr` from `a:attr`, so the
/// prefix is read from the attribute's qualified name at `range_qname()` and
/// used only when it resolves to the attribute's namespace URI.
fn attr_prefix<'input>(
    node: roxmltree::Node<'_, 'input>,
    attr: &roxmltree::Attribute<'_, 'input>,
) -> Option<&'input str> {
    let ns_uri = attr.namespace()?;
    node.document()
        .input_text()
        .get(attr.range_qname())
        .and_then(|qname| qname.split_once(':'))
        .map(|(prefix, _)| prefix)
        .filter(|prefix| node.lookup_namespace_uri(Some(prefix)) == Some(ns_uri))
        .or_else(|| find_attr_prefix_for_uri(node, ns_uri))
}

/// Concatenate every text child of an element, skipping comments.
///
/// This is the only correct way to read a signed element's value. Signature
/// digests cover the canonical form produced by [`exclusive_c14n`], which
/// concatenates all text children and drops comments. `roxmltree`'s
/// `Node::text()` returns only the *first* text child, so a comment placed
/// mid-value (`<NameID>a@b.com<!---->.evil.tld</NameID>`) leaves the signed
/// bytes byte-identical while `text()` yields only `a@b.com` — the signature
/// verifies over one value and the application acts on another
/// (CVE-2017-11427 class).
///
/// Returns `None` when the element has no text children.
#[must_use]
pub(crate) fn element_text(node: roxmltree::Node<'_, '_>) -> Option<String> {
    let mut out = String::new();
    let mut found = false;
    for child in node.children() {
        if child.is_text()
            && let Some(text) = child.text()
        {
            out.push_str(text);
            found = true;
        }
    }
    found.then_some(out)
}

/// Escape text content per c14n spec.
///
/// Replacements: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
#[must_use]
pub(crate) fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// Escape attribute values per c14n spec.
///
/// Replacements: `&` → `&amp;`, `<` → `&lt;`, `"` → `&quot;`,
/// `\t` → `&#x9;`, `\n` → `&#xA;`, `\r` → `&#xD;`
#[must_use]
pub(crate) fn escape_attribute(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::*;

    fn c14n(xml: &str, xpath: &str, inclusive_prefixes: &[&str]) -> String {
        let doc = roxmltree::Document::parse(xml).unwrap();
        let node = find_element(&doc, xpath).expect("Element not found");
        exclusive_c14n(node, inclusive_prefixes)
    }

    /// Find the first element whose tag name matches the given local name.
    fn find_element<'a, 'input>(
        doc: &'a roxmltree::Document<'input>,
        local_name: &str,
    ) -> Option<roxmltree::Node<'a, 'input>> {
        doc.root()
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == local_name)
    }

    // =========================================================================
    // Attribute prefix when one URI is bound to two prefixes in scope
    // =========================================================================

    // exc-c14n §1.1: "An element E in a document subset visibly utilizes a
    // namespace declaration, i.e. a namespace prefix P and bound value V, if E
    // or an attribute node in the document subset with parent E has a
    // qualified name in which P is the namespace prefix." An attribute keeps
    // the prefix it was written with, whichever binding for its URI is
    // closest. Expected strings come from libxml2 2.14.6 exclusive C14N of
    // the `e` subtree.
    #[test]
    fn attribute_keeps_its_own_prefix_among_bindings_for_one_uri() {
        let cases = [
            (
                r#"<p xmlns:b="urn:X"><e b:attr="v"/></p>"#,
                r#"<e xmlns:b="urn:X" b:attr="v"></e>"#,
            ),
            (
                r#"<p xmlns:b="urn:X"><e xmlns:a="urn:X" b:attr="v"/></p>"#,
                r#"<e xmlns:b="urn:X" b:attr="v"></e>"#,
            ),
            (
                r#"<p xmlns:b="urn:X"><e xmlns:a="urn:X" a:attr="v"/></p>"#,
                r#"<e xmlns:a="urn:X" a:attr="v"></e>"#,
            ),
            (
                r#"<p xmlns:b="urn:X"><e xmlns:a="urn:X" a:x="1" b:y="2"/></p>"#,
                r#"<e xmlns:a="urn:X" xmlns:b="urn:X" a:x="1" b:y="2"></e>"#,
            ),
            (
                r#"<e xmlns:a="urn:X" xmlns:b="urn:X" b:attr="v"/>"#,
                r#"<e xmlns:b="urn:X" b:attr="v"></e>"#,
            ),
            (
                r#"<p xmlns:b="urn:X"><e b:attr="1"><f xmlns:a="urn:X" b:attr="2"/></e></p>"#,
                r#"<e xmlns:b="urn:X" b:attr="1"><f b:attr="2"></f></e>"#,
            ),
        ];
        for (xml, expected) in cases {
            assert_eq!(c14n(xml, "e", &[]), expected, "{xml}");
        }
    }

    // =========================================================================
    // Element prefix when one URI is bound as both default and prefixed
    // =========================================================================

    // exc-c14n §3 item 3: a namespace node renders only if "it is visibly
    // utilized by its parent element". §1.1: an element utilizes the default
    // namespace only if it has no prefix. `<a:signed>` has a prefix, so
    // `xmlns="urn:X"` does not render. Expected strings come from libxml2
    // `xmllint --exc-c14n`.
    #[test]
    fn prefixed_element_keeps_prefix_when_default_binds_same_uri() {
        let xml = r#"<a:signed xmlns="urn:X" xmlns:a="urn:X" ID="s1">text</a:signed>"#;
        assert_eq!(
            c14n(xml, "signed", &[]),
            r#"<a:signed xmlns:a="urn:X" ID="s1">text</a:signed>"#
        );
    }

    #[test]
    fn prefixed_element_and_attribute_with_default_binding_same_uri() {
        let xml = r#"<a:signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</a:signed>"#;
        assert_eq!(
            c14n(xml, "signed", &[]),
            r#"<a:signed xmlns:a="urn:X" ID="s1" a:attr="v">text</a:signed>"#
        );
    }

    // Unprefixed element with the same URI also bound to `a:`. The element
    // utilizes the default namespace, so `xmlns="urn:X"` renders and
    // `xmlns:a` does not.
    #[test]
    fn unprefixed_element_keeps_default_when_prefix_binds_same_uri() {
        let xml = r#"<signed xmlns:a="urn:X" xmlns="urn:X" ID="s1">text</signed>"#;
        assert_eq!(
            c14n(xml, "signed", &[]),
            r#"<signed xmlns="urn:X" ID="s1">text</signed>"#
        );
    }

    // =========================================================================
    // escape_text tests
    // =========================================================================

    #[test]
    fn escape_text_passthrough() {
        assert_eq!(escape_text("hello world"), "hello world");
    }

    #[test]
    fn escape_text_ampersand() {
        assert_eq!(escape_text("a & b"), "a &amp; b");
    }

    #[test]
    fn escape_text_lt_gt() {
        assert_eq!(escape_text("a < b > c"), "a &lt; b &gt; c");
    }

    #[test]
    fn escape_text_cr() {
        assert_eq!(escape_text("a\rb"), "a&#xD;b");
    }

    // =========================================================================
    // escape_attribute tests
    // =========================================================================

    #[test]
    fn escape_attr_passthrough() {
        assert_eq!(escape_attribute("hello"), "hello");
    }

    #[test]
    fn escape_attr_all_specials() {
        assert_eq!(
            escape_attribute("a&b<c\"d\te\nf\rg"),
            "a&amp;b&lt;c&quot;d&#x9;e&#xA;f&#xD;g"
        );
    }

    // =========================================================================
    // Basic canonicalization tests
    // =========================================================================

    #[test]
    fn simple_element() {
        let result = c14n(
            r#"<root xmlns="urn:test"><child>text</child></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:test"><child>text</child></root>"#
        );
    }

    #[test]
    fn empty_element_expansion() {
        let result = c14n("<root><empty/></root>", "root", &[]);
        assert_eq!(result, "<root><empty></empty></root>");
    }

    #[test]
    fn special_char_escaping_text() {
        let result = c14n("<root>a &amp; b &lt; c &gt; d</root>", "root", &[]);
        assert_eq!(result, "<root>a &amp; b &lt; c &gt; d</root>");
    }

    #[test]
    fn special_char_escaping_attribute() {
        let result = c14n(r#"<root attr="a&amp;b&lt;c&quot;d"/>"#, "root", &[]);
        // roxmltree normalizes the attribute value: &amp; -> &, &lt; -> <, &quot; -> "
        // Then escape_attribute re-escapes them for canonical form.
        assert_eq!(result, r#"<root attr="a&amp;b&lt;c&quot;d"></root>"#);
    }

    #[test]
    fn namespace_sorting() {
        // Namespace declarations sorted by prefix.
        let result = c14n(
            r#"<root xmlns:z="urn:z" xmlns:a="urn:a"><z:child a:attr="v"/></root>"#,
            "root",
            &[],
        );
        // In exc-c14n, root has no visibly utilized namespaces (no prefix on root).
        // z:child has both a: (from a:attr) and z: (from z:child) visibly utilized.
        assert_eq!(
            result,
            r#"<root><z:child xmlns:a="urn:a" xmlns:z="urn:z" a:attr="v"></z:child></root>"#
        );
    }

    #[test]
    fn attribute_sorting() {
        // Attributes sorted by namespace URI then local name.
        // No-namespace attributes sort first (empty URI < any real URI).
        let result = c14n(
            r#"<root xmlns:b="urn:b" xmlns:a="urn:a"><e b:y="2" a:x="1" local="0"/></root>"#,
            "e",
            &[],
        );
        assert_eq!(
            result,
            r#"<e xmlns:a="urn:a" xmlns:b="urn:b" local="0" a:x="1" b:y="2"></e>"#
        );
    }

    /// Multiple unprefixed attributes must sort alphabetically by local name.
    #[test]
    fn multiple_unprefixed_attributes_sort_alphabetically() {
        let result = c14n(
            r#"<root xmlns:md="urn:md"><md:elem entityID="https://idp.example.com" ID="_abc"/></root>"#,
            "elem",
            &[],
        );
        // ID sorts before entityID alphabetically ('I' < 'e').
        // Wait: uppercase 'I' (0x49) < lowercase 'e' (0x65) in ASCII, so "ID" < "entityID".
        assert_eq!(
            result,
            r#"<md:elem xmlns:md="urn:md" ID="_abc" entityID="https://idp.example.com"></md:elem>"#
        );
    }

    #[test]
    fn default_namespace_undeclaration() {
        let result = c14n(
            r#"<root xmlns="urn:default"><child xmlns="">text</child></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:default"><child xmlns="">text</child></root>"#
        );
    }

    #[test]
    fn default_namespace_undeclared_on_child_without_ns() {
        // Child element has no namespace but parent has default NS --
        // canonical form must emit xmlns="" on the child.
        let result = c14n(
            r#"<root xmlns="urn:default"><child>text</child></root>"#,
            "root",
            &[],
        );
        // roxmltree: <child> inside xmlns="urn:default" inherits the default NS.
        // So child IS in urn:default. It should NOT get xmlns="".
        // The undeclaration only happens when child has NO namespace at all.
        // Since the child here inherits urn:default, it stays in that namespace.
        assert_eq!(
            result,
            r#"<root xmlns="urn:default"><child>text</child></root>"#
        );
    }

    /// Regression for the ns_rendered dictionary semantics (exc-c14n
    /// section 3.1): after a declare -> undeclare -> redeclare chain, the
    /// deepest element must still get its `xmlns=""` undeclaration. With the
    /// old set-based tracking, the historical `("", "")` entry from the
    /// undeclare level was returned by the default-namespace lookup
    /// (lexicographically smallest), so the final `xmlns=""` was skipped.
    #[test]
    fn default_namespace_undeclaration_after_redeclaration() {
        let result = c14n(
            r#"<root xmlns="urn:a"><child xmlns=""><grandchild xmlns="urn:b"><leaf xmlns="">text</leaf></grandchild></child></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:a"><child xmlns=""><grandchild xmlns="urn:b"><leaf xmlns="">text</leaf></grandchild></child></root>"#
        );
    }

    /// A redeclared default namespace on a middle element must still be
    /// undeclared on a child with no namespace (three-level variant).
    #[test]
    fn default_namespace_undeclared_after_middle_redeclaration() {
        let result = c14n(
            r#"<root><child2 xmlns="urn:b"><child3 xmlns="">text</child3></child2></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root><child2 xmlns="urn:b"><child3 xmlns="">text</child3></child2></root>"#
        );
    }

    // =========================================================================
    // exc-c14n §3 point 4 condition 1: xmlns="" only on unprefixed elements
    //
    // A prefixed element that explicitly writes xmlns="" against an
    // ancestor-rendered non-empty default namespace must NOT itself receive
    // xmlns="" (it does not visibly utilize the default namespace). The
    // undeclaration moves to the nearest unprefixed descendant. The reference
    // forms below were verified against `xmllint --exc-c14n` (libxml2, the
    // engine xmlsec1 is built on).
    // =========================================================================

    // exc-c14n §3 point 4 cond. 1: a prefixed element does not visibly utilize the default namespace,
    // so xmlns="" is never emitted on it even when it declares xmlns="".
    #[test]
    fn prefixed_element_xmlns_undeclaration_emits_nothing() {
        // No unprefixed descendant exists, so the undeclaration is dropped
        // entirely (a prefixed element has no default namespace node in the
        // node-set and there is no unprefixed descendant to receive xmlns="").
        let result = c14n(
            r#"<root xmlns="urn:a"><x:mid xmlns:x="urn:x" xmlns="">text</x:mid></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:a"><x:mid xmlns:x="urn:x">text</x:mid></root>"#
        );
    }

    // exc-c14n §3 point 4 cond. 1: the xmlns="" required by the undeclaration lands on the nearest
    // unprefixed descendant, never on the prefixed element that wrote xmlns="".
    #[test]
    fn prefixed_xmlns_undeclaration_moves_to_unprefixed_descendant() {
        let result = c14n(
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" xmlns=""><leaf>text</leaf></b:mid></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b"><leaf xmlns="">text</leaf></b:mid></root>"#
        );
    }

    // exc-c14n §3 point 4 cond. 1: the undeclaration reaches the nearest unprefixed descendant even
    // when the prefixed element has attributes (no namespace prefix => visibly utilizes default).
    #[test]
    fn prefixed_xmlns_undeclaration_with_attributes_reaches_unprefixed_descendant() {
        let result = c14n(
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" b:kind="x" xmlns=""><leaf>text</leaf></b:mid></root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" b:kind="x"><leaf xmlns="">text</leaf></b:mid></root>"#
        );
    }

    // exc-c14n §3 point 4 cond. 1 + SAML Core §2.7.3: a signed assertion body may carry arbitrary
    // XML in AttributeValue; a prefixed element there that undeclares an ancestor-rendered
    // default namespace must place xmlns="" on its unprefixed descendant.
    #[test]
    fn saml_attribute_value_prefixed_xmlns_undeclaration_reaches_inner() {
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:AttributeStatement><saml:Attribute Name="doc"><saml:AttributeValue><doc xmlns="urn:doc"><sig:detached xmlns:sig="urn:sig" xmlns=""><inner>payload</inner></sig:detached></doc></saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#;
        let result = c14n(xml, "Assertion", &[]);
        assert_eq!(
            result,
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:AttributeStatement><saml:Attribute Name="doc"><saml:AttributeValue><doc xmlns="urn:doc"><sig:detached xmlns:sig="urn:sig"><inner xmlns="">payload</inner></sig:detached></doc></saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#
        );
    }

    // exc-c14n §3 point 4 cond. 1 + §4 (InclusiveNamespaces #default): when `#default` is
    // NOT in the PrefixList the "no prefix" gate applies and `xmlns=""` lands on the nearest
    // unprefixed descendant. When `#default` IS in the PrefixList, §3.1 step 3.3.1 cond. 1
    // bypasses the gate, so a *prefixed* element that explicitly undeclares an ancestor-rendered
    // non-empty default namespace renders `xmlns=""` on itself -- matching libxml2/xmlsec1
    // (the engine every mainstream SAML IdP uses) byte-for-byte. Reference form below was
    // verified against `xmllint --exc-c14n` with `inclusive_prefixes=["#default"]`.
    #[test]
    fn prefixed_xmlns_undeclaration_with_inclusive_default_emits_on_declaring_element() {
        let xml = r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" xmlns=""><leaf>text</leaf></b:mid></root>"#;
        let without = c14n(xml, "root", &[]);
        let with_default = c14n(xml, "root", &["#default"]);

        // No #default: the "no prefix" gate keeps xmlns="" off the prefixed <b:mid>;
        // it lands on the nearest unprefixed descendant <leaf>.
        assert_eq!(
            without,
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b"><leaf xmlns="">text</leaf></b:mid></root>"#
        );

        // With #default: the gate is bypassed and xmlns="" is emitted on <b:mid> itself,
        // sorted before xmlns:b (empty prefix sorts first) -- exactly as libxml2 produces.
        assert_eq!(
            with_default,
            r#"<root xmlns="urn:a"><b:mid xmlns="" xmlns:b="urn:b"><leaf>text</leaf></b:mid></root>"#
        );

        // #default changes the placement of xmlns="" (the old code asserted equality here
        // and so locked in the bug; this inequality guards against any regression of the gate).
        assert_ne!(with_default, without);
    }

    // exc-c14n §3.1 3.3.1 cond. 1 (deeper shape): with `#default` the undeclaration is emitted
    // on the prefixed declaring element even when that element has a deeper unprefixed
    // descendant that itself re-undeclares a redeclared default. Verified against
    // `xmllint --exc-c14n` with `inclusive_prefixes=["#default"]`.
    #[test]
    fn prefixed_xmlns_undeclaration_with_inclusive_default_deeper_shape() {
        let xml = r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" xmlns=""><b:inner xmlns="urn:i"><leaf xmlns="">text</leaf></b:inner></b:mid></root>"#;
        let without = c14n(xml, "root", &[]);
        let with_default = c14n(xml, "root", &["#default"]);

        // No #default: xmlns="" is deferred from <b:mid> to the nearest unprefixed descendant.
        // <b:inner> is prefixed (inherits xmlns:b) and declares xmlns="urn:i", but that
        // declaration is not visibly utilized by b:inner itself, so it is dropped by exc-c14n;
        // the rendered default at <leaf> is still urn:a, which <leaf> then undeclares.
        assert_eq!(
            without,
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b"><b:inner><leaf xmlns="">text</leaf></b:inner></b:mid></root>"#
        );

        // With #default: xmlns="" is emitted on <b:mid> (sorted first), xmlns="urn:i" is now
        // visibly utilized on <b:inner> (forced by #default) so it is rendered there, and
        // <leaf> then undeclares urn:i. Matches libxml2 byte-for-byte.
        assert_eq!(
            with_default,
            r#"<root xmlns="urn:a"><b:mid xmlns="" xmlns:b="urn:b"><b:inner xmlns="urn:i"><leaf xmlns="">text</leaf></b:inner></b:mid></root>"#
        );
        assert_ne!(with_default, without);
    }

    // XML Signature §4.4.1: the #default-corrected canonical form is a stable fixed point
    // (canonicalizing canonical output changes nothing), guarding against a re-canonicalization
    // drift for the bug-trigger shape under the production PrefixList.
    #[test]
    fn idempotency_prefixed_xmlns_undeclaration_with_inclusive_default() {
        let input = r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" xmlns=""><leaf>text</leaf></b:mid></root>"#;
        let doc1 = roxmltree::Document::parse(input).unwrap();
        let root1 = doc1
            .root()
            .children()
            .find(|n| n.is_element())
            .expect("No root element");
        let first = exclusive_c14n(root1, &["#default"]);

        let doc2 = roxmltree::Document::parse(&first).expect("First c14n output is invalid XML");
        let root2 = doc2
            .root()
            .children()
            .find(|n| n.is_element())
            .expect("No root in re-parsed c14n output");
        let second = exclusive_c14n(root2, &["#default"]);

        assert_eq!(
            first, second,
            "Idempotency failed for #default input: {input}"
        );
        assert_eq!(
            first,
            r#"<root xmlns="urn:a"><b:mid xmlns="" xmlns:b="urn:b"><leaf>text</leaf></b:mid></root>"#
        );
    }

    // XML Signature §4.4.1: canonicalizing canonical output changes nothing, including for the
    // bug-trigger shapes (confirms the fixed output is a stable fixed point).
    #[test]
    fn idempotency_prefixed_xmlns_undeclaration() {
        let inputs = [
            r#"<root xmlns="urn:a"><x:mid xmlns:x="urn:x" xmlns="">text</x:mid></root>"#,
            r#"<root xmlns="urn:a"><b:mid xmlns:b="urn:b" xmlns=""><leaf>text</leaf></b:mid></root>"#,
        ];
        for input in inputs {
            let doc1 = roxmltree::Document::parse(input).unwrap();
            let root1 = doc1
                .root()
                .children()
                .find(|n| n.is_element())
                .expect("No root element");
            let first = exclusive_c14n(root1, &[]);

            let doc2 =
                roxmltree::Document::parse(&first).expect("First c14n output is invalid XML");
            let root2 = doc2
                .root()
                .children()
                .find(|n| n.is_element())
                .expect("No root in re-parsed c14n output");
            let second = exclusive_c14n(root2, &[]);

            assert_eq!(first, second, "Idempotency failed for input: {input}");
        }
    }

    /// A prefix re-bound to a different URI by a descendant must be
    /// re-emitted even if the original (prefix, uri) pair was rendered by
    /// an outer ancestor (dictionary lookup, not exact-pair membership).
    #[test]
    fn prefix_rebinding_re_emits_original_uri() {
        let result = c14n(
            r#"<a:root xmlns:a="urn:1"><a:mid xmlns:a="urn:2"><a:leaf xmlns:a="urn:1">text</a:leaf></a:mid></a:root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<a:root xmlns:a="urn:1"><a:mid xmlns:a="urn:2"><a:leaf xmlns:a="urn:1">text</a:leaf></a:mid></a:root>"#
        );
    }

    #[test]
    fn exclusive_ns_filtering() {
        // Exc-c14n only renders visibly utilized namespaces.
        // When canonicalizing the child element, a: and b: are not utilized.
        let result = c14n(
            r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><child xmlns:a="urn:a">text</child></root>"#,
            "child",
            &[],
        );
        // Neither a: nor b: is visibly utilized by child element or its attrs.
        // The child has its own xmlns:a="urn:a" declaration but does not USE it.
        assert_eq!(result, "<child>text</child>");
    }

    #[test]
    fn inclusive_prefixes_from_prefixlist() {
        // InclusiveNamespaces PrefixList forces rendering of listed prefixes.
        // saml prefix is not visibly utilized but is forced by PrefixList.
        // Per W3C exc-c14n spec section 4, "already rendered" optimization
        // still applies: xmlns:ds and xmlns:saml appear on ds:SignedInfo but
        // NOT repeated on ds:Reference (ancestor already rendered them).
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><ds:SignedInfo><ds:Reference URI="#id"/></ds:SignedInfo></root>"##;
        let result = c14n(xml, "SignedInfo", &["ds", "saml"]);
        // ds:SignedInfo gets xmlns:ds (visibly utilized) and xmlns:saml (from PrefixList).
        // ds:Reference gets xmlns:ds? No -- ancestor (SignedInfo) already rendered it.
        assert_eq!(
            result,
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><ds:Reference URI="#id"></ds:Reference></ds:SignedInfo>"##
        );
    }

    #[test]
    fn inclusive_default_namespace() {
        // PrefixList with #default forces default namespace rendering.
        let result = c14n(
            r#"<root xmlns="urn:default" xmlns:a="urn:a"><child>text</child></root>"#,
            "child",
            &["#default"],
        );
        // child inherits urn:default but without #default in PrefixList it wouldn't render it.
        // With #default, the default namespace is forced visible.
        assert_eq!(result, r#"<child xmlns="urn:default">text</child>"#);
    }

    /// Namespace re-declaration with different URI must re-emit the declaration.
    #[test]
    fn namespace_redeclaration_with_different_uri() {
        let xml = r#"<root xmlns:a="urn:one"><child xmlns:a="urn:two"><a:elem/></child></root>"#;
        let result = c14n(xml, "elem", &[]);
        // a:elem uses prefix "a" which maps to "urn:two" in this scope.
        // Even though an ancestor had xmlns:a="urn:one", this is a different (prefix, uri) pair.
        assert_eq!(result, r#"<a:elem xmlns:a="urn:two"></a:elem>"#);
    }

    /// InclusiveNamespaces with prefixes not in scope must be silently skipped.
    #[test]
    fn inclusive_prefixes_out_of_scope_silently_skipped() {
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Info/></root>"##;
        // xs and xsi are NOT in scope at all.
        let result = c14n(xml, "Info", &["ds", "xs", "xsi"]);
        // xs and xsi should not appear in output since they're not declared anywhere.
        assert_eq!(
            result,
            r##"<ds:Info xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Info>"##
        );
    }

    /// W3C exc-c14n spec Section 2.2 example (same input, partial assertions).
    /// See `w3c_section_2_2_context_independent_output` above for the full
    /// spec-conformant version with both contexts.
    // XML Signature §4.4.1: exclusive canonicalization matches the published example.
    #[test]
    fn w3c_example_section_2_2_partial() {
        let xml = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">
  <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
    <n3:stuff xmlns:n3="ftp://example.org"/>
  </n1:elem2>
</n0:local>"#;
        let result = c14n(xml, "elem2", &[]);
        // n1:elem2 is visibly utilized so xmlns:n1 appears.
        // xml:lang renders the attribute but NOT xmlns:xml.
        // n3 is not visibly utilized by elem2 itself, so NOT rendered on elem2.
        // n3:stuff has n3 visibly utilized, so it DOES re-declare xmlns:n3.
        assert!(
            result.starts_with(r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">"#),
            "Should start with elem2 opening: {result}"
        );
        assert!(
            !result.contains(concat!("xmlns", ":", "xml")),
            "Should NOT contain xmlns:xml: {result}"
        );
        assert!(
            result.contains(r#"<n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>"#),
            "n3:stuff should re-declare xmlns:n3: {result}"
        );
        assert!(
            !result.contains(concat!("xmlns", ":", "n0")),
            "n0 not visibly utilized by elem2: {result}"
        );
        assert!(
            result.ends_with("</n1:elem2>"),
            "Should end with closing tag: {result}"
        );
    }

    // =========================================================================
    // W3C Exclusive XML Canonicalization 1.0 spec examples
    // https://www.w3.org/TR/xml-exc-c14n/
    // =========================================================================

    /// W3C exc-c14n Section 2.1: Simple re-enveloping.
    ///
    /// Inclusive c14n of n1:elem1 includes ancestor namespace n0 (undesirable).
    /// Exclusive c14n omits n0 since it's not visibly utilized.
    // XML Signature §4.4.1: exclusive canonicalization matches the published example.
    #[test]
    fn w3c_section_2_1_simple_enveloping() {
        let xml = r#"<n0:pdu xmlns:n0="http://a.example">
   <n1:elem1 xmlns:n1="http://b.example">
       content
   </n1:elem1>
</n0:pdu>"#;
        let result = c14n(xml, "elem1", &[]);
        // Exclusive c14n: n0 is NOT visibly utilized by elem1, so omitted.
        // Only n1 (used as element prefix) is emitted.
        assert!(
            !result.contains("http://a.example"),
            "n0 should be excluded (not visibly utilized): {result}"
        );
        assert!(
            result.contains(r#"xmlns:n1="http://b.example""#),
            "n1 should be present (visibly utilized): {result}"
        );
        assert!(
            result.contains("content"),
            "Text content preserved: {result}"
        );
    }

    /// W3C exc-c14n Section 2.2: Complex re-enveloping (primary spec example).
    ///
    /// The spec states that exclusive c14n of n1:elem2 from BOTH the original
    /// document and a different enveloping context must produce identical output:
    ///
    /// ```xml
    /// <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
    ///     <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
    /// </n1:elem2>
    /// ```
    ///
    /// This is the definitive test for context-independent canonicalization.
    // XML Signature §4.4.1: exclusive canonicalization omits context the element does not use.
    #[test]
    fn w3c_section_2_2_context_independent_output() {
        // Original document context
        let original = r#"<n0:local xmlns:n0="foo:bar"
          xmlns:n3="ftp://example.org">
   <n1:elem2 xmlns:n1="http://example.net"
             xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n0:local>"#;

        // Different enveloping context (from spec Section 2.2)
        let re_enveloped = r#"<n2:pdu xmlns:n1="http://example.com"
        xmlns:n2="http://foo.example"
        xml:lang="fr"
        xml:space="retain">
   <n1:elem2 xmlns:n1="http://example.net"
             xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n2:pdu>"#;

        let result_original = c14n(original, "elem2", &[]);
        let result_re_enveloped = c14n(re_enveloped, "elem2", &[]);

        // Both contexts MUST produce identical output (the whole point of exc-c14n).
        assert_eq!(
            result_original, result_re_enveloped,
            "Exclusive c14n must be context-independent"
        );

        // Verify the output matches the spec's expected canonical form.
        // n1: visibly utilized (element prefix) → included
        assert!(
            result_original
                .starts_with(r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">"#),
            "Opening tag must have n1 and xml:lang: {result_original}"
        );
        // n0: NOT visibly utilized → excluded
        assert!(
            !result_original.contains("foo:bar"),
            "n0 (foo:bar) must be excluded: {result_original}"
        );
        // n2: NOT visibly utilized → excluded
        assert!(
            !result_original.contains("http://foo.example"),
            "n2 must be excluded: {result_original}"
        );
        // n3: visibly utilized by n3:stuff → included on n3:stuff only
        assert!(
            result_original.contains(r#"<n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>"#),
            "n3:stuff must declare n3: {result_original}"
        );
        // xml:space from re-enveloped context must NOT leak in
        assert!(
            !result_original.contains("xml:space"),
            "xml:space must not appear: {result_original}"
        );
        // xml:lang is an attribute on elem2, not a namespace → preserved
        assert!(
            result_original.contains(r#"xml:lang="en""#),
            "xml:lang attribute preserved: {result_original}"
        );
    }

    /// W3C exc-c14n Section 2.2 with InclusiveNamespaces PrefixList.
    ///
    /// When n0 is in the PrefixList, it should be included in the output
    /// even though it's not visibly utilized — this is how
    /// InclusiveNamespaces forces namespace inheritance.
    // XML Signature §4.4.3.4: prefixes named in InclusiveNamespaces are retained.
    #[test]
    fn w3c_section_2_2_with_inclusive_prefixes() {
        let xml = r#"<n0:local xmlns:n0="foo:bar"
          xmlns:n3="ftp://example.org">
   <n1:elem2 xmlns:n1="http://example.net"
             xml:lang="en">
       <n3:stuff xmlns:n3="ftp://example.org"/>
   </n1:elem2>
</n0:local>"#;

        // Force n0 to be included via PrefixList
        let result = c14n(xml, "elem2", &["n0"]);

        // n0 should now appear on elem2 (forced by PrefixList)
        assert!(
            result.contains(r#"xmlns:n0="foo:bar""#),
            "n0 should be included when in PrefixList: {result}"
        );
        // n1 still present (visibly utilized)
        assert!(
            result.contains(r#"xmlns:n1="http://example.net""#),
            "n1 should still be present: {result}"
        );
    }

    /// Idempotency: c14n(c14n(x)) == c14n(x) for a set of SAML-like inputs.
    // XML Signature §4.4.1: canonicalizing canonical output changes nothing.
    #[test]
    fn idempotency_simple() {
        let inputs = [
            r#"<root xmlns="urn:test"><child>text</child></root>"#,
            r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><a:child b:attr="v">text</a:child></root>"#,
            r#"<root><empty/></root>"#,
        ];

        for input in inputs {
            let doc1 = roxmltree::Document::parse(input).unwrap();
            let root1 = doc1
                .root()
                .children()
                .find(|n| n.is_element())
                .expect("No root element");
            let first = exclusive_c14n(root1, &[]);

            let doc2 =
                roxmltree::Document::parse(&first).expect("First c14n output is invalid XML");
            let root2 = doc2
                .root()
                .children()
                .find(|n| n.is_element())
                .expect("No root in re-parsed c14n output");
            let second = exclusive_c14n(root2, &[]);

            assert_eq!(first, second, "Idempotency failed for input: {input}");
        }
    }

    /// Realistic SAML ds:SignedInfo canonicalization.
    // XML Signature §4.4.1: the SignedInfo element canonicalizes as the signature requires.
    #[test]
    fn saml_signed_info_realistic() {
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_abc123">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abc123==</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>sig==</ds:SignatureValue>
  </ds:Signature>
</samlp:Response>"##;

        let result = c14n(xml, "SignedInfo", &[]);

        // Workaround: Rust edition 2024 reserves prefix:ident syntax in literals.
        assert!(
            result.contains("SignedInfo"),
            "Should contain SignedInfo: {result}"
        );
        assert!(
            result.contains("xmldsig"),
            "Should contain ds namespace: {result}"
        );
        assert!(
            !result.contains("samlp"),
            "samlp should NOT appear (not visibly utilized): {result}"
        );
        assert!(
            !result.contains("/>"),
            "No self-closing tags in canonical form: {result}"
        );
    }

    // =========================================================================
    // Attribute prefix resolution: default-namespace binding exclusion
    //
    // Namespaces in XML §6.3: "the default namespace does not apply to
    // attribute names". exc-c14n §3 item 3 renders a namespace node only if
    // "it is visibly utilized by its parent element" or its attributes. An
    // element that binds one URI as both `xmlns="urn:X"` and `xmlns:a="urn:X"`
    // and carries `a:attr="v"` therefore emits `a:attr` and renders
    // `xmlns:a="urn:X"`. Expected strings come from libxml2 2.9.14
    // (`xmllint --exc-c14n`).
    // =========================================================================

    // A default and a prefixed binding of one URI: the attribute takes the
    // prefixed binding, so the output has `a:attr` and `xmlns:a`.
    #[test]
    fn attribute_uses_prefixed_binding_when_default_and_prefixed_co_declared() {
        let result = c14n(
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</signed>"#,
            "signed",
            &[],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
        // A bare-colon name with no `xmlns:a` is the form libxml2 rejects.
        assert_ne!(
            result, r#"<signed xmlns="urn:X" ID="s1" :attr="v">text</signed>"#,
            "fix must not emit a bare-colon attribute name or drop xmlns:a"
        );
        assert!(
            !result.contains(" :attr="),
            "no bare-colon attribute name allowed: {result}"
        );
        assert!(
            result.contains(r#"xmlns:a="urn:X""#),
            "xmlns:a declaration the attribute depends on must be rendered: {result}"
        );
    }

    // exc-c14n §1: the method "excludes ancestor context from a canonicalized
    // subdocument". The subtree canonicalizes to the same bytes at the root and
    // under an ancestor whose bindings it does not utilize.
    #[test]
    fn attribute_prefixed_binding_is_context_independent() {
        let nested = c14n(
            r#"<wrap xmlns="urn:R" xmlns:b="urn:R"><signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</signed></wrap>"#,
            "signed",
            &[],
        );
        assert_eq!(
            nested,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }

    // exc-c14n §3 item 3 condition 3: a namespace node renders only if "the
    // prefix has not yet been rendered by any output ancestor". The child reuses
    // `a:` from its parent and renders only its own `xmlns:b`.
    #[test]
    fn attribute_prefixed_binding_not_re_rendered_on_child() {
        let result = c14n(
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" xmlns:b="urn:Y" a:attr="v" ID="s1"><b:inner a:z="1">t</b:inner></signed>"#,
            "signed",
            &[],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v"><b:inner xmlns:b="urn:Y" a:z="1">t</b:inner></signed>"#
        );
    }

    // XML Names: the prefixed binding an attribute needs may live on an ANCESTOR
    // while the element itself only re-declares the same URI as the default
    // namespace. The resolver must skip the element's own default binding (invalid
    // for an attribute) and use the ancestor's prefixed binding, rendering
    // `xmlns:a` on the element. Verified against `xmllint --exc-c14n`.
    #[test]
    fn attribute_prefix_resolved_from_ancestor_when_element_only_declares_default() {
        let result = c14n(
            r#"<outer xmlns:a="urn:X"><signed xmlns="urn:X" a:attr="v" ID="s1">text</signed></outer>"#,
            "signed",
            &[],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }

    // XML Names: the element may inherit an ancestor default namespace (rendered
    // as `xmlns="..."`) while declaring the prefixed binding its attribute needs
    // on itself. Both the default (for the element) and the prefixed (for the
    // attribute) bindings render. Verified against `xmllint --exc-c14n`.
    #[test]
    fn attribute_prefix_default_from_ancestor_prefixed_on_self() {
        let result = c14n(
            r#"<root xmlns="urn:R"><signed xmlns:a="urn:X" a:attr="v" ID="s1">text</signed></root>"#,
            "signed",
            &[],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:R" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }

    // Production-shaped trigger: a prefixed `<ds:SignedInfo>` (the exact node
    // `exclusive_c14n` is called on directly at `signature.rs:230`) that
    // co-declares a default+prefixed binding and carries a prefixed attribute
    // using that URI. The prefixed element does NOT visibly utilize the default
    // namespace, so `xmlns="urn:X"` is omitted; only `xmlns:a` (the attribute's
    // prefix) and `xmlns:ds` (the element's prefix, inherited from the parent)
    // render. Verified against `xmllint --exc-c14n`.
    #[test]
    fn signed_info_shape_default_and_prefixed_collision_with_prefixed_attr() {
        let result = c14n(
            r##"<ds:Signature xmlns:ds="urn:ds"><ds:SignedInfo xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1"><ds:Reference URI="#s1"/></ds:SignedInfo></ds:Signature>"##,
            "SignedInfo",
            &[],
        );
        assert_eq!(
            result,
            r##"<ds:SignedInfo xmlns:a="urn:X" xmlns:ds="urn:ds" ID="s1" a:attr="v"><ds:Reference URI="#s1"></ds:Reference></ds:SignedInfo>"##
        );
    }

    // A namespaced attribute with no default binding for the same URI.
    #[test]
    fn attribute_prefixed_binding_regression_without_default_collision() {
        let result = c14n(
            r#"<root xmlns:a="urn:X" a:attr="v" ID="s1">text</root>"#,
            "root",
            &[],
        );
        assert_eq!(
            result,
            r#"<root xmlns:a="urn:X" ID="s1" a:attr="v">text</root>"#
        );
    }

    // Canonical output canonicalizes to itself.
    #[test]
    fn idempotency_attribute_prefixed_binding_after_default_collision() {
        let input = r#"<signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</signed>"#;
        let doc1 = roxmltree::Document::parse(input).unwrap();
        let root1 = doc1
            .root()
            .children()
            .find(|n| n.is_element())
            .expect("No root element");
        let first = exclusive_c14n(root1, &[]);

        let doc2 = roxmltree::Document::parse(&first).expect("First c14n output is invalid XML");
        let root2 = doc2
            .root()
            .children()
            .find(|n| n.is_element())
            .expect("No root in re-parsed c14n output");
        let second = exclusive_c14n(root2, &[]);

        assert_eq!(first, second, "Idempotency failed for input: {input}");
        assert_eq!(
            first,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }

    // exc-c14n §4 + XML Names: InclusiveNamespaces PrefixList interactively
    // listing the attribute's own prefix is a no-op here (already visibly
    // utilized), and the prefixed binding is still chosen over the default for
    // the attribute. Verified against libxml2 (inclusive_ns_prefixes=["a"]).
    #[test]
    fn attribute_prefixed_binding_with_inclusive_prefix_listed() {
        let result = c14n(
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</signed>"#,
            "signed",
            &["a"],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }

    // exc-c14n §4 + XML Names: `#default` in InclusiveNamespaces PrefixList
    // forces the default namespace visible but does NOT cause the attribute to
    // take it; the prefixed binding is still chosen for the attribute.
    // Verified against libxml2 (inclusive_ns_prefixes=["#default"]).
    #[test]
    fn attribute_prefixed_binding_with_inclusive_default_listed() {
        let result = c14n(
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" a:attr="v" ID="s1">text</signed>"#,
            "signed",
            &["#default"],
        );
        assert_eq!(
            result,
            r#"<signed xmlns="urn:X" xmlns:a="urn:X" ID="s1" a:attr="v">text</signed>"#
        );
    }
}
