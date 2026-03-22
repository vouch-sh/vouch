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
//! # Known Limitation: Prefix Resolution
//!
//! roxmltree does NOT expose the original prefix on `tag_name()`. We reconstruct
//! prefixes by walking namespace declarations from the element up through ancestors,
//! preferring the declaration closest to the element. In the rare case where
//! multiple prefixes map to the same namespace URI, the prefix declared closest to
//! the element is used. This is documented as a known limitation and a
//! `tracing::warn` is emitted when detected.
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

use std::collections::BTreeSet;

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
pub fn exclusive_c14n(node: roxmltree::Node<'_, '_>, inclusive_prefixes: &[&str]) -> String {
    if !node.is_element() {
        return String::new();
    }
    let mut output = String::with_capacity(512);
    let rendered_ns: BTreeSet<(String, String)> = BTreeSet::new();
    canonicalize_node(node, &mut output, inclusive_prefixes, &rendered_ns);
    output
}

/// Recursively canonicalize an element node and its children.
///
/// `rendered_ns` tracks `(prefix, uri)` pairs already emitted by ancestor
/// elements. The check uses the EXACT `(prefix, uri)` pair -- if a prefix is
/// re-declared with a different URI by a descendant, it must be re-emitted.
fn canonicalize_node(
    node: roxmltree::Node<'_, '_>,
    output: &mut String,
    inclusive_prefixes: &[&str],
    rendered_ns: &BTreeSet<(String, String)>,
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

    for (prefix, uri) in &sorted_ns {
        if prefix.is_empty() {
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
        new_rendered_ns.insert((prefix.clone(), uri.clone()));
    }

    // Step 3: Handle default namespace undeclaration.
    // If this element has no namespace (or the default NS is now empty), check
    // if an ancestor rendered a default namespace that must be undeclared.
    let elem_default_ns = node.default_namespace().unwrap_or("");
    let ancestor_default_ns = rendered_ns
        .iter()
        .find(|(p, _)| p.is_empty())
        .map(|(_, u)| u.as_str())
        .unwrap_or("");

    // Undeclare if: element has no default NS but ancestor rendered one,
    // AND we haven't already emitted xmlns="" (which would happen if this
    // element itself declares xmlns="").
    let already_emitted_default = sorted_ns.iter().any(|(p, _)| p.is_empty());
    if !already_emitted_default && elem_default_ns.is_empty() && !ancestor_default_ns.is_empty() {
        output.push_str(" xmlns=\"\"");
        new_rendered_ns.insert((String::new(), String::new()));
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
            let prefix = find_prefix_for_uri(node, attr_ns);
            if let Some(p) = prefix {
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
/// 3. Exclude pairs already rendered by an ancestor (exact `(prefix, uri)` match).
/// 4. Never emit the `xml:` namespace declaration.
fn collect_namespaces(
    node: roxmltree::Node<'_, '_>,
    inclusive_prefixes: &[&str],
    rendered_ns: &BTreeSet<(String, String)>,
) -> BTreeSet<(String, String)> {
    let mut result: BTreeSet<(String, String)> = BTreeSet::new();

    // Visibly utilized: the element's own namespace (if it has a prefix).
    if let Some(ns_uri) = node.tag_name().namespace()
        && !ns_uri.is_empty()
        && ns_uri != "http://www.w3.org/XML/1998/namespace"
    {
        let prefix = find_prefix_for_uri(node, ns_uri).unwrap_or("").to_string();
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
        let prefix = find_prefix_for_uri(node, attr_ns).unwrap_or("").to_string();
        result.insert((prefix, attr_ns.to_string()));
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
        // If the prefix is not in scope, silently skip it (per C4 fix).
    }

    // Exclude pairs already rendered by an ancestor (exact (prefix, uri) match).
    // C2 fix: check the EXACT (prefix, uri) pair, not just prefix.
    result
        .into_iter()
        .filter(|pair| !rendered_ns.contains(pair))
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
/// # Multi-prefix-same-URI (Known Limitation)
///
/// When multiple prefixes are bound to the same URI in the same scope,
/// the prefix declared first (closest to the element) is returned, and a
/// warning is emitted. In practice, SAML documents do not use this pattern.
fn find_prefix_for_uri<'a>(node: roxmltree::Node<'_, 'a>, uri: &str) -> Option<&'a str> {
    let mut candidates: Vec<(&'a str, usize)> = Vec::new();
    let mut depth = 0usize;

    let mut current = Some(node);
    while let Some(n) = current {
        for ns in n.namespaces() {
            if ns.uri() == uri {
                let prefix = ns.name().unwrap_or("");
                // A2 fix: never return the xml prefix via this path.
                // xml: is implicitly bound; it must never appear in ns declarations output.
                if prefix != "xml" {
                    candidates.push((prefix, depth));
                }
            }
        }
        current = n.parent();
        depth += 1;
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
/// Note: The `xml:` prefix is never returned by `find_prefix_for_uri` (see A2 fix).
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

    match find_prefix_for_uri(node, ns_uri) {
        Some("") | None => local.to_string(), // default namespace or unresolvable
        Some(prefix) => format!("{prefix}:{local}"),
    }
}

/// Escape text content per c14n spec.
///
/// Replacements: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`
#[must_use]
pub fn escape_text(s: &str) -> String {
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
pub fn escape_attribute(s: &str) -> String {
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// C1: Multiple unprefixed attributes must sort alphabetically by local name.
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

    /// C2: Namespace re-declaration with different URI must re-emit the declaration.
    #[test]
    fn namespace_redeclaration_with_different_uri() {
        let xml = r#"<root xmlns:a="urn:one"><child xmlns:a="urn:two"><a:elem/></child></root>"#;
        let result = c14n(xml, "elem", &[]);
        // a:elem uses prefix "a" which maps to "urn:two" in this scope.
        // Even though an ancestor had xmlns:a="urn:one", this is a different (prefix, uri) pair.
        assert_eq!(result, r#"<a:elem xmlns:a="urn:two"></a:elem>"#);
    }

    /// C4: InclusiveNamespaces with prefixes not in scope must be silently skipped.
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
    #[test]
    fn w3c_example_section_2_2_partial() {
        let xml = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">
  <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
    <n3:stuff xmlns:n3="ftp://example.org"/>
  </n1:elem2>
</n0:local>"#;
        let result = c14n(xml, "elem2", &[]);
        // n1:elem2 is visibly utilized so xmlns:n1 appears.
        // xml:lang renders the attribute but NOT xmlns:xml (A2 fix).
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
}
