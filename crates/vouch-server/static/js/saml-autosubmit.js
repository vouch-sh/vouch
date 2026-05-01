// Auto-submit the SAML AuthnRequest form to the upstream IdP.
// Loaded by templates/saml_post_form.html via <script defer> so it runs
// after the form is parsed. Inline event handlers (e.g. body onload) are
// blocked by Content-Security-Policy script-src 'self'.
document.forms[0].submit();
