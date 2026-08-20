# Specifications Are the Source of Truth

Read by every agent before implementing, reviewing, or describing
protocol behavior. Vouch implements ~25 RFCs and OIDC/SAML/SCIM
specifications and is OpenID Certified; a wrong assumption about
normative text ships as a conformance defect.

## The rule

**Never state what a specification requires from memory. Open it.**

Model training data reproduces the *shape* of a spec sentence reliably
and its *content* unreliably. The failure is not "I don't know" — it is
a fluent, plausible, correctly-formatted sentence that is not in the
document. That is indistinguishable from a real citation at review time,
which is what makes it dangerous.

This applies to reviews and PR descriptions as much as to code. Saying
"this is a spec violation" is a normative claim and needs the same
evidence as writing the code.

## What a citation must contain

A claim about required behavior is only supported by all three:

1. The document and section number — "OIDC Core 3.1.2.1", not "the OIDC spec".
2. A **verbatim quote** of the sentence carrying the requirement.
3. The URL it was fetched from, in this session.

Without the quote it is not a citation. `// per RFC 9449` on its own
records that someone believed something, not what the RFC says.

## Verify the fetch, not just the answer

Summarizers hallucinate normative text. In one session a lookup produced
a fluent sentence about returning HTTP 400 for an unsupported
`response_mode`, attributed to a real section of a real spec. No such
sentence exists in any OAuth or OIDC document.

So: when a quote is load-bearing — when it decides a behavior, settles a
review, or justifies a merge — confirm it against a second source or a
targeted search for the exact phrase. If the phrase cannot be found
again, it is not real.

## MUST, SHOULD, MAY are not interchangeable

Report the actual strength. Three real examples from one session:

- Unrecognized `prompt`: "it MAY return an error or it MAY ignore it" —
  both behaviors are conformant, so consistency is a product decision,
  not a compliance one.
- `response_mode` for errors: "All parameters returned from the
  Authorization Endpoint SHOULD use the same Response Mode" — a
  recommendation, so calling a deviation a "violation" overstates it.
- JARM error responses: the JWT "MUST furthermore contain the
  authorization endpoint response parameters ... even in case of an
  error response" — no escape clause, so an unsigned fallback is a
  genuine violation.

Downgrading a MUST hides a real defect. Upgrading a MAY invents work and
burns credibility on the ones that matter.

## Silence is an answer, and it is not permission

If a spec does not address a case, say so explicitly. "The Form Post
Response Mode spec does not mention error responses" is a finding. It
means the decision is ours and should be justified on its merits —
interop, security, least surprise — rather than dressed up as
conformance.

## When the spec contradicts an earlier decision

The spec wins, including over a decision recorded in this repo, in the
knowledge base, or in a merged PR. Surface the contradiction with the
quote rather than quietly following the local convention: a merged PR
that is less strict than the spec is a live conformance gap, not
settled precedent.

## Record what you verify

Verified quotes go in the knowledge base under `references/` so the next
lookup is cheap and the corpus grows. A quote already recorded there,
with its section and URL, may be relied on without re-fetching — that is
the whole point of recording it.
