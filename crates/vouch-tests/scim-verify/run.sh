#!/bin/sh
# Runs SCIM Verify inside its image. Mounted at /config; reads SCIM_BASE_URL
# and SCIM_AUTH_HEADER from the environment and writes TAP to stdout.
set -eu

# SCIM Verify 1.0.5 compares an error's "status" to the number 400. RFC 7644
# §3.12 defines it as "The HTTP status code (see Section 6 of [RFC7231])
# expressed as a JSON string. REQUIRED.", and Verified erratum 7898 keeps the
# §3.12 example's "status": "400". Compare against the string instead. The
# grep fails the run if the assertion changes, so this edit cannot silently
# stop applying.
assertion='assert.strictEqual(response.data.status, 400,'
grep -qF "$assertion" src/groups.js
sed -i "s/response\.data\.status, 400,/response.data.status, \"400\",/" src/groups.js
grep -qF 'response.data.status, "400",' src/groups.js

exec node bin/scimverify.js \
  --base-url "$SCIM_BASE_URL" \
  --auth-header "$SCIM_AUTH_HEADER" \
  --config /config/config.yaml \
  --har-file /out/scim-verify.har
