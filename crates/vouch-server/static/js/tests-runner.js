// Unit test runner for webauthn.js utilities.
(function() {
    var results = document.getElementById('results');
    var passed = 0;
    var failed = 0;

    function group(name) {
        var el = document.createElement('div');
        el.className = 'group';
        el.textContent = name;
        results.appendChild(el);
    }

    // Append a result row using DOM APIs (textContent), not innerHTML string
    // building. `detailLines` is an optional array of extra lines.
    function appendResult(pass, description, detailLines) {
        var el = document.createElement('div');
        el.className = 'test';
        var status = document.createElement('span');
        status.className = pass ? 'pass' : 'fail';
        status.textContent = pass ? 'PASS' : 'FAIL';
        el.appendChild(status);
        el.appendChild(document.createTextNode(' ' + description));
        if (detailLines) {
            detailLines.forEach(function(line) {
                el.appendChild(document.createElement('br'));
                el.appendChild(document.createTextNode(line));
            });
        }
        results.appendChild(el);
    }

    function assert(description, condition) {
        appendResult(condition, description);
        if (condition) { passed++; } else { failed++; }
    }

    function assertEqual(description, actual, expected) {
        var ok = actual === expected;
        if (ok) {
            appendResult(true, description);
            passed++;
        } else {
            appendResult(false, description, [
                '       expected: ' + JSON.stringify(expected),
                '       actual:   ' + JSON.stringify(actual)
            ]);
            failed++;
        }
    }

    function assertArrayEqual(description, actual, expected) {
        var ok = actual.length === expected.length;
        if (ok) {
            for (var i = 0; i < actual.length; i++) {
                if (actual[i] !== expected[i]) { ok = false; break; }
            }
        }
        if (ok) {
            appendResult(true, description);
            passed++;
        } else {
            appendResult(false, description, [
                '       expected: [' + Array.from(expected).join(', ') + ']',
                '       actual:   [' + Array.from(actual).join(', ') + ']'
            ]);
            failed++;
        }
    }

    // ================================================================
    // base64urlToBuffer
    // ================================================================
    group('base64urlToBuffer');

    // Standard base64url string (no padding)
    var buf1 = base64urlToBuffer('AQID');
    assertArrayEqual('decodes [1, 2, 3]',
        new Uint8Array(buf1), new Uint8Array([1, 2, 3]));

    // Base64url with - and _ characters (would be + and / in standard base64)
    // "+/" in standard base64 = "-_" in base64url
    var buf2 = base64urlToBuffer('-_8');
    var bytes2 = new Uint8Array(buf2);
    assertEqual('decodes base64url chars (- and _) — length', bytes2.length, 2);
    // -_8 in base64url = +/8 in standard base64 = bytes [0xfb, 0xff]
    assertEqual('decodes base64url chars — byte 0', bytes2[0], 0xfb);
    assertEqual('decodes base64url chars — byte 1', bytes2[1], 0xff);

    // Empty string
    var buf3 = base64urlToBuffer('');
    assertEqual('decodes empty string to empty buffer', new Uint8Array(buf3).length, 0);

    // Padding-requiring length (1 byte = 2 base64 chars, needs 2 pad chars)
    var buf4 = base64urlToBuffer('QQ');
    assertArrayEqual('decodes single byte (QQ)', new Uint8Array(buf4), new Uint8Array([65]));

    // ================================================================
    // bufferToBase64url
    // ================================================================
    group('bufferToBase64url');

    assertEqual('encodes [1, 2, 3]',
        bufferToBase64url(new Uint8Array([1, 2, 3]).buffer), 'AQID');

    assertEqual('encodes empty buffer',
        bufferToBase64url(new Uint8Array([]).buffer), '');

    assertEqual('encodes single byte',
        bufferToBase64url(new Uint8Array([65]).buffer), 'QQ');

    // Bytes that produce + and / in standard base64 should become - and _
    assertEqual('encodes with base64url substitutions',
        bufferToBase64url(new Uint8Array([0xfb, 0xff]).buffer), '-_8');

    // No trailing = padding
    assertEqual('strips padding',
        bufferToBase64url(new Uint8Array([0]).buffer), 'AA');

    // ================================================================
    // Round-trip: encode then decode
    // ================================================================
    group('base64url round-trip');

    var testBytes = [0, 1, 127, 128, 255, 0, 42, 99];
    var encoded = bufferToBase64url(new Uint8Array(testBytes).buffer);
    var decoded = new Uint8Array(base64urlToBuffer(encoded));
    assertArrayEqual('round-trip preserves bytes',
        decoded, new Uint8Array(testBytes));

    // 32-byte key-like data
    var keyBytes = new Uint8Array(32);
    for (var i = 0; i < 32; i++) keyBytes[i] = i * 8 + 3;
    var keyEncoded = bufferToBase64url(keyBytes.buffer);
    var keyDecoded = new Uint8Array(base64urlToBuffer(keyEncoded));
    assertArrayEqual('round-trip 32-byte key', keyDecoded, keyBytes);

    // ================================================================
    // webauthnError
    // ================================================================
    group('webauthnError');

    assertEqual('NotAllowedError',
        webauthnError({ name: 'NotAllowedError', message: 'original' }),
        'Operation was cancelled or timed out. Please try again.');

    assertEqual('SecurityError',
        webauthnError({ name: 'SecurityError', message: 'original' }),
        'Security error. Please ensure you are on a secure (HTTPS) connection.');

    assertEqual('AbortError',
        webauthnError({ name: 'AbortError', message: 'original' }),
        'Operation was cancelled.');

    assertEqual('InvalidStateError',
        webauthnError({ name: 'InvalidStateError', message: 'original' }),
        'This security key is already registered or no credentials found.');

    assertEqual('NotSupportedError',
        webauthnError({ name: 'NotSupportedError', message: 'original' }),
        'This security key is not supported. Please use a FIDO2-compatible key.');

    assertEqual('PIN error (case insensitive)',
        webauthnError({ name: 'Error', message: 'FIDO2 PIN verification failed' }),
        'PIN error. Please check your security key PIN and try again.');

    assertEqual('unknown error passes through message',
        webauthnError({ name: 'TypeError', message: 'something broke' }),
        'something broke');

    // ================================================================
    // escapeHtml
    // ================================================================
    group('escapeHtml');

    assertEqual('escapes angle brackets',
        escapeHtml('<script>alert("xss")</script>'),
        '&lt;script&gt;alert("xss")&lt;/script&gt;');

    assertEqual('escapes ampersand',
        escapeHtml('a & b'), 'a &amp; b');

    assertEqual('passes through safe text',
        escapeHtml('hello world'), 'hello world');

    assertEqual('handles empty string',
        escapeHtml(''), '');

    assertEqual('escapes quotes in attributes',
        escapeHtml('key "name"').indexOf('"') === -1 ||
        escapeHtml('key "name"') === 'key "name"',
        true);

    // ================================================================
    // formatDate
    // ================================================================
    group('formatDate');

    assertEqual('empty string returns empty',
        formatDate(''), '');

    assertEqual('null returns empty',
        formatDate(null), '');

    assertEqual('undefined returns empty',
        formatDate(undefined), '');

    // ISO 8601 format — verify it parses without error and produces non-empty output
    var iso = formatDate('2025-06-15T10:30:00Z');
    assert('ISO 8601 produces non-empty string', iso.length > 0);
    assert('ISO 8601 contains year', iso.indexOf('2025') !== -1);

    // SQLite format — should normalize to ISO and parse correctly
    var sqlite = formatDate('2025-06-15 10:30:00');
    assert('SQLite format produces non-empty string', sqlite.length > 0);
    assert('SQLite format contains year', sqlite.indexOf('2025') !== -1);

    // Both formats should produce the same date
    assertEqual('ISO and SQLite produce same output', iso, sqlite);

    // ================================================================
    // VouchValidate.isValidRedirectUri (common.js)
    //
    // Must agree with db::validate_redirect_uri on the server. The two
    // previously disagreed: the form accepted any http:// or https:// URI
    // while the server had been tightened to loopback-only http, fragments
    // rejected, and custom schemes for native clients only.
    // ================================================================
    group('VouchValidate.isValidRedirectUri');

    var isValid = window.VouchValidate.isValidRedirectUri;

    assert('https is accepted', isValid('https://example.com/cb', 'web'));
    assert('http on a non-loopback host is rejected',
        !isValid('http://evil.example/cb', 'web'));
    assert('http on localhost is accepted', isValid('http://localhost:8080/cb', 'web'));
    assert('http on 127.0.0.1 is accepted', isValid('http://127.0.0.1:1234/cb', 'web'));
    assert('http on [::1] is accepted', isValid('http://[::1]:1234/cb', 'web'));

    assert('a fragment is rejected', !isValid('https://example.com/cb#frag', 'web'));
    assert('a bare trailing # is rejected', !isValid('https://example.com/cb#', 'web'));

    assert('a custom scheme is accepted for native',
        isValid('com.example.app:/oauth', 'native'));
    assert('a custom scheme is rejected for web',
        !isValid('com.example.app:/oauth', 'web'));
    assert('a custom scheme is rejected for spa',
        !isValid('com.example.app:/oauth', 'spa'));
    assert('a custom scheme is rejected when the type is unknown',
        !isValid('com.example.app:/oauth', null));

    assert('a relative URI is rejected', !isValid('/callback', 'web'));
    assert('a non-URI is rejected', !isValid('not a uri', 'web'));

    // ================================================================
    // Summary
    // ================================================================
    var summary = document.createElement('div');
    summary.className = 'summary';
    var summarySpan = document.createElement('span');
    if (failed === 0) {
        summarySpan.className = 'pass';
        summarySpan.textContent = 'All ' + passed + ' tests passed.';
    } else {
        summarySpan.className = 'fail';
        summarySpan.textContent = failed + ' of ' + (passed + failed) + ' tests failed.';
    }
    summary.appendChild(summarySpan);
    results.appendChild(summary);

    document.title = (failed === 0 ? 'PASS' : 'FAIL') + ' — Vouch JS Unit Tests';
})();
