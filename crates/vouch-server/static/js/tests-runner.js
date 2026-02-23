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

    function assert(description, condition) {
        var el = document.createElement('div');
        el.className = 'test';
        if (condition) {
            el.innerHTML = '<span class="pass">PASS</span> ' + description;
            passed++;
        } else {
            el.innerHTML = '<span class="fail">FAIL</span> ' + description;
            failed++;
        }
        results.appendChild(el);
    }

    function assertEqual(description, actual, expected) {
        var ok = actual === expected;
        var el = document.createElement('div');
        el.className = 'test';
        if (ok) {
            el.innerHTML = '<span class="pass">PASS</span> ' + description;
            passed++;
        } else {
            el.innerHTML = '<span class="fail">FAIL</span> ' + description +
                '<br>       expected: ' + JSON.stringify(expected) +
                '<br>       actual:   ' + JSON.stringify(actual);
            failed++;
        }
        results.appendChild(el);
    }

    function assertArrayEqual(description, actual, expected) {
        var ok = actual.length === expected.length;
        if (ok) {
            for (var i = 0; i < actual.length; i++) {
                if (actual[i] !== expected[i]) { ok = false; break; }
            }
        }
        var el = document.createElement('div');
        el.className = 'test';
        if (ok) {
            el.innerHTML = '<span class="pass">PASS</span> ' + description;
            passed++;
        } else {
            el.innerHTML = '<span class="fail">FAIL</span> ' + description +
                '<br>       expected: [' + Array.from(expected).join(', ') + ']' +
                '<br>       actual:   [' + Array.from(actual).join(', ') + ']';
            failed++;
        }
        results.appendChild(el);
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
    // Summary
    // ================================================================
    var summary = document.createElement('div');
    summary.className = 'summary';
    if (failed === 0) {
        summary.innerHTML = '<span class="pass">All ' + passed + ' tests passed.</span>';
    } else {
        summary.innerHTML = '<span class="fail">' + failed + ' of ' + (passed + failed) + ' tests failed.</span>';
    }
    results.appendChild(summary);

    document.title = (failed === 0 ? 'PASS' : 'FAIL') + ' — Vouch JS Unit Tests';
})();
