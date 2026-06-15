// Shared utilities for WebAuthn pages: base64url encoding/decoding,
// error message mapping, HTML escaping, and date formatting.

function base64urlToBuffer(base64url) {
    var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    var pad = base64.length % 4;
    var padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function webauthnError(err) {
    var message = err.message;
    if (err.name === 'NotAllowedError') {
        message = t('webauthn-err-notallowed');
    } else if (err.name === 'SecurityError') {
        message = t('webauthn-err-security');
    } else if (err.name === 'AbortError') {
        message = t('webauthn-err-abort');
    } else if (err.name === 'InvalidStateError') {
        message = t('webauthn-err-invalidstate');
    } else if (err.name === 'NotSupportedError') {
        message = t('webauthn-err-notsupported');
    } else if (message && message.toLowerCase().indexOf('pin') !== -1) {
        message = t('webauthn-err-pin');
    }
    return message;
}

function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    // Handle both SQLite format ("YYYY-MM-DD HH:MM:SS") and ISO 8601 ("YYYY-MM-DDTHH:MM:SS.ffffffZ")
    var normalized = dateStr;
    if (dateStr.indexOf('T') === -1) {
        normalized = dateStr.replace(' ', 'T') + 'Z';
    }
    var date = new Date(normalized);
    return date.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}
