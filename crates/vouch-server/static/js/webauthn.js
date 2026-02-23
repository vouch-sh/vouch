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
        message = 'Operation was cancelled or timed out. Please try again.';
    } else if (err.name === 'SecurityError') {
        message = 'Security error. Please ensure you are on a secure (HTTPS) connection.';
    } else if (err.name === 'AbortError') {
        message = 'Operation was cancelled.';
    } else if (err.name === 'InvalidStateError') {
        message = 'This security key is already registered or no credentials found.';
    } else if (err.name === 'NotSupportedError') {
        message = 'This security key is not supported. Please use a FIDO2-compatible key.';
    } else if (message && message.toLowerCase().indexOf('pin') !== -1) {
        message = 'PIN error. Please check your security key PIN and try again.';
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
