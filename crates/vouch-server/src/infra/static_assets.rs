// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Static asset serving via rust-embed.
//!
//! Embeds the `static/` directory into the binary and serves assets with
//! appropriate cache headers and ETag-based validation.

use axum::{
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
struct Assets;

pub async fn favicon_handler() -> Response {
    static_handler(Path("images/favicon.ico".to_string())).await
}

pub async fn static_handler(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            // Use rust-embed's SHA256 hash as ETag for cache validation
            let etag = format!("\"{}\"", hex::encode(content.metadata.sha256_hash()));
            // Images and fonts rarely change -- cache for 24h.
            // CSS/JS may change on each deploy -- always revalidate via ETag.
            let mime_type = mime.type_().as_str();
            let cache_control = match mime_type {
                "image" | "font" => "public, max-age=86400",
                _ => "no-cache",
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (header::CACHE_CONTROL, cache_control.to_string()),
                    (header::ETAG, etag),
                ],
                content.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
