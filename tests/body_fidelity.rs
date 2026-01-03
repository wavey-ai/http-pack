//! Tests for byte-for-byte body serialization fidelity across all protocols

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Version};
use http_pack::{decode_request, decode_response, encode_request, encode_response, HttpVersion};

/// Generate test data with all possible byte values
fn all_bytes() -> Vec<u8> {
    (0u8..=255).collect()
}

/// Generate binary data with problematic patterns
fn problematic_bytes() -> Vec<u8> {
    let mut data = Vec::new();
    // Null bytes
    data.extend_from_slice(&[0x00, 0x00, 0x00]);
    // CRLF sequences (could break HTTP/1.1 framing)
    data.extend_from_slice(b"\r\n\r\n");
    // High bytes
    data.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
    // UTF-8 invalid sequences
    data.extend_from_slice(&[0x80, 0x81, 0xC0, 0xC1]);
    // Common delimiter bytes
    data.extend_from_slice(&[0x00, 0x0A, 0x0D, 0x20, 0x3A]);
    // Chunk size lookalikes (hex digits followed by CRLF)
    data.extend_from_slice(b"10\r\n");
    // Transfer-Encoding: chunked terminator
    data.extend_from_slice(b"0\r\n\r\n");
    data
}

/// Generate a large body (1MB)
fn large_body() -> Vec<u8> {
    let pattern: Vec<u8> = (0u8..=255).collect();
    pattern.iter().cycle().take(1024 * 1024).copied().collect()
}

// ============= HTTP/1.1 Tests =============

#[test]
fn h1_request_body_all_bytes() {
    let body_data = all_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::Http11);
    assert_eq!(decoded.body.len(), 256, "Body length mismatch");
    assert_eq!(decoded.body, body_data, "Body content mismatch - not byte-for-byte identical");
}

#[test]
fn h1_response_body_all_bytes() {
    let body_data = all_bytes();

    let resp = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_response(&resp).unwrap();
    let decoded = decode_response(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::Http11);
    assert_eq!(decoded.body, body_data, "Body content mismatch");
}

#[test]
fn h1_request_body_problematic_bytes() {
    let body_data = problematic_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body, body_data, "Problematic bytes corrupted");
}

#[test]
fn h1_request_body_large() {
    let body_data = large_body();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body.len(), body_data.len(), "Large body length mismatch");
    assert_eq!(decoded.body, body_data, "Large body content mismatch");
}

#[test]
fn h1_request_empty_body() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .version(Version::HTTP_11)
        .body(Bytes::new())
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert!(decoded.body.is_empty(), "Empty body should remain empty");
}

// ============= HTTP/2 Tests =============

#[test]
fn h2_request_body_all_bytes() {
    let body_data = all_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::H2);
    assert_eq!(decoded.body, body_data, "H2 body content mismatch");
}

#[test]
fn h2_response_body_all_bytes() {
    let body_data = all_bytes();

    let resp = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_response(&resp).unwrap();
    let decoded = decode_response(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::H2);
    assert_eq!(decoded.body, body_data, "H2 response body mismatch");
}

#[test]
fn h2_request_body_problematic_bytes() {
    let body_data = problematic_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body, body_data, "H2 problematic bytes corrupted");
}

#[test]
fn h2_request_body_large() {
    let body_data = large_body();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body.len(), body_data.len(), "H2 large body length mismatch");
    assert_eq!(decoded.body, body_data, "H2 large body content mismatch");
}

// ============= HTTP/3 Tests =============

#[test]
fn h3_request_body_all_bytes() {
    let body_data = all_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::H3);
    assert_eq!(decoded.body, body_data, "H3 body content mismatch");
}

#[test]
fn h3_response_body_all_bytes() {
    let body_data = all_bytes();

    let resp = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_response(&resp).unwrap();
    let decoded = decode_response(&encoded).unwrap();

    assert_eq!(decoded.version, HttpVersion::H3);
    assert_eq!(decoded.body, body_data, "H3 response body mismatch");
}

#[test]
fn h3_request_body_problematic_bytes() {
    let body_data = problematic_bytes();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body, body_data, "H3 problematic bytes corrupted");
}

#[test]
fn h3_request_body_large() {
    let body_data = large_body();

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.body.len(), body_data.len(), "H3 large body length mismatch");
    assert_eq!(decoded.body, body_data, "H3 large body content mismatch");
}

// ============= Cross-protocol consistency =============

#[test]
fn body_identical_across_protocols() {
    let body_data = all_bytes();

    // Encode with each protocol version
    let req_h1 = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let req_h2 = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let req_h3 = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/test")
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let decoded_h1 = decode_request(&encode_request(&req_h1).unwrap()).unwrap();
    let decoded_h2 = decode_request(&encode_request(&req_h2).unwrap()).unwrap();
    let decoded_h3 = decode_request(&encode_request(&req_h3).unwrap()).unwrap();

    // All should have identical body bytes
    assert_eq!(decoded_h1.body, decoded_h2.body, "H1 vs H2 body mismatch");
    assert_eq!(decoded_h2.body, decoded_h3.body, "H2 vs H3 body mismatch");
    assert_eq!(decoded_h1.body, body_data, "Body doesn't match original");
}

#[test]
fn response_body_identical_across_protocols() {
    let body_data = problematic_bytes();

    let resp_h1 = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_11)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let resp_h2 = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let resp_h3 = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_3)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let decoded_h1 = decode_response(&encode_response(&resp_h1).unwrap()).unwrap();
    let decoded_h2 = decode_response(&encode_response(&resp_h2).unwrap()).unwrap();
    let decoded_h3 = decode_response(&encode_response(&resp_h3).unwrap()).unwrap();

    assert_eq!(decoded_h1.body, decoded_h2.body, "Response H1 vs H2 body mismatch");
    assert_eq!(decoded_h2.body, decoded_h3.body, "Response H2 vs H3 body mismatch");
    assert_eq!(decoded_h1.body, body_data, "Response body doesn't match original");
}

// ============= Specific byte patterns =============

#[test]
fn body_with_only_null_bytes() {
    let body_data = vec![0u8; 1024];

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let decoded = decode_request(&encode_request(&req).unwrap()).unwrap();
    assert_eq!(decoded.body, body_data, "Null byte body corrupted");
}

#[test]
fn body_with_only_0xff_bytes() {
    let body_data = vec![0xFFu8; 1024];

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .version(Version::HTTP_2)
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let decoded = decode_request(&encode_request(&req).unwrap()).unwrap();
    assert_eq!(decoded.body, body_data, "0xFF byte body corrupted");
}

#[test]
fn body_single_byte_each_value() {
    // Test each byte value individually
    for byte_val in 0u8..=255 {
        let body_data = vec![byte_val];

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .version(Version::HTTP_2)
            .body(Bytes::from(body_data.clone()))
            .unwrap();

        let decoded = decode_request(&encode_request(&req).unwrap()).unwrap();
        assert_eq!(
            decoded.body, body_data,
            "Single byte 0x{:02X} corrupted", byte_val
        );
    }
}
