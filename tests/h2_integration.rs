//! Integration tests for HTTP/2 packing

use bytes::Bytes;
use h2::client;
use h2::server;
use http::{Method, Request, Response, StatusCode};
use http_pack::{decode_request, decode_response, encode_request, encode_response, PackedRequest, HttpVersion};
use tokio::net::{TcpListener, TcpStream};

/// Test that we can pack an HTTP/2 request with body
#[tokio::test]
async fn h2_request_pack_roundtrip() {
    // Spawn H2 server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = server::handshake(socket).await.unwrap();

        while let Some(result) = connection.accept().await {
            let (request, mut respond) = result.unwrap();

            // Collect body
            let mut body_data = Vec::new();
            let mut body = request.into_body();
            while let Some(chunk) = body.data().await {
                body_data.extend_from_slice(&chunk.unwrap());
            }

            // Pack the request
            let req = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .version(http::Version::HTTP_2)
                .header("content-type", "application/json")
                .body(Bytes::from(body_data.clone()))
                .unwrap();

            let encoded = encode_request(&req).unwrap();
            let decoded = decode_request(&encoded).unwrap();

            // Verify
            assert_eq!(decoded.method, b"POST");
            assert_eq!(decoded.path, b"/test");
            assert_eq!(decoded.body, body_data);
            assert_eq!(decoded.version, HttpVersion::H2);

            // Send response
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from("ok"), true).unwrap();
        }
    });

    // H2 client
    let socket = TcpStream::connect(addr).await.unwrap();
    let (h2, connection) = client::handshake(socket).await.unwrap();

    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let mut h2 = h2.ready().await.unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost/test")
        .body(())
        .unwrap();

    let (response, mut send_body) = h2.send_request(request, false).unwrap();
    send_body.send_data(Bytes::from(r#"{"hello":"world"}"#), true).unwrap();

    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
}

/// Test that we can pack an HTTP/2 response with body
#[tokio::test]
async fn h2_response_pack_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = server::handshake(socket).await.unwrap();

        while let Some(result) = connection.accept().await {
            let (_, mut respond) = result.unwrap();

            let response = Response::builder()
                .status(StatusCode::CREATED)
                .version(http::Version::HTTP_2)
                .header("x-custom", "value")
                .body(())
                .unwrap();

            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from("response body"), true).unwrap();
        }
    });

    // H2 client
    let socket = TcpStream::connect(addr).await.unwrap();
    let (h2, connection) = client::handshake(socket).await.unwrap();

    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let mut h2 = h2.ready().await.unwrap();

    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/test")
        .body(())
        .unwrap();

    let (response, _) = h2.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    // Collect response body
    let mut body_data = Vec::new();
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        body_data.extend_from_slice(&chunk.unwrap());
    }

    // Pack the response
    let resp = Response::builder()
        .status(StatusCode::CREATED)
        .version(http::Version::HTTP_2)
        .header("x-custom", "value")
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_response(&resp).unwrap();
    let decoded = decode_response(&encoded).unwrap();

    assert_eq!(decoded.status, 201);
    assert_eq!(decoded.body, b"response body");
    assert_eq!(decoded.version, HttpVersion::H2);

    let custom_header = decoded.headers.iter().find(|h| h.name == b"x-custom");
    assert!(custom_header.is_some());
    assert_eq!(custom_header.unwrap().value, b"value");

    server_handle.abort();
}

/// Test packing preserves H2 pseudo-headers correctly
#[tokio::test]
async fn h2_preserves_authority() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com:8443/path?query=1")
        .version(http::Version::HTTP_2)
        .body(Bytes::new())
        .unwrap();

    let packed = PackedRequest::from_request(&req).unwrap();

    assert_eq!(packed.version, HttpVersion::H2);
    assert_eq!(packed.method, b"GET");
    assert_eq!(packed.scheme, Some(b"https".to_vec()));
    assert_eq!(packed.authority, Some(b"example.com:8443".to_vec()));
    assert_eq!(packed.path, b"/path?query=1");

    // Roundtrip
    let encoded = encode_request(&req).unwrap();
    let decoded = decode_request(&encoded).unwrap();

    assert_eq!(decoded.scheme, Some(b"https".to_vec()));
    assert_eq!(decoded.authority, Some(b"example.com:8443".to_vec()));
}
