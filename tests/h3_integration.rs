//! Integration tests for HTTP/3 packing

use bytes::{Buf, Bytes};
use h3_quinn::quinn;
use http::{Method, Request, Response, StatusCode};
use http_pack::{decode_request, decode_response, encode_request, encode_response, HttpVersion};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::CertifiedKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert_der], key_der)
}

fn server_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> ServerConfig {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap(),
    ));

    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());

    server_config
}

fn client_config() -> ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap(),
    ))
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Test HTTP/3 request packing with real QUIC connection
#[tokio::test]
async fn h3_request_pack_roundtrip() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // Ignore if already installed

    let (certs, key) = generate_self_signed_cert();
    let server_config = server_config(certs, key);

    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server_endpoint.local_addr().unwrap();

    // Server task
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        while let Some(resolver) = h3_conn.accept().await.unwrap() {
            let (req, mut stream) = resolver.resolve_request().await.unwrap();

            // Collect body from H3 stream
            let mut body_data = Vec::new();
            while let Some(chunk) = stream.recv_data().await.unwrap() {
                body_data.extend_from_slice(chunk.chunk());
            }

            // Pack the request
            let packed_req = Request::builder()
                .method(req.method().clone())
                .uri(req.uri().clone())
                .version(http::Version::HTTP_3)
                .body(Bytes::from(body_data.clone()))
                .unwrap();

            let encoded = encode_request(&packed_req).unwrap();
            let decoded = decode_request(&encoded).unwrap();

            // Verify H3 packing works
            assert_eq!(decoded.method, b"POST");
            assert_eq!(decoded.path, b"/h3-test");
            assert_eq!(decoded.body, b"h3 request body");
            assert_eq!(decoded.version, HttpVersion::H3);

            // Send response
            let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(response).await.unwrap();
            stream.send_data(Bytes::from("h3 ok")).await.unwrap();
            stream.finish().await.unwrap();
        }
    });

    // Client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config());

    let connection = client_endpoint
        .connect(addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let quinn_conn = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();

    let drive_handle = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("https://localhost/h3-test")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(request).await.unwrap();
    stream.send_data(Bytes::from("h3 request body")).await.unwrap();
    stream.finish().await.unwrap();

    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server_handle.abort();
    drive_handle.abort();
}

/// Test HTTP/3 response packing
#[tokio::test]
async fn h3_response_pack_roundtrip() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // Ignore if already installed

    let (certs, key) = generate_self_signed_cert();
    let server_config = server_config(certs, key);

    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server_endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        while let Some(resolver) = h3_conn.accept().await.unwrap() {
            let (_, mut stream) = resolver.resolve_request().await.unwrap();

            let response = Response::builder()
                .status(StatusCode::ACCEPTED)
                .header("x-h3-test", "works")
                .body(())
                .unwrap();

            stream.send_response(response).await.unwrap();
            stream.send_data(Bytes::from("h3 response body")).await.unwrap();
            stream.finish().await.unwrap();
        }
    });

    // Client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config());

    let connection = client_endpoint
        .connect(addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let quinn_conn = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();

    let drive_handle = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri("https://localhost/test")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();

    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Collect response body
    let mut body_data = Vec::new();
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        body_data.extend_from_slice(chunk.chunk());
    }

    // Pack the response as H3
    let packed_resp = Response::builder()
        .status(StatusCode::ACCEPTED)
        .version(http::Version::HTTP_3)
        .header("x-h3-test", "works")
        .body(Bytes::from(body_data.clone()))
        .unwrap();

    let encoded = encode_response(&packed_resp).unwrap();
    let decoded = decode_response(&encoded).unwrap();

    assert_eq!(decoded.status, 202);
    assert_eq!(decoded.body, b"h3 response body");
    assert_eq!(decoded.version, HttpVersion::H3);

    let h3_header = decoded.headers.iter().find(|h| h.name == b"x-h3-test");
    assert!(h3_header.is_some());
    assert_eq!(h3_header.unwrap().value, b"works");

    server_handle.abort();
    drive_handle.abort();
}

/// Test that H3 version is correctly encoded in the binary format
#[tokio::test]
async fn h3_version_byte_encoding() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/path")
        .version(http::Version::HTTP_3)
        .body(Bytes::new())
        .unwrap();

    let encoded = encode_request(&req).unwrap();

    // HPK1 magic (4) + format version (1) + kind (1) + http version (1)
    // HTTP/3 version byte should be 3
    assert_eq!(encoded[6], 3, "H3 version byte should be 3");

    let decoded = decode_request(&encoded).unwrap();
    assert_eq!(decoded.version, HttpVersion::H3);
}
