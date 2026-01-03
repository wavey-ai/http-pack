use bytes::{Buf, Bytes};
use h3::quic::RecvStream;

use crate::{EncodeError, PackedRequest, PackedResponse};

#[derive(Debug)]
pub enum H3PackError {
    Stream(h3::error::StreamError),
    Encode(EncodeError),
}

impl std::fmt::Display for H3PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3PackError::Stream(err) => write!(f, "h3 stream error: {}", err),
            H3PackError::Encode(err) => write!(f, "encode error: {}", err),
        }
    }
}

impl std::error::Error for H3PackError {}

pub async fn pack_server_request<S, B>(
    req: http::Request<()>,
    stream: &mut h3::server::RequestStream<S, B>,
) -> Result<PackedRequest, H3PackError>
where
    S: RecvStream,
    B: Buf,
{
    let body = collect_server_body(stream).await?;
    let request = req.map(|_| Bytes::from(body));
    PackedRequest::from_request(&request).map_err(H3PackError::Encode)
}

pub async fn pack_client_response<S, B>(
    resp: http::Response<()>,
    stream: &mut h3::client::RequestStream<S, B>,
) -> Result<PackedResponse, H3PackError>
where
    S: RecvStream,
    B: Buf,
{
    let body = collect_client_body(stream).await?;
    let response = resp.map(|_| Bytes::from(body));
    PackedResponse::from_response(&response).map_err(H3PackError::Encode)
}

async fn collect_server_body<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
) -> Result<Vec<u8>, H3PackError>
where
    S: RecvStream,
    B: Buf,
{
    let mut out = Vec::new();
    loop {
        match stream.recv_data().await.map_err(H3PackError::Stream)? {
            Some(mut chunk) => {
                let remaining = chunk.remaining();
                if remaining == 0 {
                    continue;
                }
                let bytes = chunk.copy_to_bytes(remaining);
                out.extend_from_slice(bytes.as_ref());
            }
            None => break,
        }
    }
    Ok(out)
}

async fn collect_client_body<S, B>(
    stream: &mut h3::client::RequestStream<S, B>,
) -> Result<Vec<u8>, H3PackError>
where
    S: RecvStream,
    B: Buf,
{
    let mut out = Vec::new();
    loop {
        match stream.recv_data().await.map_err(H3PackError::Stream)? {
            Some(mut chunk) => {
                let remaining = chunk.remaining();
                if remaining == 0 {
                    continue;
                }
                let bytes = chunk.copy_to_bytes(remaining);
                out.extend_from_slice(bytes.as_ref());
            }
            None => break,
        }
    }
    Ok(out)
}
