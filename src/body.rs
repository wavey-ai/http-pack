use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;

use crate::{EncodeError, PackedRequest, PackedResponse};

#[derive(Debug)]
pub enum BodyCollectError {
    Body(Box<dyn std::error::Error + Send + Sync>),
    Encode(EncodeError),
}

impl std::fmt::Display for BodyCollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyCollectError::Body(err) => write!(f, "body error: {}", err),
            BodyCollectError::Encode(err) => write!(f, "encode error: {}", err),
        }
    }
}

impl std::error::Error for BodyCollectError {}

pub async fn pack_request<B>(req: Request<B>) -> Result<PackedRequest, BodyCollectError>
where
    B: Body,
    B::Data: Buf,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = req.into_parts();
    let bytes = collect_body(body).await?;
    let request = Request::from_parts(parts, bytes);
    PackedRequest::from_request(&request).map_err(BodyCollectError::Encode)
}

pub async fn pack_response<B>(resp: Response<B>) -> Result<PackedResponse, BodyCollectError>
where
    B: Body,
    B::Data: Buf,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = resp.into_parts();
    let bytes = collect_body(body).await?;
    let response = Response::from_parts(parts, bytes);
    PackedResponse::from_response(&response).map_err(BodyCollectError::Encode)
}

async fn collect_body<B>(body: B) -> Result<Bytes, BodyCollectError>
where
    B: Body,
    B::Data: Buf,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let collected = body
        .collect()
        .await
        .map_err(|err| BodyCollectError::Body(Box::new(err)))?;
    Ok(collected.to_bytes())
}
