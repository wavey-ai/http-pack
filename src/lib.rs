use bytes::{Buf, Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};

const MAGIC: [u8; 4] = *b"HPK1";
const FORMAT_VERSION: u8 = 1;
const KIND_REQUEST: u8 = 1;
const KIND_RESPONSE: u8 = 2;
const MAX_HEADERS: u64 = 8192;

#[cfg(feature = "h1")]
pub mod h1;

#[cfg(feature = "body")]
pub mod body;

#[cfg(feature = "h3")]
pub mod h3;

pub mod stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
    H2,
    H3,
}

impl HttpVersion {
    fn from_http(version: Version) -> Result<Self, EncodeError> {
        match version {
            Version::HTTP_11 => Ok(Self::Http11),
            Version::HTTP_2 => Ok(Self::H2),
            Version::HTTP_3 => Ok(Self::H3),
            other => Err(EncodeError::UnsupportedHttpVersion(other)),
        }
    }

    fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            1 => Ok(Self::Http11),
            2 => Ok(Self::H2),
            3 => Ok(Self::H3),
            other => Err(DecodeError::UnsupportedHttpVersion(other)),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::Http11 => 1,
            Self::H2 => 2,
            Self::H3 => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedRequest {
    pub version: HttpVersion,
    pub method: Vec<u8>,
    pub scheme: Option<Vec<u8>>,
    pub authority: Option<Vec<u8>>,
    pub path: Vec<u8>,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedResponse {
    pub version: HttpVersion,
    pub status: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackedMessage {
    Request(PackedRequest),
    Response(PackedResponse),
}

#[derive(Debug)]
pub enum EncodeError {
    UnsupportedHttpVersion(Version),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::UnsupportedHttpVersion(version) => {
                write!(f, "unsupported http version: {:?}", version)
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[derive(Debug)]
pub enum DecodeError {
    Incomplete,
    InvalidMagic,
    UnsupportedFormatVersion(u8),
    UnsupportedHttpVersion(u8),
    InvalidKind(u8),
    InvalidVarint,
    LengthOverflow,
    TooManyHeaders(u64),
    InvalidMethod,
    InvalidPath,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidStatus,
    TrailingBytes(usize),
    UnexpectedMessageKind,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Incomplete => write!(f, "incomplete payload"),
            DecodeError::InvalidMagic => write!(f, "invalid magic"),
            DecodeError::UnsupportedFormatVersion(version) => {
                write!(f, "unsupported format version: {}", version)
            }
            DecodeError::UnsupportedHttpVersion(version) => {
                write!(f, "unsupported http version: {}", version)
            }
            DecodeError::InvalidKind(kind) => write!(f, "invalid message kind: {}", kind),
            DecodeError::InvalidVarint => write!(f, "invalid varint"),
            DecodeError::LengthOverflow => write!(f, "length overflow"),
            DecodeError::TooManyHeaders(count) => write!(f, "too many headers: {}", count),
            DecodeError::InvalidMethod => write!(f, "invalid method"),
            DecodeError::InvalidPath => write!(f, "invalid path"),
            DecodeError::InvalidHeaderName => write!(f, "invalid header name"),
            DecodeError::InvalidHeaderValue => write!(f, "invalid header value"),
            DecodeError::InvalidStatus => write!(f, "invalid status"),
            DecodeError::TrailingBytes(remaining) => {
                write!(f, "trailing bytes: {}", remaining)
            }
            DecodeError::UnexpectedMessageKind => write!(f, "unexpected message kind"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl PackedRequest {
    pub fn from_request<B: AsRef<[u8]>>(req: &Request<B>) -> Result<Self, EncodeError> {
        let version = HttpVersion::from_http(req.version())?;
        let method = req.method().as_str().as_bytes().to_vec();

        let uri = req.uri();
        let scheme = uri.scheme_str().map(|s| s.as_bytes().to_vec());
        let authority = uri
            .authority()
            .map(|a| a.as_str().as_bytes().to_vec())
            .or_else(|| req.headers().get("host").map(|v| v.as_bytes().to_vec()));
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let path = if path.is_empty() { "/" } else { path };
        let headers = collect_headers(req.headers());
        let body = req.body().as_ref().to_vec();

        Ok(Self {
            version,
            method,
            scheme,
            authority,
            path: path.as_bytes().to_vec(),
            headers,
            body,
        })
    }

    pub fn to_http1_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        validate_method(&self.method)?;
        validate_path(&self.path)?;

        let mut out = Vec::new();
        out.extend_from_slice(&self.method);
        out.extend_from_slice(b" ");
        out.extend_from_slice(&self.path);
        out.extend_from_slice(b" HTTP/1.1\r\n");

        let mut has_host = false;
        let mut has_content_length = false;

        for header in &self.headers {
            if eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
                continue;
            }
            if eq_ignore_ascii_case(&header.name, b"host") {
                has_host = true;
            }
            if eq_ignore_ascii_case(&header.name, b"content-length") {
                has_content_length = true;
            }
            validate_header_field(header)?;
            out.extend_from_slice(&header.name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(&header.value);
            out.extend_from_slice(b"\r\n");
        }

        if !has_host {
            if let Some(authority) = &self.authority {
                if has_crlf(authority) {
                    return Err(DecodeError::InvalidHeaderValue);
                }
                out.extend_from_slice(b"host: ");
                out.extend_from_slice(authority);
                out.extend_from_slice(b"\r\n");
            }
        }

        if !has_content_length {
            let len = self.body.len().to_string();
            out.extend_from_slice(b"content-length: ");
            out.extend_from_slice(len.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn into_http1_request(self) -> Result<Request<Bytes>, DecodeError> {
        validate_method(&self.method)?;
        let method = Method::from_bytes(&self.method).map_err(|_| DecodeError::InvalidMethod)?;
        let path = if self.path.is_empty() {
            b"/".as_slice()
        } else {
            self.path.as_slice()
        };
        let path_str = std::str::from_utf8(path).map_err(|_| DecodeError::InvalidPath)?;
        let uri = path_str.parse::<Uri>().map_err(|_| DecodeError::InvalidPath)?;

        let mut builder = Request::builder().method(method).uri(uri).version(Version::HTTP_11);
        let mut has_host = false;
        let mut has_content_length = false;
        for header in &self.headers {
            if eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
                continue;
            }
            let name = HeaderName::from_bytes(&header.name)
                .map_err(|_| DecodeError::InvalidHeaderName)?;
            let value = HeaderValue::from_bytes(&header.value)
                .map_err(|_| DecodeError::InvalidHeaderValue)?;
            if eq_ignore_ascii_case(&header.name, b"host") {
                has_host = true;
            }
            if eq_ignore_ascii_case(&header.name, b"content-length") {
                has_content_length = true;
            }
            builder = builder.header(name, value);
        }

        if !has_host {
            if let Some(authority) = &self.authority {
                let value = HeaderValue::from_bytes(authority)
                    .map_err(|_| DecodeError::InvalidHeaderValue)?;
                builder = builder.header("host", value);
            }
        }

        if !has_content_length {
            let len = self.body.len().to_string();
            builder = builder.header("content-length", len);
        }

        builder
            .body(Bytes::from(self.body))
            .map_err(|_| DecodeError::InvalidPath)
    }
}

impl PackedResponse {
    pub fn from_response<B: AsRef<[u8]>>(resp: &Response<B>) -> Result<Self, EncodeError> {
        let version = HttpVersion::from_http(resp.version())?;
        let status = resp.status().as_u16();
        let headers = collect_headers(resp.headers());
        let body = resp.body().as_ref().to_vec();

        Ok(Self {
            version,
            status,
            headers,
            body,
        })
    }

    pub fn to_http1_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        let status = StatusCode::from_u16(self.status).map_err(|_| DecodeError::InvalidStatus)?;
        let reason = status.canonical_reason().unwrap_or("");

        let mut out = Vec::new();
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(status.as_str().as_bytes());
        if !reason.is_empty() {
            out.extend_from_slice(b" ");
            out.extend_from_slice(reason.as_bytes());
        }
        out.extend_from_slice(b"\r\n");

        let mut has_content_length = false;
        for header in &self.headers {
            if eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
                continue;
            }
            if eq_ignore_ascii_case(&header.name, b"content-length") {
                has_content_length = true;
            }
            validate_header_field(header)?;
            out.extend_from_slice(&header.name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(&header.value);
            out.extend_from_slice(b"\r\n");
        }

        if !has_content_length {
            let len = self.body.len().to_string();
            out.extend_from_slice(b"content-length: ");
            out.extend_from_slice(len.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn into_http1_response(self) -> Result<Response<Bytes>, DecodeError> {
        let status = StatusCode::from_u16(self.status).map_err(|_| DecodeError::InvalidStatus)?;
        let mut builder = Response::builder().status(status).version(Version::HTTP_11);
        let mut has_content_length = false;
        for header in &self.headers {
            if eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
                continue;
            }
            let name = HeaderName::from_bytes(&header.name)
                .map_err(|_| DecodeError::InvalidHeaderName)?;
            let value = HeaderValue::from_bytes(&header.value)
                .map_err(|_| DecodeError::InvalidHeaderValue)?;
            if eq_ignore_ascii_case(&header.name, b"content-length") {
                has_content_length = true;
            }
            builder = builder.header(name, value);
        }

        if !has_content_length {
            let len = self.body.len().to_string();
            builder = builder.header("content-length", len);
        }

        builder
            .body(Bytes::from(self.body))
            .map_err(|_| DecodeError::InvalidStatus)
    }
}

pub fn encode_request<B: AsRef<[u8]>>(req: &Request<B>) -> Result<Vec<u8>, EncodeError> {
    let packed = PackedRequest::from_request(req)?;
    Ok(encode_message(&PackedMessage::Request(packed)))
}

pub fn encode_response<B: AsRef<[u8]>>(resp: &Response<B>) -> Result<Vec<u8>, EncodeError> {
    let packed = PackedResponse::from_response(resp)?;
    Ok(encode_message(&PackedMessage::Response(packed)))
}

pub fn encode_message(message: &PackedMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    buf.push(FORMAT_VERSION);

    match message {
        PackedMessage::Request(req) => {
            buf.push(KIND_REQUEST);
            buf.push(req.version.to_byte());
            encode_request_fields(req, &mut buf);
        }
        PackedMessage::Response(resp) => {
            buf.push(KIND_RESPONSE);
            buf.push(resp.version.to_byte());
            encode_response_fields(resp, &mut buf);
        }
    }

    buf
}

pub fn decode(bytes: &[u8]) -> Result<PackedMessage, DecodeError> {
    match decode_from_prefix(bytes)? {
        Some((message, consumed)) => {
            if consumed != bytes.len() {
                return Err(DecodeError::TrailingBytes(bytes.len() - consumed));
            }
            Ok(message)
        }
        None => Err(DecodeError::Incomplete),
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<PackedRequest, DecodeError> {
    match decode(bytes)? {
        PackedMessage::Request(request) => Ok(request),
        PackedMessage::Response(_) => Err(DecodeError::UnexpectedMessageKind),
    }
}

pub fn decode_response(bytes: &[u8]) -> Result<PackedResponse, DecodeError> {
    match decode(bytes)? {
        PackedMessage::Response(response) => Ok(response),
        PackedMessage::Request(_) => Err(DecodeError::UnexpectedMessageKind),
    }
}

pub struct Decoder {
    buf: BytesMut,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn try_decode(&mut self) -> Result<Option<PackedMessage>, DecodeError> {
        match decode_from_prefix(&self.buf)? {
            Some((message, consumed)) => {
                self.buf.advance(consumed);
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.buf.len()
    }
}

pub mod packetizer {
    use super::{decode, encode_message, EncodeError, PackedMessage};
    use super::stream::{decode_frame, encode_frame, StreamDecodeError, StreamFrame};
    use message_packetizer::SignableMessage;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct HttpPackMessage {
        pub payload: Vec<u8>,
    }

    impl HttpPackMessage {
        pub fn from_message(message: &PackedMessage) -> Self {
            Self {
                payload: encode_message(message),
            }
        }

        pub fn decode(&self) -> Result<PackedMessage, super::DecodeError> {
            decode(&self.payload)
        }

        pub fn try_into_message(&self) -> Result<PackedMessage, super::DecodeError> {
            decode(&self.payload)
        }

        pub fn from_request<B: AsRef<[u8]>>(
            req: &http::Request<B>,
        ) -> Result<Self, EncodeError> {
            Ok(Self {
                payload: super::encode_request(req)?,
            })
        }

        pub fn from_response<B: AsRef<[u8]>>(
            resp: &http::Response<B>,
        ) -> Result<Self, EncodeError> {
            Ok(Self {
                payload: super::encode_response(resp)?,
            })
        }
    }

    impl SignableMessage for HttpPackMessage {}

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct HttpPackStreamMessage {
        pub payload: Vec<u8>,
    }

    impl HttpPackStreamMessage {
        pub fn from_frame(frame: &StreamFrame) -> Self {
            Self {
                payload: encode_frame(frame),
            }
        }

        pub fn decode(&self) -> Result<StreamFrame, StreamDecodeError> {
            decode_frame(&self.payload)
        }

        pub fn try_into_frame(&self) -> Result<StreamFrame, StreamDecodeError> {
            decode_frame(&self.payload)
        }
    }

    impl SignableMessage for HttpPackStreamMessage {}

    #[cfg(any(feature = "body", feature = "h3"))]
    pub mod stream {
        use super::HttpPackStreamMessage;
        use crate::stream::{self, StreamEncodeError};

        #[cfg(feature = "body")]
        pub async fn encode_request<B, F, E>(
            req: http::Request<B>,
            stream_id: u64,
            mut emit: F,
        ) -> Result<(), StreamEncodeError<E>>
        where
            B: http_body::Body + Unpin,
            B::Data: bytes::Buf,
            B::Error: std::error::Error + Send + Sync + 'static,
            F: FnMut(HttpPackStreamMessage) -> Result<(), E>,
        {
            stream::body::encode_request(req, stream_id, |frame| {
                emit(HttpPackStreamMessage::from_frame(&frame))
            })
            .await
        }

        #[cfg(feature = "body")]
        pub async fn encode_response<B, F, E>(
            resp: http::Response<B>,
            stream_id: u64,
            mut emit: F,
        ) -> Result<(), StreamEncodeError<E>>
        where
            B: http_body::Body + Unpin,
            B::Data: bytes::Buf,
            B::Error: std::error::Error + Send + Sync + 'static,
            F: FnMut(HttpPackStreamMessage) -> Result<(), E>,
        {
            stream::body::encode_response(resp, stream_id, |frame| {
                emit(HttpPackStreamMessage::from_frame(&frame))
            })
            .await
        }

        #[cfg(feature = "h3")]
        pub async fn encode_server_request<S, B, F, E>(
            req: http::Request<()>,
            stream_id: u64,
            stream: &mut h3::server::RequestStream<S, B>,
            mut emit: F,
        ) -> Result<(), StreamEncodeError<E>>
        where
            S: h3::quic::RecvStream,
            B: bytes::Buf,
            F: FnMut(HttpPackStreamMessage) -> Result<(), E>,
        {
            stream::h3::encode_server_request(req, stream_id, stream, |frame| {
                emit(HttpPackStreamMessage::from_frame(&frame))
            })
            .await
        }

        #[cfg(feature = "h3")]
        pub async fn encode_client_response<S, B, F, E>(
            resp: http::Response<()>,
            stream_id: u64,
            stream: &mut h3::client::RequestStream<S, B>,
            mut emit: F,
        ) -> Result<(), StreamEncodeError<E>>
        where
            S: h3::quic::RecvStream,
            B: bytes::Buf,
            F: FnMut(HttpPackStreamMessage) -> Result<(), E>,
        {
            stream::h3::encode_client_response(resp, stream_id, stream, |frame| {
                emit(HttpPackStreamMessage::from_frame(&frame))
            })
            .await
        }
    }
}

fn collect_headers(headers: &HeaderMap) -> Vec<HeaderField> {
    headers
        .iter()
        .map(|(name, value)| HeaderField {
            name: name.as_str().as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn encode_request_fields(req: &PackedRequest, buf: &mut Vec<u8>) {
    put_varint(buf, req.method.len() as u64);
    buf.extend_from_slice(&req.method);

    if let Some(scheme) = &req.scheme {
        put_varint(buf, scheme.len() as u64);
        buf.extend_from_slice(scheme);
    } else {
        put_varint(buf, 0);
    }

    if let Some(authority) = &req.authority {
        put_varint(buf, authority.len() as u64);
        buf.extend_from_slice(authority);
    } else {
        put_varint(buf, 0);
    }

    put_varint(buf, req.path.len() as u64);
    buf.extend_from_slice(&req.path);

    put_varint(buf, req.headers.len() as u64);
    for header in &req.headers {
        put_varint(buf, header.name.len() as u64);
        buf.extend_from_slice(&header.name);
        put_varint(buf, header.value.len() as u64);
        buf.extend_from_slice(&header.value);
    }

    put_varint(buf, req.body.len() as u64);
    buf.extend_from_slice(&req.body);
}

fn encode_response_fields(resp: &PackedResponse, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&resp.status.to_be_bytes());

    put_varint(buf, resp.headers.len() as u64);
    for header in &resp.headers {
        put_varint(buf, header.name.len() as u64);
        buf.extend_from_slice(&header.name);
        put_varint(buf, header.value.len() as u64);
        buf.extend_from_slice(&header.value);
    }

    put_varint(buf, resp.body.len() as u64);
    buf.extend_from_slice(&resp.body);
}

fn decode_from_prefix(bytes: &[u8]) -> Result<Option<(PackedMessage, usize)>, DecodeError> {
    let mut offset = 0usize;

    if bytes.len() < MAGIC.len() {
        return Ok(None);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    offset += MAGIC.len();

    if bytes.len() < offset + 3 {
        return Ok(None);
    }
    let format_version = bytes[offset];
    offset += 1;
    if format_version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedFormatVersion(format_version));
    }

    let kind = bytes[offset];
    offset += 1;
    let http_version = HttpVersion::from_byte(bytes[offset])?;
    offset += 1;

    match kind {
        KIND_REQUEST => {
            let method = read_bytes(bytes, &mut offset)?;
            let scheme = read_bytes(bytes, &mut offset)?;
            let authority = read_bytes(bytes, &mut offset)?;
            let path = read_bytes(bytes, &mut offset)?;

            let method = match method {
                Some(value) if !value.is_empty() => value,
                Some(_) => return Err(DecodeError::InvalidMethod),
                None => return Ok(None),
            };

            let scheme = match scheme {
                Some(value) if value.is_empty() => None,
                Some(value) => Some(value),
                None => return Ok(None),
            };

            let authority = match authority {
                Some(value) if value.is_empty() => None,
                Some(value) => Some(value),
                None => return Ok(None),
            };

            let path = match path {
                Some(value) if value.is_empty() => b"/".to_vec(),
                Some(value) => value,
                None => return Ok(None),
            };

            validate_method(&method)?;
            validate_path(&path)?;

            let header_count = match read_varint(bytes, &mut offset)? {
                Some(value) => value,
                None => return Ok(None),
            };
            if header_count > MAX_HEADERS {
                return Err(DecodeError::TooManyHeaders(header_count));
            }
            let mut headers = Vec::with_capacity(header_count as usize);
            for _ in 0..header_count {
                let name = match read_bytes(bytes, &mut offset)? {
                    Some(value) => value,
                    None => return Ok(None),
                };
                let value = match read_bytes(bytes, &mut offset)? {
                    Some(value) => value,
                    None => return Ok(None),
                };
                validate_header_name(&name)?;
                validate_header_value(&value)?;
                headers.push(HeaderField { name, value });
            }

            let body_len = match read_varint(bytes, &mut offset)? {
                Some(value) => value,
                None => return Ok(None),
            };
            let body = read_raw(bytes, &mut offset, body_len)?;
            let body = match body {
                Some(value) => value,
                None => return Ok(None),
            };

            Ok(Some((
                PackedMessage::Request(PackedRequest {
                    version: http_version,
                    method,
                    scheme,
                    authority,
                    path,
                    headers,
                    body,
                }),
                offset,
            )))
        }
        KIND_RESPONSE => {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            let status = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;
            if StatusCode::from_u16(status).is_err() {
                return Err(DecodeError::InvalidStatus);
            }

            let header_count = match read_varint(bytes, &mut offset)? {
                Some(value) => value,
                None => return Ok(None),
            };
            if header_count > MAX_HEADERS {
                return Err(DecodeError::TooManyHeaders(header_count));
            }
            let mut headers = Vec::with_capacity(header_count as usize);
            for _ in 0..header_count {
                let name = match read_bytes(bytes, &mut offset)? {
                    Some(value) => value,
                    None => return Ok(None),
                };
                let value = match read_bytes(bytes, &mut offset)? {
                    Some(value) => value,
                    None => return Ok(None),
                };
                validate_header_name(&name)?;
                validate_header_value(&value)?;
                headers.push(HeaderField { name, value });
            }

            let body_len = match read_varint(bytes, &mut offset)? {
                Some(value) => value,
                None => return Ok(None),
            };
            let body = read_raw(bytes, &mut offset, body_len)?;
            let body = match body {
                Some(value) => value,
                None => return Ok(None),
            };

            Ok(Some((
                PackedMessage::Response(PackedResponse {
                    version: http_version,
                    status,
                    headers,
                    body,
                }),
                offset,
            )))
        }
        other => Err(DecodeError::InvalidKind(other)),
    }
}

fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<Option<u64>, DecodeError> {
    let mut value: u64 = 0;
    let mut shift = 0;

    for _ in 0..10 {
        if *offset >= bytes.len() {
            return Ok(None);
        }
        let byte = bytes[*offset];
        *offset += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(Some(value));
        }
        shift += 7;
    }

    Err(DecodeError::InvalidVarint)
}

fn read_bytes(bytes: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, DecodeError> {
    let len = match read_varint(bytes, offset)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let data = read_raw(bytes, offset, len)?;
    Ok(data)
}

fn read_raw(
    bytes: &[u8],
    offset: &mut usize,
    len: u64,
) -> Result<Option<Vec<u8>>, DecodeError> {
    let len = usize::try_from(len).map_err(|_| DecodeError::LengthOverflow)?;
    if bytes.len() < *offset + len {
        return Ok(None);
    }
    let data = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(Some(data))
}

fn validate_method(method: &[u8]) -> Result<(), DecodeError> {
    Method::from_bytes(method).map_err(|_| DecodeError::InvalidMethod)?;
    Ok(())
}

fn validate_path(path: &[u8]) -> Result<(), DecodeError> {
    if path.is_empty() || has_crlf(path) {
        return Err(DecodeError::InvalidPath);
    }
    Ok(())
}

fn validate_header_name(name: &[u8]) -> Result<(), DecodeError> {
    HeaderName::from_bytes(name).map_err(|_| DecodeError::InvalidHeaderName)?;
    Ok(())
}

fn validate_header_value(value: &[u8]) -> Result<(), DecodeError> {
    HeaderValue::from_bytes(value).map_err(|_| DecodeError::InvalidHeaderValue)?;
    Ok(())
}

fn validate_header_field(field: &HeaderField) -> Result<(), DecodeError> {
    validate_header_name(&field.name)?;
    validate_header_value(&field.value)?;
    Ok(())
}

fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn has_crlf(data: &[u8]) -> bool {
    data.iter().any(|byte| *byte == b'\r' || *byte == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = Request::builder()
            .method("POST")
            .uri("https://example.com/ingest?x=1")
            .header("x-test", "value")
            .body(Bytes::from_static(b"hello"))
            .unwrap();

        let encoded = encode_request(&req).unwrap();
        let decoded = decode(&encoded).unwrap();

        let packed = match decoded {
            PackedMessage::Request(packed) => packed,
            _ => panic!("expected request"),
        };

        assert_eq!(packed.method, b"POST".to_vec());
        assert_eq!(packed.path, b"/ingest?x=1".to_vec());
        assert_eq!(packed.body, b"hello".to_vec());

        let http1 = packed.to_http1_bytes().unwrap();
        let http1_str = String::from_utf8(http1).unwrap();
        assert!(http1_str.starts_with("POST /ingest?x=1 HTTP/1.1\r\n"));
        assert!(http1_str.contains("host: example.com\r\n"));
        assert!(http1_str.contains("content-length: 5\r\n"));
    }

    #[test]
    fn decoder_streaming() {
        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .body(Bytes::from_static(b""))
            .unwrap();

        let encoded = encode_request(&req).unwrap();
        let mid = encoded.len() / 2;

        let mut decoder = Decoder::new();
        decoder.push(&encoded[..mid]);
        assert!(decoder.try_decode().unwrap().is_none());

        decoder.push(&encoded[mid..]);
        let message = decoder.try_decode().unwrap();
        assert!(matches!(message, Some(PackedMessage::Request(_))));
        assert_eq!(decoder.buffer_len(), 0);
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::builder()
            .status(204)
            .header("x-reply", "ok")
            .body(Bytes::from_static(b""))
            .unwrap();

        let encoded = encode_response(&resp).unwrap();
        let decoded = decode(&encoded).unwrap();

        let packed = match decoded {
            PackedMessage::Response(packed) => packed,
            _ => panic!("expected response"),
        };

        assert_eq!(packed.status, 204);
        let http1 = packed.to_http1_bytes().unwrap();
        let http1_str = String::from_utf8(http1).unwrap();
        assert!(http1_str.starts_with("HTTP/1.1 204 No Content\r\n"));
    }
}
