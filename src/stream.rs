use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use std::collections::HashSet;

use crate::{
    HeaderField, HttpVersion, PackedRequest, PackedResponse, MAX_HEADERS, DecodeError, EncodeError,
};

const STREAM_MAGIC: [u8; 4] = *b"HPKS";
const STREAM_VERSION: u8 = 1;
const FRAME_HEADERS: u8 = 1;
const FRAME_BODY: u8 = 2;
const FRAME_END: u8 = 3;
const END_FLAGS_NONE: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequestHeaders {
    pub stream_id: u64,
    pub version: HttpVersion,
    pub method: Vec<u8>,
    pub scheme: Option<Vec<u8>>,
    pub authority: Option<Vec<u8>>,
    pub path: Vec<u8>,
    pub headers: Vec<HeaderField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamResponseHeaders {
    pub stream_id: u64,
    pub version: HttpVersion,
    pub status: u16,
    pub headers: Vec<HeaderField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamHeaders {
    Request(StreamRequestHeaders),
    Response(StreamResponseHeaders),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBody {
    pub stream_id: u64,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEnd {
    pub stream_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    Headers(StreamHeaders),
    Body(StreamBody),
    End(StreamEnd),
}

impl StreamFrame {
    pub fn stream_id(&self) -> u64 {
        match self {
            StreamFrame::Headers(headers) => match headers {
                StreamHeaders::Request(req) => req.stream_id,
                StreamHeaders::Response(resp) => resp.stream_id,
            },
            StreamFrame::Body(body) => body.stream_id,
            StreamFrame::End(end) => end.stream_id,
        }
    }
}

impl StreamHeaders {
    pub fn from_request<B>(stream_id: u64, req: &Request<B>) -> Result<Self, EncodeError> {
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

        Ok(StreamHeaders::Request(StreamRequestHeaders {
            stream_id,
            version,
            method,
            scheme,
            authority,
            path: path.as_bytes().to_vec(),
            headers,
        }))
    }

    pub fn from_response<B>(stream_id: u64, resp: &Response<B>) -> Result<Self, EncodeError> {
        let version = HttpVersion::from_http(resp.version())?;
        let status = resp.status().as_u16();
        let headers = collect_headers(resp.headers());

        Ok(StreamHeaders::Response(StreamResponseHeaders {
            stream_id,
            version,
            status,
            headers,
        }))
    }

    pub fn from_packed_request(stream_id: u64, req: PackedRequest) -> Self {
        StreamHeaders::Request(StreamRequestHeaders {
            stream_id,
            version: req.version,
            method: req.method,
            scheme: req.scheme,
            authority: req.authority,
            path: req.path,
            headers: req.headers,
        })
    }

    pub fn from_packed_response(stream_id: u64, resp: PackedResponse) -> Self {
        StreamHeaders::Response(StreamResponseHeaders {
            stream_id,
            version: resp.version,
            status: resp.status,
            headers: resp.headers,
        })
    }
}

pub fn encode_frame(frame: &StreamFrame) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&STREAM_MAGIC);
    buf.push(STREAM_VERSION);

    match frame {
        StreamFrame::Headers(headers) => {
            buf.push(FRAME_HEADERS);
            match headers {
                StreamHeaders::Request(req) => {
                    buf.extend_from_slice(&req.stream_id.to_be_bytes());
                    buf.push(StreamKind::Request.to_byte());
                    buf.push(req.version.to_byte());
                    encode_request_fields(req, &mut buf);
                }
                StreamHeaders::Response(resp) => {
                    buf.extend_from_slice(&resp.stream_id.to_be_bytes());
                    buf.push(StreamKind::Response.to_byte());
                    buf.push(resp.version.to_byte());
                    encode_response_fields(resp, &mut buf);
                }
            }
        }
        StreamFrame::Body(body) => {
            buf.push(FRAME_BODY);
            buf.extend_from_slice(&body.stream_id.to_be_bytes());
            crate::put_varint(&mut buf, body.data.len() as u64);
            buf.extend_from_slice(&body.data);
        }
        StreamFrame::End(end) => {
            buf.push(FRAME_END);
            buf.extend_from_slice(&end.stream_id.to_be_bytes());
            buf.push(END_FLAGS_NONE);
        }
    }

    buf
}

#[derive(Debug)]
pub enum StreamDecodeError {
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidFrameType(u8),
    TrailingBytes(usize),
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
    InvalidEndFlags(u8),
}

impl std::fmt::Display for StreamDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamDecodeError::InvalidMagic => write!(f, "invalid magic"),
            StreamDecodeError::UnsupportedVersion(version) => {
                write!(f, "unsupported format version: {}", version)
            }
            StreamDecodeError::InvalidFrameType(frame) => {
                write!(f, "invalid frame type: {}", frame)
            }
            StreamDecodeError::TrailingBytes(remaining) => {
                write!(f, "trailing bytes: {}", remaining)
            }
            StreamDecodeError::UnsupportedHttpVersion(version) => {
                write!(f, "unsupported http version: {}", version)
            }
            StreamDecodeError::InvalidKind(kind) => write!(f, "invalid message kind: {}", kind),
            StreamDecodeError::InvalidVarint => write!(f, "invalid varint"),
            StreamDecodeError::LengthOverflow => write!(f, "length overflow"),
            StreamDecodeError::TooManyHeaders(count) => write!(f, "too many headers: {}", count),
            StreamDecodeError::InvalidMethod => write!(f, "invalid method"),
            StreamDecodeError::InvalidPath => write!(f, "invalid path"),
            StreamDecodeError::InvalidHeaderName => write!(f, "invalid header name"),
            StreamDecodeError::InvalidHeaderValue => write!(f, "invalid header value"),
            StreamDecodeError::InvalidStatus => write!(f, "invalid status"),
            StreamDecodeError::InvalidEndFlags(flags) => write!(f, "invalid end flags: {}", flags),
        }
    }
}

impl std::error::Error for StreamDecodeError {}

pub fn decode_frame(bytes: &[u8]) -> Result<StreamFrame, StreamDecodeError> {
    match decode_frame_from_prefix(bytes)? {
        Some((frame, consumed)) => {
            if consumed != bytes.len() {
                return Err(StreamDecodeError::TrailingBytes(bytes.len() - consumed));
            }
            Ok(frame)
        }
        None => Err(StreamDecodeError::InvalidMagic),
    }
}

pub fn decode_frame_from_prefix(
    bytes: &[u8],
) -> Result<Option<(StreamFrame, usize)>, StreamDecodeError> {
    let mut offset = 0usize;

    if bytes.len() < STREAM_MAGIC.len() {
        return Ok(None);
    }
    if &bytes[..STREAM_MAGIC.len()] != STREAM_MAGIC {
        return Err(StreamDecodeError::InvalidMagic);
    }
    offset += STREAM_MAGIC.len();

    if bytes.len() < offset + 2 {
        return Ok(None);
    }
    let version = bytes[offset];
    offset += 1;
    if version != STREAM_VERSION {
        return Err(StreamDecodeError::UnsupportedVersion(version));
    }

    let frame_type = bytes[offset];
    offset += 1;

    if bytes.len() < offset + 8 {
        return Ok(None);
    }
    let stream_id = u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    match frame_type {
        FRAME_HEADERS => {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            let kind = StreamKind::from_byte(bytes[offset])?;
            offset += 1;
            let http_version = HttpVersion::from_byte(bytes[offset])
                .map_err(|err| match err {
                    DecodeError::UnsupportedHttpVersion(v) => {
                        StreamDecodeError::UnsupportedHttpVersion(v)
                    }
                    _ => StreamDecodeError::UnsupportedHttpVersion(0),
                })?;
            offset += 1;

            match kind {
                StreamKind::Request => {
                    let method = match read_bytes(bytes, &mut offset)? {
                        Some(value) if !value.is_empty() => value,
                        Some(_) => return Err(StreamDecodeError::InvalidMethod),
                        None => return Ok(None),
                    };

                    let scheme = match read_bytes(bytes, &mut offset)? {
                        Some(value) if value.is_empty() => None,
                        Some(value) => Some(value),
                        None => return Ok(None),
                    };

                    let authority = match read_bytes(bytes, &mut offset)? {
                        Some(value) if value.is_empty() => None,
                        Some(value) => Some(value),
                        None => return Ok(None),
                    };

                    let path = match read_bytes(bytes, &mut offset)? {
                        Some(value) if value.is_empty() => b"/".to_vec(),
                        Some(value) => value,
                        None => return Ok(None),
                    };

                    validate_method(&method)?;
                    validate_path(&path)?;

                    let headers = read_headers(bytes, &mut offset)?;
                    let headers = match headers {
                        Some(value) => value,
                        None => return Ok(None),
                    };

                    Ok(Some((
                        StreamFrame::Headers(StreamHeaders::Request(StreamRequestHeaders {
                            stream_id,
                            version: http_version,
                            method,
                            scheme,
                            authority,
                            path,
                            headers,
                        })),
                        offset,
                    )))
                }
                StreamKind::Response => {
                    if bytes.len() < offset + 2 {
                        return Ok(None);
                    }
                    let status = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                    offset += 2;
                    if StatusCode::from_u16(status).is_err() {
                        return Err(StreamDecodeError::InvalidStatus);
                    }

                    let headers = read_headers(bytes, &mut offset)?;
                    let headers = match headers {
                        Some(value) => value,
                        None => return Ok(None),
                    };

                    Ok(Some((
                        StreamFrame::Headers(StreamHeaders::Response(StreamResponseHeaders {
                            stream_id,
                            version: http_version,
                            status,
                            headers,
                        })),
                        offset,
                    )))
                }
            }
        }
        FRAME_BODY => {
            let body_len = match read_varint(bytes, &mut offset)? {
                Some(value) => value,
                None => return Ok(None),
            };
            let len = usize::try_from(body_len).map_err(|_| StreamDecodeError::LengthOverflow)?;
            if bytes.len() < offset + len {
                return Ok(None);
            }
            // Use Bytes::copy_from_slice for body data to enable efficient handling
            let data = Bytes::copy_from_slice(&bytes[offset..offset + len]);
            offset += len;

            Ok(Some((StreamFrame::Body(StreamBody { stream_id, data }), offset)))
        }
        FRAME_END => {
            if bytes.len() < offset + 1 {
                return Ok(None);
            }
            let flags = bytes[offset];
            offset += 1;
            if flags != END_FLAGS_NONE {
                return Err(StreamDecodeError::InvalidEndFlags(flags));
            }
            Ok(Some((StreamFrame::End(StreamEnd { stream_id }), offset)))
        }
        other => Err(StreamDecodeError::InvalidFrameType(other)),
    }
}

pub struct StreamDecoder {
    buf: BytesMut,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self { buf: BytesMut::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn try_decode(&mut self) -> Result<Option<StreamFrame>, StreamDecodeError> {
        match decode_frame_from_prefix(&self.buf)? {
            Some((frame, consumed)) => {
                self.buf.advance(consumed);
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.buf.len()
    }
}

#[derive(Debug)]
pub enum StreamRebuildError {
    MissingHeaders(u64),
    DuplicateHeaders(u64),
    InvalidFrame,
    InvalidMethod,
    InvalidPath,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidStatus,
}

impl std::fmt::Display for StreamRebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamRebuildError::MissingHeaders(id) => write!(f, "missing headers for stream {}", id),
            StreamRebuildError::DuplicateHeaders(id) => write!(f, "duplicate headers for stream {}", id),
            StreamRebuildError::InvalidFrame => write!(f, "invalid frame order"),
            StreamRebuildError::InvalidMethod => write!(f, "invalid method"),
            StreamRebuildError::InvalidPath => write!(f, "invalid path"),
            StreamRebuildError::InvalidHeaderName => write!(f, "invalid header name"),
            StreamRebuildError::InvalidHeaderValue => write!(f, "invalid header value"),
            StreamRebuildError::InvalidStatus => write!(f, "invalid status"),
        }
    }
}

impl std::error::Error for StreamRebuildError {}

pub struct Http1StreamRebuilder {
    streams: HashSet<u64>,
}

impl Http1StreamRebuilder {
    pub fn new() -> Self {
        Self { streams: HashSet::new() }
    }

    pub fn push_frame(&mut self, frame: StreamFrame) -> Result<Vec<Bytes>, StreamRebuildError> {
        match frame {
            StreamFrame::Headers(headers) => self.handle_headers(headers),
            StreamFrame::Body(body) => self.handle_body(body),
            StreamFrame::End(end) => self.handle_end(end),
        }
    }

    fn handle_headers(&mut self, headers: StreamHeaders) -> Result<Vec<Bytes>, StreamRebuildError> {
        let stream_id = match &headers {
            StreamHeaders::Request(req) => req.stream_id,
            StreamHeaders::Response(resp) => resp.stream_id,
        };
        if self.streams.contains(&stream_id) {
            return Err(StreamRebuildError::DuplicateHeaders(stream_id));
        }

        let mut out = Vec::new();
        let bytes = match headers {
            StreamHeaders::Request(req) => {
                self.streams.insert(stream_id);
                build_http1_request_headers(&req)?
            }
            StreamHeaders::Response(resp) => {
                self.streams.insert(stream_id);
                build_http1_response_headers(&resp)?
            }
        };

        out.push(Bytes::from(bytes));
        Ok(out)
    }

    fn handle_body(&mut self, body: StreamBody) -> Result<Vec<Bytes>, StreamRebuildError> {
        if !self.streams.contains(&body.stream_id) {
            return Err(StreamRebuildError::MissingHeaders(body.stream_id));
        }
        if body.data.is_empty() {
            return Ok(Vec::new());
        }
        let mut chunk = Vec::new();
        write_chunk_size(body.data.len(), &mut chunk);
        chunk.extend_from_slice(&body.data);
        chunk.extend_from_slice(b"\r\n");
        Ok(vec![Bytes::from(chunk)])
    }

    fn handle_end(&mut self, end: StreamEnd) -> Result<Vec<Bytes>, StreamRebuildError> {
        if !self.streams.remove(&end.stream_id) {
            return Err(StreamRebuildError::MissingHeaders(end.stream_id));
        }
        Ok(vec![Bytes::from_static(b"0\r\n\r\n")])
    }
}

fn build_http1_request_headers(req: &StreamRequestHeaders) -> Result<Vec<u8>, StreamRebuildError> {
    validate_method(&req.method).map_err(|_| StreamRebuildError::InvalidMethod)?;
    validate_path(&req.path).map_err(|_| StreamRebuildError::InvalidPath)?;

    let mut out = Vec::new();
    out.extend_from_slice(&req.method);
    out.extend_from_slice(b" ");
    out.extend_from_slice(&req.path);
    out.extend_from_slice(b" HTTP/1.1\r\n");

    let mut has_host = false;
    for header in &req.headers {
        if crate::eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
            continue;
        }
        if crate::eq_ignore_ascii_case(&header.name, b"content-length") {
            continue;
        }
        if crate::eq_ignore_ascii_case(&header.name, b"host") {
            has_host = true;
        }
        validate_header_field(header).map_err(map_header_error)?;
        out.extend_from_slice(&header.name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }

    if !has_host {
        if let Some(authority) = &req.authority {
            if crate::has_crlf(authority) {
                return Err(StreamRebuildError::InvalidHeaderValue);
            }
            out.extend_from_slice(b"host: ");
            out.extend_from_slice(authority);
            out.extend_from_slice(b"\r\n");
        }
    }

    out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
    Ok(out)
}

fn build_http1_response_headers(
    resp: &StreamResponseHeaders,
) -> Result<Vec<u8>, StreamRebuildError> {
    let status = StatusCode::from_u16(resp.status).map_err(|_| StreamRebuildError::InvalidStatus)?;
    let reason = status.canonical_reason().unwrap_or("");

    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.as_str().as_bytes());
    if !reason.is_empty() {
        out.extend_from_slice(b" ");
        out.extend_from_slice(reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    for header in &resp.headers {
        if crate::eq_ignore_ascii_case(&header.name, b"transfer-encoding") {
            continue;
        }
        if crate::eq_ignore_ascii_case(&header.name, b"content-length") {
            continue;
        }
        validate_header_field(header).map_err(map_header_error)?;
        out.extend_from_slice(&header.name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
    Ok(out)
}

fn map_header_error(err: DecodeError) -> StreamRebuildError {
    match err {
        DecodeError::InvalidHeaderName => StreamRebuildError::InvalidHeaderName,
        DecodeError::InvalidHeaderValue => StreamRebuildError::InvalidHeaderValue,
        _ => StreamRebuildError::InvalidFrame,
    }
}

fn write_chunk_size(len: usize, out: &mut Vec<u8>) {
    let mut buf = [0u8; 16];
    let mut idx = buf.len();
    let mut value = len;
    if value == 0 {
        out.extend_from_slice(b"0\r\n");
        return;
    }
    while value > 0 {
        let digit = (value & 0xF) as u8;
        let ch = if digit < 10 { b'0' + digit } else { b'A' + (digit - 10) };
        idx -= 1;
        buf[idx] = ch;
        value >>= 4;
    }
    out.extend_from_slice(&buf[idx..]);
    out.extend_from_slice(b"\r\n");
}

fn encode_request_fields(req: &StreamRequestHeaders, buf: &mut Vec<u8>) {
    crate::put_varint(buf, req.method.len() as u64);
    buf.extend_from_slice(&req.method);

    if let Some(scheme) = &req.scheme {
        crate::put_varint(buf, scheme.len() as u64);
        buf.extend_from_slice(scheme);
    } else {
        crate::put_varint(buf, 0);
    }

    if let Some(authority) = &req.authority {
        crate::put_varint(buf, authority.len() as u64);
        buf.extend_from_slice(authority);
    } else {
        crate::put_varint(buf, 0);
    }

    crate::put_varint(buf, req.path.len() as u64);
    buf.extend_from_slice(&req.path);

    crate::put_varint(buf, req.headers.len() as u64);
    for header in &req.headers {
        crate::put_varint(buf, header.name.len() as u64);
        buf.extend_from_slice(&header.name);
        crate::put_varint(buf, header.value.len() as u64);
        buf.extend_from_slice(&header.value);
    }
}

fn encode_response_fields(resp: &StreamResponseHeaders, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&resp.status.to_be_bytes());

    crate::put_varint(buf, resp.headers.len() as u64);
    for header in &resp.headers {
        crate::put_varint(buf, header.name.len() as u64);
        buf.extend_from_slice(&header.name);
        crate::put_varint(buf, header.value.len() as u64);
        buf.extend_from_slice(&header.value);
    }
}

fn read_headers(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<Option<Vec<HeaderField>>, StreamDecodeError> {
    let header_count = match read_varint(bytes, offset)? {
        Some(value) => value,
        None => return Ok(None),
    };
    if header_count > MAX_HEADERS {
        return Err(StreamDecodeError::TooManyHeaders(header_count));
    }

    let mut headers = Vec::with_capacity(header_count as usize);
    for _ in 0..header_count {
        let name = match read_bytes(bytes, offset)? {
            Some(value) => value,
            None => return Ok(None),
        };
        let value = match read_bytes(bytes, offset)? {
            Some(value) => value,
            None => return Ok(None),
        };
        validate_header_name(&name)?;
        validate_header_value(&value)?;
        headers.push(HeaderField { name, value });
    }

    Ok(Some(headers))
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<Option<u64>, StreamDecodeError> {
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

    Err(StreamDecodeError::InvalidVarint)
}

fn read_bytes(bytes: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, StreamDecodeError> {
    let len = match read_varint(bytes, offset)? {
        Some(value) => value,
        None => return Ok(None),
    };
    read_raw(bytes, offset, len)
}

fn read_raw(
    bytes: &[u8],
    offset: &mut usize,
    len: u64,
) -> Result<Option<Vec<u8>>, StreamDecodeError> {
    let len = usize::try_from(len).map_err(|_| StreamDecodeError::LengthOverflow)?;
    if bytes.len() < *offset + len {
        return Ok(None);
    }
    let data = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(Some(data))
}

fn validate_method(method: &[u8]) -> Result<(), StreamDecodeError> {
    Method::from_bytes(method).map_err(|_| StreamDecodeError::InvalidMethod)?;
    Ok(())
}

fn validate_path(path: &[u8]) -> Result<(), StreamDecodeError> {
    if path.is_empty() || crate::has_crlf(path) {
        return Err(StreamDecodeError::InvalidPath);
    }
    Ok(())
}

fn validate_header_name(name: &[u8]) -> Result<(), StreamDecodeError> {
    HeaderName::from_bytes(name).map_err(|_| StreamDecodeError::InvalidHeaderName)?;
    Ok(())
}

fn validate_header_value(value: &[u8]) -> Result<(), StreamDecodeError> {
    HeaderValue::from_bytes(value).map_err(|_| StreamDecodeError::InvalidHeaderValue)?;
    Ok(())
}

fn validate_header_field(field: &HeaderField) -> Result<(), DecodeError> {
    crate::validate_header_name(&field.name)?;
    crate::validate_header_value(&field.value)?;
    Ok(())
}

fn collect_headers(headers: &http::HeaderMap) -> Vec<HeaderField> {
    headers
        .iter()
        .map(|(name, value)| HeaderField {
            name: name.as_str().as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

impl StreamKind {
    fn to_byte(self) -> u8 {
        match self {
            StreamKind::Request => 1,
            StreamKind::Response => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, StreamDecodeError> {
        match byte {
            1 => Ok(StreamKind::Request),
            2 => Ok(StreamKind::Response),
            other => Err(StreamDecodeError::InvalidKind(other)),
        }
    }
}

#[cfg(feature = "body")]
pub mod body {
    use super::{StreamFrame, StreamHeaders, StreamBody, StreamEnd, StreamEncodeError};
    use bytes::Buf;
    use http::{Request, Response};
    use http_body::Body;
    use http_body_util::BodyExt;

    pub async fn encode_request<B, F, E>(
        req: Request<B>,
        stream_id: u64,
        mut emit: F,
    ) -> Result<(), StreamEncodeError<E>>
    where
        B: Body + Unpin,
        B::Data: Buf,
        B::Error: std::error::Error + Send + Sync + 'static,
        F: FnMut(StreamFrame) -> Result<(), E>,
    {
        let (parts, mut body) = req.into_parts();
        let request = Request::from_parts(parts, ());
        let headers = StreamHeaders::from_request(stream_id, &request)
            .map_err(StreamEncodeError::Encode)?;
        emit(StreamFrame::Headers(headers)).map_err(StreamEncodeError::Emit)?;

        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|err| StreamEncodeError::Body(Box::new(err)))?
        {
            if let Ok(mut data) = frame.into_data() {
                if data.remaining() == 0 {
                    continue;
                }
                let bytes = data.copy_to_bytes(data.remaining());
                emit(StreamFrame::Body(StreamBody {
                    stream_id,
                    data: bytes,
                }))
                .map_err(StreamEncodeError::Emit)?;
            }
        }

        emit(StreamFrame::End(StreamEnd { stream_id })).map_err(StreamEncodeError::Emit)?;
        Ok(())
    }

    pub async fn encode_response<B, F, E>(
        resp: Response<B>,
        stream_id: u64,
        mut emit: F,
    ) -> Result<(), StreamEncodeError<E>>
    where
        B: Body + Unpin,
        B::Data: Buf,
        B::Error: std::error::Error + Send + Sync + 'static,
        F: FnMut(StreamFrame) -> Result<(), E>,
    {
        let (parts, mut body) = resp.into_parts();
        let response = Response::from_parts(parts, ());
        let headers = StreamHeaders::from_response(stream_id, &response)
            .map_err(StreamEncodeError::Encode)?;
        emit(StreamFrame::Headers(headers)).map_err(StreamEncodeError::Emit)?;

        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|err| StreamEncodeError::Body(Box::new(err)))?
        {
            if let Ok(mut data) = frame.into_data() {
                if data.remaining() == 0 {
                    continue;
                }
                let bytes = data.copy_to_bytes(data.remaining());
                emit(StreamFrame::Body(StreamBody {
                    stream_id,
                    data: bytes,
                }))
                .map_err(StreamEncodeError::Emit)?;
            }
        }

        emit(StreamFrame::End(StreamEnd { stream_id })).map_err(StreamEncodeError::Emit)?;
        Ok(())
    }
}

#[cfg(feature = "h3")]
pub mod h3 {
    use super::{StreamFrame, StreamHeaders, StreamBody, StreamEnd, StreamEncodeError};
    use bytes::Buf;
    use h3::quic::RecvStream;

    pub async fn encode_server_request<S, B, F, E>(
        req: http::Request<()>,
        stream_id: u64,
        stream: &mut h3::server::RequestStream<S, B>,
        mut emit: F,
    ) -> Result<(), StreamEncodeError<E>>
    where
        S: RecvStream,
        B: Buf,
        F: FnMut(StreamFrame) -> Result<(), E>,
    {
        let headers = StreamHeaders::from_request(stream_id, &req)
            .map_err(StreamEncodeError::Encode)?;
        emit(StreamFrame::Headers(headers)).map_err(StreamEncodeError::Emit)?;

        loop {
            match stream.recv_data().await.map_err(StreamEncodeError::H3Stream)? {
                Some(mut chunk) => {
                    let remaining = chunk.remaining();
                    if remaining == 0 {
                        continue;
                    }
                    let bytes = chunk.copy_to_bytes(remaining);
                    emit(StreamFrame::Body(StreamBody {
                        stream_id,
                        data: bytes,
                    }))
                    .map_err(StreamEncodeError::Emit)?;
                }
                None => break,
            }
        }

        emit(StreamFrame::End(StreamEnd { stream_id })).map_err(StreamEncodeError::Emit)?;
        Ok(())
    }

    pub async fn encode_client_response<S, B, F, E>(
        resp: http::Response<()>,
        stream_id: u64,
        stream: &mut h3::client::RequestStream<S, B>,
        mut emit: F,
    ) -> Result<(), StreamEncodeError<E>>
    where
        S: RecvStream,
        B: Buf,
        F: FnMut(StreamFrame) -> Result<(), E>,
    {
        let headers = StreamHeaders::from_response(stream_id, &resp)
            .map_err(StreamEncodeError::Encode)?;
        emit(StreamFrame::Headers(headers)).map_err(StreamEncodeError::Emit)?;

        loop {
            match stream.recv_data().await.map_err(StreamEncodeError::H3Stream)? {
                Some(mut chunk) => {
                    let remaining = chunk.remaining();
                    if remaining == 0 {
                        continue;
                    }
                    let bytes = chunk.copy_to_bytes(remaining);
                    emit(StreamFrame::Body(StreamBody {
                        stream_id,
                        data: bytes,
                    }))
                    .map_err(StreamEncodeError::Emit)?;
                }
                None => break,
            }
        }

        emit(StreamFrame::End(StreamEnd { stream_id })).map_err(StreamEncodeError::Emit)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum StreamEncodeError<E> {
    Encode(EncodeError),
    Body(Box<dyn std::error::Error + Send + Sync>),
    #[cfg(feature = "h3")]
    H3Stream(::h3::error::StreamError),
    Emit(E),
}

impl<E: std::fmt::Display> std::fmt::Display for StreamEncodeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamEncodeError::Encode(err) => write!(f, "encode error: {}", err),
            StreamEncodeError::Body(err) => write!(f, "body error: {}", err),
            #[cfg(feature = "h3")]
            StreamEncodeError::H3Stream(err) => write!(f, "h3 stream error: {}", err),
            StreamEncodeError::Emit(err) => write!(f, "emit error: {}", err),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for StreamEncodeError<E> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_request_headers() {
        let headers = StreamHeaders::Request(StreamRequestHeaders {
            stream_id: 7,
            version: HttpVersion::Http11,
            method: b"GET".to_vec(),
            scheme: None,
            authority: Some(b"example.com".to_vec()),
            path: b"/".to_vec(),
            headers: vec![HeaderField {
                name: b"x-test".to_vec(),
                value: b"ok".to_vec(),
            }],
        });
        let frame = StreamFrame::Headers(headers);
        let encoded = encode_frame(&frame);
        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn http1_rebuild_request() {
        let headers = StreamHeaders::Request(StreamRequestHeaders {
            stream_id: 1,
            version: HttpVersion::Http11,
            method: b"POST".to_vec(),
            scheme: None,
            authority: Some(b"example.com".to_vec()),
            path: b"/upload".to_vec(),
            headers: vec![HeaderField {
                name: b"x-test".to_vec(),
                value: b"ok".to_vec(),
            }],
        });

        let mut rebuilder = Http1StreamRebuilder::new();
        let head = rebuilder
            .push_frame(StreamFrame::Headers(headers))
            .unwrap();
        let head_str = String::from_utf8(head[0].to_vec()).unwrap();
        assert!(head_str.starts_with("POST /upload HTTP/1.1\r\n"));
        assert!(head_str.contains("transfer-encoding: chunked\r\n"));

        let body = rebuilder
            .push_frame(StreamFrame::Body(StreamBody {
                stream_id: 1,
                data: Bytes::from_static(b"hello"),
            }))
            .unwrap();
        assert_eq!(body[0].as_ref(), b"5\r\nhello\r\n");

        let end = rebuilder
            .push_frame(StreamFrame::End(StreamEnd { stream_id: 1 }))
            .unwrap();
        assert_eq!(end[0].as_ref(), b"0\r\n\r\n");
    }
}
