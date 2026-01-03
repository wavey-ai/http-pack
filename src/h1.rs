use bytes::{Buf, BytesMut};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use httparse::Status;
use std::collections::VecDeque;

use crate::{
    stream::{
        StreamBody, StreamEnd, StreamFrame, StreamHeaders, StreamRequestHeaders,
        StreamResponseHeaders,
    },
    HeaderField, HttpVersion, PackedMessage, PackedRequest, PackedResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1MessageKind {
    Request,
    Response,
}

#[derive(Debug)]
pub enum H1DecodeError {
    InvalidStartLine,
    InvalidVersion(u8),
    InvalidHeader,
    TooManyHeaders(usize),
    InvalidMethod,
    InvalidPath,
    InvalidStatus,
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidContentLength,
    InvalidChunkedEncoding,
}

impl std::fmt::Display for H1DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H1DecodeError::InvalidStartLine => write!(f, "invalid start line"),
            H1DecodeError::InvalidVersion(version) => {
                write!(f, "unsupported http version: {}", version)
            }
            H1DecodeError::InvalidHeader => write!(f, "invalid header"),
            H1DecodeError::TooManyHeaders(count) => write!(f, "too many headers: {}", count),
            H1DecodeError::InvalidMethod => write!(f, "invalid method"),
            H1DecodeError::InvalidPath => write!(f, "invalid path"),
            H1DecodeError::InvalidStatus => write!(f, "invalid status"),
            H1DecodeError::InvalidHeaderName => write!(f, "invalid header name"),
            H1DecodeError::InvalidHeaderValue => write!(f, "invalid header value"),
            H1DecodeError::InvalidContentLength => write!(f, "invalid content-length"),
            H1DecodeError::InvalidChunkedEncoding => write!(f, "invalid chunked encoding"),
        }
    }
}

impl std::error::Error for H1DecodeError {}

pub struct H1Decoder {
    kind: H1MessageKind,
    buf: BytesMut,
}

pub struct H1StreamDecoder {
    kind: H1MessageKind,
    stream_id: u64,
    buf: BytesMut,
    out: VecDeque<StreamFrame>,
    state: H1StreamState,
}

enum H1StreamState {
    ReadingHeaders,
    ReadingBody(BodyReader),
    Done,
}

struct BodyReader {
    kind: BodyKind,
}

enum BodyKind {
    None,
    Length { remaining: usize },
    Chunked { phase: ChunkPhase },
}

enum ChunkPhase {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
}

impl H1StreamDecoder {
    pub fn new(kind: H1MessageKind, stream_id: u64) -> Self {
        Self {
            kind,
            stream_id,
            buf: BytesMut::new(),
            out: VecDeque::new(),
            state: H1StreamState::ReadingHeaders,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn try_decode(&mut self) -> Result<Option<StreamFrame>, H1DecodeError> {
        if let Some(frame) = self.out.pop_front() {
            return Ok(Some(frame));
        }
        self.fill_out()?;
        Ok(self.out.pop_front())
    }

    pub fn try_decode_message(
        &mut self,
    ) -> Result<Option<crate::packetizer::HttpPackStreamMessage>, H1DecodeError> {
        match self.try_decode()? {
            Some(frame) => Ok(Some(crate::packetizer::HttpPackStreamMessage::from_frame(
                &frame,
            ))),
            None => Ok(None),
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn fill_out(&mut self) -> Result<(), H1DecodeError> {
        if !self.out.is_empty() {
            return Ok(());
        }

        match &mut self.state {
            H1StreamState::ReadingHeaders => {
                let (headers, body_kind) = match self.kind {
                    H1MessageKind::Request => {
                        let (method, path, header_len, headers) =
                            match parse_request_headers(&self.buf)? {
                                Some(value) => value,
                                None => return Ok(()),
                            };
                        self.buf.advance(header_len);
                        let authority =
                            find_header_value(&headers, b"host").map(|value| value.to_vec());
                        let path = if path.is_empty() {
                            b"/".as_slice()
                        } else {
                            path.as_slice()
                        };
                        let body_kind = body_kind_from_headers(&headers)?;
                        let header = StreamHeaders::Request(StreamRequestHeaders {
                            stream_id: self.stream_id,
                            version: HttpVersion::Http11,
                            method,
                            scheme: None,
                            authority,
                            path: path.to_vec(),
                            headers,
                        });
                        (header, body_kind)
                    }
                    H1MessageKind::Response => {
                        let (status, header_len, headers) =
                            match parse_response_headers(&self.buf)? {
                                Some(value) => value,
                                None => return Ok(()),
                            };
                        self.buf.advance(header_len);
                        let body_kind = body_kind_from_headers(&headers)?;
                        let header = StreamHeaders::Response(StreamResponseHeaders {
                            stream_id: self.stream_id,
                            version: HttpVersion::Http11,
                            status,
                            headers,
                        });
                        (header, body_kind)
                    }
                };

                self.out.push_back(StreamFrame::Headers(headers));
                match body_kind {
                    BodyKind::None => {
                        self.out.push_back(StreamFrame::End(StreamEnd {
                            stream_id: self.stream_id,
                        }));
                        self.state = H1StreamState::Done;
                    }
                    BodyKind::Length { remaining } if remaining == 0 => {
                        self.out.push_back(StreamFrame::End(StreamEnd {
                            stream_id: self.stream_id,
                        }));
                        self.state = H1StreamState::Done;
                    }
                    body_kind => {
                        self.state = H1StreamState::ReadingBody(BodyReader { kind: body_kind });
                    }
                }
            }
            H1StreamState::ReadingBody(reader) => {
                if let Some(frame) = read_body_frame(&mut self.buf, reader, self.stream_id)? {
                    self.out.push_back(frame);
                    if matches!(reader.kind, BodyKind::None) {
                        self.state = H1StreamState::Done;
                    }
                } else if matches!(reader.kind, BodyKind::None) {
                    self.state = H1StreamState::Done;
                }
            }
            H1StreamState::Done => {}
        }

        Ok(())
    }
}

impl H1Decoder {
    pub fn new(kind: H1MessageKind) -> Self {
        Self {
            kind,
            buf: BytesMut::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn try_decode(&mut self) -> Result<Option<PackedMessage>, H1DecodeError> {
        match decode_message_from_prefix(&self.buf, self.kind)? {
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

pub fn decode_request(bytes: &[u8]) -> Result<Option<(PackedRequest, usize)>, H1DecodeError> {
    match decode_message_from_prefix(bytes, H1MessageKind::Request)? {
        Some((PackedMessage::Request(req), consumed)) => Ok(Some((req, consumed))),
        Some(_) => Err(H1DecodeError::InvalidStartLine),
        None => Ok(None),
    }
}

pub fn decode_response(bytes: &[u8]) -> Result<Option<(PackedResponse, usize)>, H1DecodeError> {
    match decode_message_from_prefix(bytes, H1MessageKind::Response)? {
        Some((PackedMessage::Response(resp), consumed)) => Ok(Some((resp, consumed))),
        Some(_) => Err(H1DecodeError::InvalidStartLine),
        None => Ok(None),
    }
}

fn decode_message_from_prefix(
    bytes: &[u8],
    kind: H1MessageKind,
) -> Result<Option<(PackedMessage, usize)>, H1DecodeError> {
    match kind {
        H1MessageKind::Request => decode_request_from_prefix(bytes).map(|opt| {
            opt.map(|(req, consumed)| (PackedMessage::Request(req), consumed))
        }),
        H1MessageKind::Response => decode_response_from_prefix(bytes).map(|opt| {
            opt.map(|(resp, consumed)| (PackedMessage::Response(resp), consumed))
        }),
    }
}

fn decode_request_from_prefix(
    bytes: &[u8],
) -> Result<Option<(PackedRequest, usize)>, H1DecodeError> {
    let (method, path, header_len, headers) = match parse_request_headers(bytes)? {
        Some(value) => value,
        None => return Ok(None),
    };

    let authority = find_header_value(&headers, b"host").map(|value| value.to_vec());
    let path = if path.is_empty() {
        b"/".as_slice()
    } else {
        path.as_slice()
    };

    let (body, body_len) = match decode_body(bytes, header_len, &headers)? {
        Some(value) => value,
        None => return Ok(None),
    };

    Ok(Some((
        PackedRequest {
            version: HttpVersion::Http11,
            method: method.to_vec(),
            scheme: None,
            authority,
            path: path.to_vec(),
            headers,
            body,
        },
        header_len + body_len,
    )))
}

fn decode_response_from_prefix(
    bytes: &[u8],
) -> Result<Option<(PackedResponse, usize)>, H1DecodeError> {
    let (status, header_len, headers) = match parse_response_headers(bytes)? {
        Some(value) => value,
        None => return Ok(None),
    };

    let (body, body_len) = match decode_body(bytes, header_len, &headers)? {
        Some(value) => value,
        None => return Ok(None),
    };

    Ok(Some((
        PackedResponse {
            version: HttpVersion::Http11,
            status,
            headers,
            body,
        },
        header_len + body_len,
    )))
}

fn parse_request_headers(
    bytes: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>, usize, Vec<HeaderField>)>, H1DecodeError> {
    let mut header_cap = 32usize;
    loop {
        let mut headers = vec![httparse::EMPTY_HEADER; header_cap];
        let mut req = httparse::Request::new(&mut headers);
        let status = match req.parse(bytes) {
            Ok(status) => status,
            Err(err) => {
                if let httparse::Error::TooManyHeaders = err {
                    header_cap = grow_header_cap(header_cap)?;
                    continue;
                }
                return Err(map_parse_error(err));
            }
        };

        let header_len = match status {
            Status::Complete(len) => len,
            Status::Partial => return Ok(None),
        };

        let method = req.method.ok_or(H1DecodeError::InvalidStartLine)?;
        let path = req.path.ok_or(H1DecodeError::InvalidStartLine)?;
        let version = req.version.ok_or(H1DecodeError::InvalidStartLine)?;
        if version != 1 {
            return Err(H1DecodeError::InvalidVersion(version));
        }

        Method::from_bytes(method.as_bytes()).map_err(|_| H1DecodeError::InvalidMethod)?;
        if path.is_empty() || crate::has_crlf(path.as_bytes()) {
            return Err(H1DecodeError::InvalidPath);
        }

        let header_fields = collect_headers(&req.headers)?;

        return Ok(Some((
            method.as_bytes().to_vec(),
            path.as_bytes().to_vec(),
            header_len,
            header_fields,
        )));
    }
}

fn parse_response_headers(
    bytes: &[u8],
) -> Result<Option<(u16, usize, Vec<HeaderField>)>, H1DecodeError> {
    let mut header_cap = 32usize;
    loop {
        let mut headers = vec![httparse::EMPTY_HEADER; header_cap];
        let mut resp = httparse::Response::new(&mut headers);
        let status = match resp.parse(bytes) {
            Ok(status) => status,
            Err(err) => {
                if let httparse::Error::TooManyHeaders = err {
                    header_cap = grow_header_cap(header_cap)?;
                    continue;
                }
                return Err(map_parse_error(err));
            }
        };

        let header_len = match status {
            Status::Complete(len) => len,
            Status::Partial => return Ok(None),
        };

        let version = resp.version.ok_or(H1DecodeError::InvalidStartLine)?;
        if version != 1 {
            return Err(H1DecodeError::InvalidVersion(version));
        }

        let status_code = resp.code.ok_or(H1DecodeError::InvalidStatus)?;
        if StatusCode::from_u16(status_code).is_err() {
            return Err(H1DecodeError::InvalidStatus);
        }

        let header_fields = collect_headers(&resp.headers)?;

        return Ok(Some((status_code, header_len, header_fields)));
    }
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Result<Vec<HeaderField>, H1DecodeError> {
    if headers.len() > crate::MAX_HEADERS as usize {
        return Err(H1DecodeError::TooManyHeaders(headers.len()));
    }

    let mut out = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.as_bytes().to_vec();
        let value = header.value.to_vec();
        HeaderName::from_bytes(&name).map_err(|_| H1DecodeError::InvalidHeaderName)?;
        HeaderValue::from_bytes(&value).map_err(|_| H1DecodeError::InvalidHeaderValue)?;
        out.push(HeaderField { name, value });
    }

    Ok(out)
}

fn grow_header_cap(current: usize) -> Result<usize, H1DecodeError> {
    let next = current.saturating_mul(2);
    if next == current || next > crate::MAX_HEADERS as usize {
        return Err(H1DecodeError::TooManyHeaders(current));
    }
    Ok(next)
}

fn map_parse_error(err: httparse::Error) -> H1DecodeError {
    match err {
        httparse::Error::Version => H1DecodeError::InvalidVersion(0),
        httparse::Error::Status => H1DecodeError::InvalidStatus,
        httparse::Error::Token => H1DecodeError::InvalidMethod,
        httparse::Error::HeaderName => H1DecodeError::InvalidHeaderName,
        httparse::Error::HeaderValue => H1DecodeError::InvalidHeaderValue,
        _ => H1DecodeError::InvalidHeader,
    }
}

fn decode_body(
    bytes: &[u8],
    header_len: usize,
    headers: &[HeaderField],
) -> Result<Option<(Vec<u8>, usize)>, H1DecodeError> {
    let body_bytes = &bytes[header_len..];
    if has_chunked_encoding(headers) {
        return decode_chunked_body(body_bytes);
    }

    if let Some(len) = content_length(headers)? {
        if body_bytes.len() < len {
            return Ok(None);
        }
        return Ok(Some((body_bytes[..len].to_vec(), len)));
    }

    Ok(Some((Vec::new(), 0)))
}

fn body_kind_from_headers(headers: &[HeaderField]) -> Result<BodyKind, H1DecodeError> {
    if has_chunked_encoding(headers) {
        return Ok(BodyKind::Chunked {
            phase: ChunkPhase::SizeLine,
        });
    }

    if let Some(len) = content_length(headers)? {
        return Ok(BodyKind::Length { remaining: len });
    }

    Ok(BodyKind::None)
}

fn read_body_frame(
    buf: &mut BytesMut,
    reader: &mut BodyReader,
    stream_id: u64,
) -> Result<Option<StreamFrame>, H1DecodeError> {
    match &mut reader.kind {
        BodyKind::None => Ok(None),
        BodyKind::Length { remaining } => {
            if *remaining == 0 {
                reader.kind = BodyKind::None;
                return Ok(Some(StreamFrame::End(StreamEnd { stream_id })));
            }
            if buf.is_empty() {
                return Ok(None);
            }
            let take = (*remaining).min(buf.len());
            let chunk = buf.split_to(take).to_vec();
            *remaining -= take;
            Ok(Some(StreamFrame::Body(StreamBody {
                stream_id,
                data: chunk.into(),
            })))
        }
        BodyKind::Chunked { phase } => {
            let frame = read_chunked_frame(buf, phase, stream_id)?;
            if matches!(frame, Some(StreamFrame::End(_))) {
                reader.kind = BodyKind::None;
            }
            Ok(frame)
        }
    }
}

fn read_chunked_frame(
    buf: &mut BytesMut,
    phase: &mut ChunkPhase,
    stream_id: u64,
) -> Result<Option<StreamFrame>, H1DecodeError> {
    loop {
        match phase {
            ChunkPhase::SizeLine => {
                let line_end = match find_crlf(buf, 0) {
                    Some(value) => value,
                    None => return Ok(None),
                };
                let line = &buf[..line_end];
                let size = parse_chunk_size(line)?;
                buf.advance(line_end + 2);
                if size == 0 {
                    *phase = ChunkPhase::Trailers;
                    continue;
                }
                let size = usize::try_from(size)
                    .map_err(|_| H1DecodeError::InvalidChunkedEncoding)?;
                *phase = ChunkPhase::Data { remaining: size };
            }
            ChunkPhase::Data { remaining } => {
                if buf.is_empty() {
                    return Ok(None);
                }
                let take = (*remaining).min(buf.len());
                let chunk = buf.split_to(take).to_vec();
                *remaining -= take;
                if *remaining == 0 {
                    *phase = ChunkPhase::DataCrlf;
                }
                if chunk.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(StreamFrame::Body(StreamBody {
                    stream_id,
                    data: chunk.into(),
                })));
            }
            ChunkPhase::DataCrlf => {
                if buf.len() < 2 {
                    return Ok(None);
                }
                if buf[0] != b'\r' || buf[1] != b'\n' {
                    return Err(H1DecodeError::InvalidChunkedEncoding);
                }
                buf.advance(2);
                *phase = ChunkPhase::SizeLine;
            }
            ChunkPhase::Trailers => {
                let trailer_end = match find_double_crlf(buf, 0) {
                    Some(value) => value,
                    None => return Ok(None),
                };
                buf.advance(trailer_end + 4);
                return Ok(Some(StreamFrame::End(StreamEnd { stream_id })));
            }
        }
    }
}

fn content_length(headers: &[HeaderField]) -> Result<Option<usize>, H1DecodeError> {
    let mut value = None;
    for header in headers {
        if !crate::eq_ignore_ascii_case(&header.name, b"content-length") {
            continue;
        }
        let trimmed = trim_ascii(&header.value);
        if trimmed.is_empty() {
            return Err(H1DecodeError::InvalidContentLength);
        }
        let parsed = parse_usize_ascii(trimmed)?;
        if let Some(existing) = value {
            if existing != parsed {
                return Err(H1DecodeError::InvalidContentLength);
            }
        } else {
            value = Some(parsed);
        }
    }
    Ok(value)
}

fn has_chunked_encoding(headers: &[HeaderField]) -> bool {
    headers.iter().any(|header| {
        crate::eq_ignore_ascii_case(&header.name, b"transfer-encoding")
            && contains_token(&header.value, b"chunked")
    })
}

fn contains_token(value: &[u8], token: &[u8]) -> bool {
    let mut start = 0;
    while start <= value.len() {
        let mut end = start;
        while end < value.len() && value[end] != b',' {
            end += 1;
        }
        let part = trim_ascii(&value[start..end]);
        if crate::eq_ignore_ascii_case(part, token) {
            return true;
        }
        if end == value.len() {
            break;
        }
        start = end + 1;
    }
    false
}

fn decode_chunked_body(bytes: &[u8]) -> Result<Option<(Vec<u8>, usize)>, H1DecodeError> {
    let mut out = Vec::new();
    let mut offset = 0usize;

    loop {
        let line_end = match find_crlf(bytes, offset) {
            Some(value) => value,
            None => return Ok(None),
        };
        let line = &bytes[offset..line_end];
        let size = parse_chunk_size(line)?;
        offset = line_end + 2;

        if size == 0 {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            if bytes.get(offset) == Some(&b'\r') && bytes.get(offset + 1) == Some(&b'\n') {
                offset += 2;
                break;
            }
            let trailer_end = match find_double_crlf(bytes, offset) {
                Some(value) => value,
                None => return Ok(None),
            };
            offset = trailer_end + 4;
            break;
        }

        let size_usize = usize::try_from(size).map_err(|_| H1DecodeError::InvalidChunkedEncoding)?;
        if bytes.len() < offset + size_usize + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&bytes[offset..offset + size_usize]);
        offset += size_usize;
        if bytes.get(offset) != Some(&b'\r') || bytes.get(offset + 1) != Some(&b'\n') {
            return Err(H1DecodeError::InvalidChunkedEncoding);
        }
        offset += 2;
    }

    Ok(Some((out, offset)))
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, H1DecodeError> {
    let mut end = line.len();
    for (idx, byte) in line.iter().enumerate() {
        if *byte == b';' {
            end = idx;
            break;
        }
    }
    let trimmed = trim_ascii(&line[..end]);
    if trimmed.is_empty() {
        return Err(H1DecodeError::InvalidChunkedEncoding);
    }

    let mut value: u64 = 0;
    for &byte in trimmed {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            b'a'..=b'f' => (byte - b'a' + 10) as u64,
            b'A'..=b'F' => (byte - b'A' + 10) as u64,
            _ => return Err(H1DecodeError::InvalidChunkedEncoding),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or(H1DecodeError::InvalidChunkedEncoding)?;
    }

    Ok(value)
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    let mut idx = start;
    while idx + 1 < bytes.len() {
        if bytes[idx] == b'\r' && bytes[idx + 1] == b'\n' {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn find_double_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    let mut idx = start;
    while idx + 3 < bytes.len() {
        if bytes[idx] == b'\r'
            && bytes[idx + 1] == b'\n'
            && bytes[idx + 2] == b'\r'
            && bytes[idx + 3] == b'\n'
        {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end {
        let byte = value[start];
        if byte != b' ' && byte != b'\t' {
            break;
        }
        start += 1;
    }
    while end > start {
        let byte = value[end - 1];
        if byte != b' ' && byte != b'\t' {
            break;
        }
        end -= 1;
    }
    &value[start..end]
}

fn parse_usize_ascii(value: &[u8]) -> Result<usize, H1DecodeError> {
    if value.is_empty() {
        return Err(H1DecodeError::InvalidContentLength);
    }
    let mut out: usize = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(H1DecodeError::InvalidContentLength);
        }
        let digit = (byte - b'0') as usize;
        out = out
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(H1DecodeError::InvalidContentLength)?;
    }
    Ok(out)
}

fn find_header_value<'a>(headers: &'a [HeaderField], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|header| crate::eq_ignore_ascii_case(&header.name, name))
        .map(|header| header.value.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_request() {
        let input = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (req, consumed) = decode_request(input).unwrap().unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(req.method, b"GET".to_vec());
        assert_eq!(req.path, b"/hello".to_vec());
        assert_eq!(req.authority.unwrap(), b"example.com".to_vec());
        assert!(req.body.is_empty());
    }

    #[test]
    fn decode_request_with_body() {
        let input = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let (req, consumed) = decode_request(input).unwrap().unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(req.method, b"POST".to_vec());
        assert_eq!(req.body, b"hello".to_vec());
    }

    #[test]
    fn decode_chunked_response() {
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let (resp, consumed) = decode_response(input).unwrap().unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"Wikipedia".to_vec());
    }

    #[test]
    fn decoder_streaming() {
        let input = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut decoder = H1Decoder::new(H1MessageKind::Request);
        decoder.push(&input[..10]);
        assert!(decoder.try_decode().unwrap().is_none());

        decoder.push(&input[10..]);
        let msg = decoder.try_decode().unwrap();
        assert!(matches!(msg, Some(PackedMessage::Request(_))));
        assert_eq!(decoder.buffer_len(), 0);
    }

    #[test]
    fn stream_decoder_content_length() {
        let input = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let mut decoder = H1StreamDecoder::new(H1MessageKind::Request, 42);
        decoder.push(input);

        let frame = decoder.try_decode().unwrap();
        assert!(matches!(frame, Some(StreamFrame::Headers(_))));

        let frame = decoder.try_decode().unwrap();
        match frame {
            Some(StreamFrame::Body(body)) => {
                assert_eq!(body.stream_id, 42);
                assert_eq!(body.data, b"hello".to_vec());
            }
            _ => panic!("expected body frame"),
        }

        let frame = decoder.try_decode().unwrap();
        assert!(matches!(frame, Some(StreamFrame::End(_))));
    }
}
