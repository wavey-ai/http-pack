# http-pack

Binary framing for HTTP requests/responses so they can be relayed as a stream-decodable payload.

The format is designed to carry HTTP/1.1, H2, or H3 messages after TLS termination, then rebuild
HTTP/1.1 requests or responses on the receiving side.

## Format (v1)

- Magic: `HPK1`
- Format version: `u8`
- Kind: `u8` (`1` = request, `2` = response)
- HTTP version: `u8` (`1` = HTTP/1.1, `2` = H2, `3` = H3)
- Request fields (length-delimited with varint):
  - method
  - scheme (empty = none)
  - authority (empty = none)
  - path
- Response fields:
  - status (`u16`, network order)
- Headers:
  - header count (varint)
  - name length + bytes
  - value length + bytes
- Body:
  - body length (varint)
  - body bytes

Lengths are unsigned LEB128 varints so the payload can be decoded from a stream.

## Usage

```rust
use bytes::Bytes;
use http::Request;
use http_pack::{decode, encode_request, Decoder, PackedMessage};

let req = Request::builder()
    .method("POST")
    .uri("https://example.com/ingest")
    .body(Bytes::from_static(b"hello"))
    .unwrap();

let payload = encode_request(&req).unwrap();
let decoded = decode(&payload).unwrap();

if let PackedMessage::Request(packed) = decoded {
    let http1 = packed.to_http1_bytes().unwrap();
    // send http1 bytes to an HTTP/1.1 backend
}
```

The HTTP/1.1 reconstruction helpers drop `transfer-encoding` and add a `content-length` when
missing so the resulting request/response is valid in HTTP/1.1 form.

## Streaming frames

For streaming relays, use the stream frame format (`HPKS`). Each frame is a small binary payload
that can be signed and packetized independently:

- Headers frame: carries the request/response line + headers.
- Body frame: carries a chunk of body bytes.
- End frame: marks the end of the body.

On the receiving side, `Http1StreamRebuilder` converts these frames into HTTP/1.1 bytes using
`transfer-encoding: chunked` so the body can be forwarded without buffering.

```rust
use http_pack::stream::{StreamFrame, StreamHeaders, StreamRequestHeaders, StreamBody, StreamEnd, Http1StreamRebuilder};

let headers = StreamHeaders::Request(StreamRequestHeaders {
    stream_id: 1,
    version: http_pack::HttpVersion::Http11,
    method: b"POST".to_vec(),
    scheme: None,
    authority: Some(b"example.com".to_vec()),
    path: b"/upload".to_vec(),
    headers: vec![],
});

let mut rebuilder = Http1StreamRebuilder::new();
let header_bytes = rebuilder.push_frame(StreamFrame::Headers(headers))?;
let body_bytes = rebuilder.push_frame(StreamFrame::Body(StreamBody { stream_id: 1, data: Bytes::from_static(b"hi") }))?;
let end_bytes = rebuilder.push_frame(StreamFrame::End(StreamEnd { stream_id: 1 }))?;
```

## Streaming encode helpers

- HTTP/1.1 raw: `h1::H1StreamDecoder` emits `StreamFrame` values as bytes arrive.
- HTTP/2 (or any `http_body::Body`): `stream::body::encode_request/encode_response` emits frames via a callback.
- HTTP/3: `stream::h3::encode_server_request/encode_client_response` emits frames from `h3::RequestStream`.

These helpers let you stream the body without buffering it in memory.

## HTTP/1.1 raw decoder

Enable `h1` to parse raw HTTP/1.1 bytes into `PackedRequest`/`PackedResponse` values. This parser
expects either `content-length` or `transfer-encoding: chunked` when a body is present.

```toml
http-pack = { path = "../http-pack", features = ["h1"] }
```

```rust
use http_pack::h1::{decode_request, H1MessageKind, H1Decoder};

let bytes = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
let (req, _consumed) = decode_request(bytes).unwrap().unwrap();

let mut decoder = H1Decoder::new(H1MessageKind::Request);
decoder.push(bytes);
let msg = decoder.try_decode().unwrap();
```

## Body collection for HTTP/1.1 and HTTP/2

Enable `body` to collect `http_body::Body` payloads (hyper requests/responses, h2 responses, etc.)
into `PackedRequest`/`PackedResponse` values.

```toml
http-pack = { path = "../http-pack", features = ["body"] }
```

```rust
use http_pack::body::pack_request;

let packed = pack_request(req).await?;
```

## HTTP/3 stream adapter

Enable `h3` to collect data frames from `h3::server::RequestStream` or `h3::client::RequestStream`
and build packed messages.

```toml
http-pack = { path = "../http-pack", features = ["h3"] }
```

```rust
use http_pack::h3::{pack_server_request, pack_client_response};

let packed_req = pack_server_request(req, &mut stream).await?;
let packed_resp = pack_client_response(resp, &mut stream).await?;
```

## message-packetizer integration

`http-pack` always ships a `HttpPackMessage` wrapper that implements
`message_packetizer::SignableMessage`. You encode an HTTP request/response into a packed payload,
wrap it in `HttpPackMessage`, then sign and stream packets using `message-packetizer`.

```rust
use http_pack::packetizer::HttpPackMessage;
use message_packetizer::MessageSigner;

let msg = HttpPackMessage::from_request(&req).unwrap();
let mut signer = MessageSigner::new(&signing_key)?;
let signed = signer.sign(&msg)?;

for packet in signed.to_packets() {
    // stream packet bytes over SRT/UDP/etc
}
```

For streaming relays, use `HttpPackStreamMessage` and send each frame independently:

```rust
use http_pack::packetizer::HttpPackStreamMessage;
use http_pack::stream::StreamFrame;
use message_packetizer::MessageSigner;

let msg = HttpPackStreamMessage::from_frame(&frame);
let mut signer = MessageSigner::new(&signing_key)?;
let signed = signer.sign(&msg)?;
for packet in signed.to_packets() {
    // send packet bytes
}
```

Or use the convenience adapters to emit `HttpPackStreamMessage` directly (requires `body` feature):

```rust
use http_pack::packetizer::stream;

stream::encode_request(req, stream_id, |msg| {
    let signed = signer.sign(&msg)?;
    for packet in signed.to_packets() {
        // send packet bytes
    }
    Ok(())
}).await?;
```

## Testing

```bash
cargo test
```

The test suite includes:
- Core HPK1 encode/decode roundtrips
- Real HTTP/2 connections via `h2`
- Real HTTP/3 connections via `quinn` + `h3`
- Byte-for-byte body fidelity across all protocols (all 256 byte values, null bytes, CRLF sequences, 1MB bodies)

## License

MIT
