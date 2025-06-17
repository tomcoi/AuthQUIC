#!/usr/bin/env python3
import argparse
import asyncio
import struct
import hashlib
import secrets

from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived


#   PDU HEADER & MESSAGE (un)PACKING
# ──────────────────────────────────────────────────────────────────────────────

# Message Type Constants
MSG_TYPE_HELLO     = 0x01
MSG_TYPE_CHALLENGE = 0x02
MSG_TYPE_RESPONSE  = 0x03
MSG_TYPE_ACCEPT    = 0x04
MSG_TYPE_REJECT    = 0x05
MSG_TYPE_ERROR     = 0x06

PROTOCOL_VERSION = 0x01
HEADER_STRUCT = struct.Struct("!BBBH")  # version, type, flags, length

def pack_header(msg_type: int, body_length: int, flags: int = 0) -> bytes:
    return HEADER_STRUCT.pack(PROTOCOL_VERSION, msg_type, flags, body_length)

def unpack_header(data: bytes):
    version, msg_type, flags, length = HEADER_STRUCT.unpack(data[:5])
    return version, msg_type, flags, length

def pack_hello(client_id: str) -> bytes:
    cid_bytes = client_id.encode("utf-8")
    if len(cid_bytes) > 255:
        raise ValueError("client_id too long")
    body = struct.pack("!B", len(cid_bytes)) + cid_bytes
    return pack_header(MSG_TYPE_HELLO, len(body)) + body

def unpack_hello(data: bytes) -> str:
    length = data[0]
    return data[1:1 + length].decode("utf-8")

def pack_challenge(nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    body = nonce
    return pack_header(MSG_TYPE_CHALLENGE, len(body)) + body

def unpack_challenge(data: bytes) -> bytes:
    return data[:16]

def pack_response(username: str, response_hash: bytes) -> bytes:
    uname_bytes = username.encode("utf-8")
    if len(uname_bytes) > 255:
        raise ValueError("username too long")
    if len(response_hash) != 32:
        raise ValueError("response_hash must be 32 bytes")
    body = struct.pack("!B", len(uname_bytes)) + uname_bytes + response_hash
    return pack_header(MSG_TYPE_RESPONSE, len(body)) + body

def unpack_response(data: bytes):
    uname_len = data[0]
    username = data[1:1 + uname_len].decode("utf-8")
    response_hash = data[1 + uname_len : 1 + uname_len + 32]
    return username, response_hash

def pack_accept(session_token: bytes) -> bytes:
    if len(session_token) != 16:
        raise ValueError("session_token must be 16 bytes")
    body = session_token
    return pack_header(MSG_TYPE_ACCEPT, len(body)) + body

def unpack_accept(data: bytes) -> bytes:
    return data[:16]

def pack_reject(reason: str) -> bytes:
    reason_bytes = reason.encode("utf-8")
    if len(reason_bytes) > 255:
        raise ValueError("reason too long")
    body = struct.pack("!B", len(reason_bytes)) + reason_bytes
    return pack_header(MSG_TYPE_REJECT, len(body)) + body

def unpack_reject(data: bytes) -> str:
    length = data[0]
    return data[1:1 + length].decode("utf-8")

def pack_error(error_code: int, description: str) -> bytes:
    desc_bytes = description.encode("utf-8")
    if len(desc_bytes) > 255:
        raise ValueError("description too long")
    body = struct.pack("!H", error_code) + struct.pack("!B", len(desc_bytes)) + desc_bytes
    return pack_header(MSG_TYPE_ERROR, len(body)) + body

def unpack_error(data: bytes):
    error_code = struct.unpack("!H", data[:2])[0]
    desc_len = data[2]
    description = data[3:3 + desc_len].decode("utf-8")
    return error_code, description


#   SERVER PROTOCOL (stateful)
# ──────────────────────────────────────────────────────────────────────────────


class AuthQuicServerProtocol(QuicConnectionProtocol):
    """
    DFA:
      "START" → "WAIT_RESPONSE" → "AUTH_SUCCESS" or "AUTH_FAILED"
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = "START"
        self.client_id = None
        self.nonce = None
        self.username = None
        # can store salted password hashes instead of plaintext
        self.users_db = {
            "user1": "abc123",
            "user2":   "qwer5678"
        }

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data

            if len(data) < 5:
                self._send_error(stream_id, 1, "Header too short")
                return

            version, msg_type, flags, length = unpack_header(data[:5])
            if version != PROTOCOL_VERSION:
                self._send_error(stream_id, 2, f"Unsupported version {version}")
                return

            body = data[5:]
            if len(body) != length:
                self._send_error(stream_id, 3, "Length mismatch")
                return

            if msg_type == MSG_TYPE_HELLO:
                self._handle_hello(stream_id, body)
            elif msg_type == MSG_TYPE_RESPONSE:
                self._handle_response(stream_id, body)
            else:
                self._send_error(stream_id, 4, f"Unexpected msg_type {msg_type} in state {self.state}")

    def _handle_hello(self, stream_id: int, body: bytes):
        if self.state != "START":
            self._send_error(stream_id, 5, "Hello not expected at this time")
            return

        try:
            client_id = unpack_hello(body)
        except Exception as e:
            self._send_error(stream_id, 6, f"Malformed HELLO: {e}")
            return

        self.client_id = client_id
        self.nonce = secrets.token_bytes(16)
        self.state = "WAIT_RESPONSE"

        # Send CHALLENGE without closing the stream
        pdu = pack_challenge(self.nonce)
        self._quic.send_stream_data(stream_id, pdu, end_stream=False)
        self.transmit()

    def _handle_response(self, stream_id: int, body: bytes):
        if self.state != "WAIT_RESPONSE":
            self._send_error(stream_id, 7, "Response not expected at this time")
            return

        try:
            username, response_hash = unpack_response(body)
        except Exception as e:
            self._send_error(stream_id, 8, f"Malformed RESPONSE: {e}")
            return

        self.username = username
        pwd = self.users_db.get(username)
        if pwd is None:
            self.state = "AUTH_FAILED"
            pdu = pack_reject("Unknown user")
            self._send_pdu(stream_id, pdu)
            return

        expected_hash = hashlib.sha256(
            username.encode("utf-8") +
            pwd.encode("utf-8") +
            self.nonce
        ).digest()

        if expected_hash == response_hash:
            self.state = "AUTH_SUCCESS"
            token = secrets.token_bytes(16)
            pdu = pack_accept(token)
            self._send_pdu(stream_id, pdu)
        else:
            self.state = "AUTH_FAILED"
            pdu = pack_reject("Hash mismatch")
            self._send_pdu(stream_id, pdu)

    def _send_pdu(self, stream_id: int, pdu: bytes):
        """
        Send the final ACCEPT or REJECT and close the stream.
        """
        self._quic.send_stream_data(stream_id, pdu, end_stream=True)
        self.transmit()

    def _send_error(self, stream_id: int, code: int, desc: str):
        pdu = pack_error(code, desc)
        self._quic.send_stream_data(stream_id, pdu, end_stream=True)
        self.transmit()

async def main():
    parser = argparse.ArgumentParser(description="AuthQUIC Server")
    parser.add_argument(
        "--host", type=str, required=True,
        help="Host/IP to bind the server (e.g. 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, required=True,
        help="UDP port to listen on (e.g. 12345)"
    )
    parser.add_argument(
        "--cert", type=str, required=True,
        help="Path to TLS certificate (e.g. cert.pem)"
    )
    parser.add_argument(
        "--key", type=str, required=True,
        help="Path to TLS private key (e.g. key.pem)"
    )

    args = parser.parse_args()

    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["authquic"],
    )
    configuration.load_cert_chain(args.cert, args.key)

    print(f"Starting AuthQUIC server on {args.host}:{args.port} …")
    server = await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=AuthQuicServerProtocol
    )

    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer interrupted by user, shutting down…")
