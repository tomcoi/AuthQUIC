#!/usr/bin/env python3
import argparse
import asyncio
import struct
import hashlib

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted



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
HEADER_STRUCT = struct.Struct("!BBBH") # version, type, flags, length

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

def unpack_challenge(data: bytes):
    # CHALLENGE body is exactly 16 bytes (nonce)
    return data[:16]

def pack_response(username: str, response_hash: bytes) -> bytes:
    uname_bytes = username.encode("utf-8")
    if len(uname_bytes) > 255:
        raise ValueError("username too long")
    if len(response_hash) != 32:
        raise ValueError("response_hash must be 32 bytes")
    body = struct.pack("!B", len(uname_bytes)) + uname_bytes + response_hash
    return pack_header(MSG_TYPE_RESPONSE, len(body)) + body

def unpack_accept(data: bytes):
    # ACCEPT body is exactly 16 bytes (session token)
    return data[:16]

def unpack_reject(data: bytes):
    length = data[0]
    return data[1:1 + length].decode("utf-8")

def unpack_error(data: bytes):
    error_code = struct.unpack("!H", data[:2])[0]
    desc_len = data[2]
    description = data[3:3 + desc_len].decode("utf-8")
    return error_code, description



#   CLIENT PROTOCOL 
# ──────────────────────────────────────────────────────────────────────────────

class AuthQuicClientProtocol(QuicConnectionProtocol):
    """
    DFA:
      START → (send HELLO) → WAIT_CHALLENGE → (receive CHALLENGE) → send RESPONSE
      → WAIT_RESULT → (receive ACCEPT/REJECT/ERROR)
    """

    def __init__(self, username: str, password: str, client_id: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username = username
        self.password = password
        self.client_id = client_id

        self.state = "START"
        self.nonce = None
        self.session_token = None
        self._stream_id = None
        # Flag to ensure HELLO is sent only once after handshake
        self._hello_sent = False

    def quic_event_received(self, event):
        from aioquic.quic.events import HandshakeCompleted
        if isinstance(event, HandshakeCompleted):
            if not self._hello_sent:
                self._send_hello()
                self._hello_sent = True
            return

        if isinstance(event, StreamDataReceived):
            data = event.data
            if len(data) < 5:
                print("ERROR: Received too‐short header")
                return

            version, msg_type, flags, length = unpack_header(data[:5])
            if version != PROTOCOL_VERSION:
                print(f"ERROR: Unsupported version {version}")
                return

            body = data[5:]
            if len(body) != length:
                print(f"ERROR: Body length mismatch (expected {length})")
                return

            if msg_type == MSG_TYPE_CHALLENGE and self.state == "WAIT_CHALLENGE":
                self._handle_challenge(body, event.stream_id)
            elif msg_type == MSG_TYPE_ACCEPT and self.state == "WAIT_RESULT":
                token = unpack_accept(body)
                self.session_token = token
                self.state = "AUTH_SUCCESS"
                print(f"[+] Authentication succeeded! Session Token: {token.hex()}")
                # Send empty data to close the stream
                self._quic.send_stream_data(event.stream_id, b"", end_stream=True)
                self.transmit()
            elif msg_type == MSG_TYPE_REJECT and self.state == "WAIT_RESULT":
                reason = unpack_reject(body)
                self.state = "AUTH_FAILED"
                print(f"[-] Authentication failed: {reason}")
                self._quic.send_stream_data(event.stream_id, b"", end_stream=True)
                self.transmit()
            elif msg_type == MSG_TYPE_ERROR:
                code, desc = unpack_error(body)
                self.state = "AUTH_FAILED"
                print(f"[-] Received ERROR (code={code}): {desc}")
                self._quic.send_stream_data(event.stream_id, b"", end_stream=True)
                self.transmit()
            else:
                print(f"ERROR: Unexpected msg_type={msg_type} in state={self.state}")

    def _send_hello(self):
        if self.state != "START":
            raise RuntimeError("HELLO not allowed in current state")

        # Open a new bidirectional stream
        self._stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        pdu = pack_hello(self.client_id)
        self._quic.send_stream_data(self._stream_id, pdu, end_stream=False)
        self.transmit()
        self.state = "WAIT_CHALLENGE"
        print("[*] Sent HELLO → waiting for CHALLENGE...")

    def _handle_challenge(self, body: bytes, stream_id: int):
        try:
            nonce = unpack_challenge(body)
        except Exception as e:
            print(f"Malformed CHALLENGE: {e}")
            return

        self.nonce = nonce
        # Compute response_hash = SHA256(username || password || nonce)
        to_hash = self.username.encode("utf-8") + self.password.encode("utf-8") + nonce
        response_hash = hashlib.sha256(to_hash).digest()
        # Build and send RESPONSE
        pdu = pack_response(self.username, response_hash)
        self._quic.send_stream_data(stream_id, pdu, end_stream=False)
        self.transmit()
        self.state = "WAIT_RESULT"
        print("[*] Received CHALLENGE → sent RESPONSE, now waiting for ACCEPT/REJECT...")


async def main():
    parser = argparse.ArgumentParser(description="AuthQUIC Client")
    parser.add_argument(
        "--host", type=str, required=True,
        help="Server hostname or IP (e.g. 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, required=True,
        help="Server port (e.g. 12345)"
    )
    parser.add_argument(
        "--username", type=str, required=True,
        help="Username for authentication"
    )
    parser.add_argument(
        "--password", type=str, required=True,
        help="Password for authentication"
    )
    parser.add_argument(
        "--client-id", type=str, required=True,
        help="Unique client_id to present in HELLO"
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disable certificate verification (for self‐signed certs)"
    )

    args = parser.parse_args()

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["authquic"],
    )
    if args.insecure:
        configuration.verify_mode = False

    print(f"Connecting to {args.host}:{args.port} as {args.client_id} ...")
    async with connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=lambda *a, **kw: AuthQuicClientProtocol(
            args.username, args.password, args.client_id, *a, **kw
        )
    ) as protocol:
        # Wait for the authentication process to complete
        while protocol.state not in ("AUTH_SUCCESS", "AUTH_FAILED"):
            await asyncio.sleep(0.1)

        await asyncio.sleep(0.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
