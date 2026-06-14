from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag
import hashlib
import hmac as hmaclib
import struct


class SVPFormatError(Exception):
	"""Raised when an SVP frame has an invalid binary format."""


class SVPHmacError(Exception):
	"""Raised when an SVP frame fails HMAC validation."""


class MsgType(IntEnum):
	"""SVP message types from specification section 3.2."""

	HELLO = 0x01
	CHALLENGE = 0x02
	AUTH = 0x03
	AUTH_OK = 0x04
	AUTH_FAIL = 0x05
	VAULT_GET = 0x10
	VAULT_PUT = 0x11
	VAULT_SYNC = 0x12
	VAULT_DATA = 0x13
	VAULT_ACK = 0x14
	PING = 0x20
	PONG = 0x21
	BYE = 0xF0
	ERROR = 0xFF


class SVPFlags(IntFlag):
	"""SVP frame flags from specification section 3.3."""

	NONE = 0x00
	COMPRESSED = 0x01
	ENCRYPTED = 0x02
	FRAGMENTED = 0x04
	LAST_FRAG = 0x08


@dataclass(slots=True)
class SVPFrame:
	"""SVP frame object model."""

	version: int
	msg_type: MsgType
	flags: SVPFlags
	seq_id: int
	payload_len: int
	payload: bytes
	hmac: bytes


class SVPCodec:
	"""Binary codec for SVP frames."""

	HEADER_STRUCT: struct.Struct = struct.Struct("<BBBII")
	HEADER_LEN: int = HEADER_STRUCT.size
	HMAC_LEN: int = 32
	MAX_PAYLOAD_LEN: int = 1_048_576
	_RESERVED_FLAG_MASK: int = 0xF0

	@classmethod
	def encode(cls, frame: SVPFrame, mac_key: bytes) -> bytes:
		"""Encode an SVPFrame into binary frame bytes with trailing HMAC-SHA256."""
		if len(frame.payload) != frame.payload_len:
			raise SVPFormatError(
				"payload_len does not match actual payload length"
			)

		if frame.payload_len > cls.MAX_PAYLOAD_LEN:
			raise SVPFormatError("payload_len exceeds maximum allowed size")

		if int(frame.flags) & cls._RESERVED_FLAG_MASK:
			raise SVPFormatError("reserved SVP flags (bits 4-7) must be unset")

		header: bytes = cls.HEADER_STRUCT.pack(
			frame.version,
			int(frame.msg_type),
			int(frame.flags),
			frame.seq_id,
			frame.payload_len,
		)
		signed_part: bytes = header + frame.payload
		frame_hmac: bytes = hmaclib.new(
			mac_key,
			signed_part,
			hashlib.sha256,
		).digest()
		return signed_part + frame_hmac

	@classmethod
	def decode(cls, data: bytes, mac_key: bytes) -> SVPFrame:
		"""Decode raw bytes into SVPFrame and validate trailing HMAC-SHA256."""
		min_frame_len: int = cls.HEADER_LEN + cls.HMAC_LEN
		if len(data) < min_frame_len:
			raise SVPFormatError("frame too short")

		header: bytes = data[: cls.HEADER_LEN]
		try:
			version, msg_type_raw, flags_raw, seq_id, payload_len = cls.HEADER_STRUCT.unpack(
				header
			)
		except struct.error as exc:
			raise SVPFormatError("invalid SVP header") from exc

		if payload_len > cls.MAX_PAYLOAD_LEN:
			raise SVPFormatError("payload_len exceeds maximum allowed size")

		expected_len: int = cls.HEADER_LEN + payload_len + cls.HMAC_LEN
		if len(data) != expected_len:
			raise SVPFormatError("frame length does not match payload_len")

		payload_start: int = cls.HEADER_LEN
		payload_end: int = payload_start + payload_len
		payload: bytes = data[payload_start:payload_end]
		frame_hmac: bytes = data[payload_end:]

		signed_part: bytes = header + payload
		calculated_hmac: bytes = hmaclib.new(
			mac_key,
			signed_part,
			hashlib.sha256,
		).digest()
		if not hmaclib.compare_digest(frame_hmac, calculated_hmac):
			raise SVPHmacError("invalid frame HMAC")

		if flags_raw & cls._RESERVED_FLAG_MASK:
			raise SVPFormatError("reserved SVP flags (bits 4-7) must be unset")

		try:
			msg_type: MsgType = MsgType(msg_type_raw)
		except ValueError as exc:
			raise SVPFormatError(f"unknown message type: 0x{msg_type_raw:02X}") from exc

		return SVPFrame(
			version=version,
			msg_type=msg_type,
			flags=SVPFlags(flags_raw),
			seq_id=seq_id,
			payload_len=payload_len,
			payload=payload,
			hmac=frame_hmac,
		)
