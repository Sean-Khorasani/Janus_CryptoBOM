#!/usr/bin/env python3
"""Verify repository-specific Rust and Go protobuf bindings against janus.proto.

This intentionally checks wire-contract semantics instead of source formatting:
enum values, message field names/numbers/cardinality/types, and RPC signatures.
It uses only Python's standard library so clean-clone verification has no hidden
Python package dependency.
"""

from __future__ import annotations

import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTO = ROOT / "proto/janus.proto"
RUST = ROOT / "agent/src/proto.rs"
GO_TYPES = ROOT / "server/internal/pb/types.go"
GO_SERVICE = ROOT / "server/internal/pb/service.go"

SCALARS = {
    "bool": "bool",
    "bytes": "bytes",
    "double": "double",
    "int64": "int64",
    "string": "string",
    "uint32": "uint32",
}


@dataclass(frozen=True)
class Field:
    name: str
    number: int
    kind: str
    repeated: bool


def blocks(source: str, keyword: str) -> dict[str, str]:
    return {
        name: body
        for name, body in re.findall(
            rf"\b{keyword}\s+(\w+)\s*\{{(.*?)\}}", source, flags=re.DOTALL
        )
    }


def parse_proto() -> tuple[dict[str, dict[str, int]], dict[str, list[Field]], list[tuple[str, str, str, bool, bool]]]:
    source = re.sub(r"//.*", "", PROTO.read_text())
    enums: dict[str, dict[str, int]] = {}
    for name, body in blocks(source, "enum").items():
        enums[name] = {
            value: int(number)
            for value, number in re.findall(r"\b(\w+)\s*=\s*(\d+)\s*;", body)
        }

    messages: dict[str, list[Field]] = {}
    for name, body in blocks(source, "message").items():
        fields = []
        for repeated, kind, field_name, number in re.findall(
            r"\b(repeated\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)\s*;", body
        ):
            semantic_kind = SCALARS.get(kind, f"enum:{kind}" if kind in enums else "message")
            fields.append(Field(field_name, int(number), semantic_kind, bool(repeated)))
        messages[name] = fields

    rpcs = []
    for _, body in blocks(source, "service").items():
        for name, request_stream, request, response_stream, response in re.findall(
            r"\brpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+)\s*\)"
            r"\s+returns\s+\(\s*(stream\s+)?(\w+)\s*\)\s*;",
            body,
        ):
            rpcs.append((name, request, response, bool(request_stream), bool(response_stream)))
    return enums, messages, rpcs


def rust_kind(options: str) -> tuple[str, bool]:
    repeated = "repeated" in options
    enum = re.search(r'enumeration\s*=\s*"(\w+)"', options)
    if enum:
        return f"enum:{enum.group(1)}", repeated
    for kind in SCALARS.values():
        if re.search(rf"\b{kind}\b", options):
            return kind, repeated
    if re.search(r"\bmessage\b", options):
        return "message", repeated
    return "unknown", repeated


def parse_rust_messages() -> dict[str, list[Field]]:
    source = RUST.read_text()
    result = {}
    for name, body in blocks(source, "struct").items():
        fields = []
        for options, field_name in re.findall(
            r"#\[prost\((.*?)\)\]\s*pub\s+(\w+)\s*:", body, flags=re.DOTALL
        ):
            tag = re.search(r'tag\s*=\s*"(\d+)"', options)
            if not tag:
                continue
            kind, repeated = rust_kind(options)
            fields.append(Field(field_name, int(tag.group(1)), kind, repeated))
        if fields:
            result[name] = fields
    return result


def parse_go_messages() -> dict[str, list[Field]]:
    source = GO_TYPES.read_text()
    result = {}
    for name, body in re.findall(
        r"\btype\s+(\w+)\s+struct\s*\{(.*?)\}", source, flags=re.DOTALL
    ):
        fields = []
        for go_type, tag in re.findall(
            r"^\s+\w+\s+(\S+)\s+`protobuf:\"([^\"]+)\"", body, flags=re.MULTILINE
        ):
            parts = tag.split(",")
            number = int(parts[1])
            proto_name = next(part.removeprefix("name=") for part in parts if part.startswith("name="))
            repeated = "rep" in parts
            base_type = go_type.removeprefix("[]").removeprefix("*")
            kind = {
                "bool": "bool",
                "float64": "double",
                "int32": "enum:int32",
                "int64": "int64",
                "string": "string",
                "uint32": "uint32",
                "byte": "bytes",
            }.get(base_type, "message")
            fields.append(Field(proto_name, number, kind, repeated))
        if fields:
            result[name] = fields
    return result


def pascal(words: str, preserve_short_acronyms: bool = False) -> str:
    pieces = []
    for word in words.split("_"):
        if preserve_short_acronyms and word in {"KDF", "KEM", "MAC"}:
            pieces.append(word)
        else:
            pieces.append(word.lower().capitalize())
    return "".join(pieces)


def enum_prefix(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper() + "_"


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def compare(label: str, expected: object, actual: object, errors: list[str]) -> None:
    if expected != actual:
        errors.append(f"{label}: expected {expected!r}, found {actual!r}")


def main() -> int:
    enums, messages, rpcs = parse_proto()
    rust_source = RUST.read_text()
    go_types_source = GO_TYPES.read_text()
    go_service_source = GO_SERVICE.read_text()
    rust_messages = parse_rust_messages()
    go_messages = parse_go_messages()
    errors: list[str] = []

    compare("Rust message set", set(messages), set(rust_messages), errors)
    compare("Go message set", set(messages), set(go_messages), errors)

    for message, expected_fields in messages.items():
        compare(f"Rust {message} fields", expected_fields, rust_messages.get(message), errors)

        go_fields = go_messages.get(message, [])
        compare(
            f"Go {message} fields",
            [
                Field(
                    field.name,
                    field.number,
                    "enum:int32" if field.kind.startswith("enum:") else field.kind,
                    field.repeated,
                )
                for field in expected_fields
            ],
            go_fields,
            errors,
        )

    for enum_name, values in enums.items():
        prefix = enum_prefix(enum_name)
        for proto_name, number in values.items():
            suffix = proto_name.removeprefix(prefix)
            rust_name = pascal(suffix)
            go_name = enum_name + pascal(suffix, preserve_short_acronyms=True)
            if not re.search(rf"\b{re.escape(rust_name)}\s*=\s*{number}\b", rust_source):
                errors.append(f"Rust enum value missing: {enum_name}.{proto_name}={number}")
            if not re.search(rf"\b{re.escape(go_name)}\s+int32\s*=\s*{number}\b", go_types_source):
                errors.append(f"Go enum value missing: {enum_name}.{proto_name}={number}")

    package_match = re.search(r"\bpackage\s+([\w.]+)\s*;", PROTO.read_text())
    package = package_match.group(1) if package_match else ""
    for rpc_name, request, response, request_stream, response_stream in rpcs:
        path = f"/{package}.JanusTelemetry/{rpc_name}"
        if path not in rust_source:
            errors.append(f"Rust RPC path missing: {path}")
        if path not in go_service_source:
            errors.append(f"Go RPC path missing: {path}")
        rust_request = (
            rf"IntoStreamingRequest<Message\s*=\s*{request}>"
            if request_stream
            else rf"IntoRequest<{request}>"
        )
        rust_response = (
            rf"Streaming<{response}>"
            if response_stream
            else rf"Response<{response}>"
        )
        rust_signature = (
            rf"pub\s+async\s+fn\s+{snake(rpc_name)}\s*\(.*?"
            rf"{rust_request}.*?{rust_response}"
        )
        if not re.search(rust_signature, rust_source, flags=re.DOTALL):
            errors.append(f"Rust RPC signature drift: {rpc_name}: {request} -> {response}")

        if not request_stream and not response_stream:
            go_signature = (
                rf"\b{rpc_name}\(ctx context\.Context, in \*{request}, "
                rf"opts \.\.\.grpc\.CallOption\) \(\*{response}, error\)"
            )
            if not re.search(go_signature, go_service_source):
                errors.append(f"Go unary RPC signature drift: {rpc_name}")
            go_server_signature = (
                rf"\b{rpc_name}\(context\.Context, \*{request}\) \(\*{response}, error\)"
            )
            if not re.search(go_server_signature, go_service_source):
                errors.append(f"Go unary server signature drift: {rpc_name}")
        else:
            client_type = f"JanusTelemetry_{rpc_name}Client"
            go_method = (
                rf"\b{rpc_name}\(ctx context\.Context, opts \.\.\.grpc\.CallOption\) "
                rf"\({client_type}, error\)"
            )
            if not re.search(go_method, go_service_source):
                errors.append(f"Go streaming RPC method drift: {rpc_name}")
            client_block = re.search(
                rf"\btype\s+{client_type}\s+interface\s*\{{(.*?)\}}",
                go_service_source,
                flags=re.DOTALL,
            )
            body = client_block.group(1) if client_block else ""
            if request_stream and not re.search(rf"\bSend\(\*{request}\) error", body):
                errors.append(f"Go client-stream request drift: {rpc_name}")
            response_method = (
                rf"\bRecv\(\) \(\*{response}, error\)"
                if response_stream
                else rf"\bCloseAndRecv\(\) \(\*{response}, error\)"
            )
            if not re.search(response_method, body):
                errors.append(f"Go streaming response drift: {rpc_name}")

            server_type = f"JanusTelemetry_{rpc_name}Server"
            if not re.search(
                rf"\b{rpc_name}\({server_type}\) error", go_service_source
            ):
                errors.append(f"Go streaming server method drift: {rpc_name}")
            server_block = re.search(
                rf"\btype\s+{server_type}\s+interface\s*\{{(.*?)\}}",
                go_service_source,
                flags=re.DOTALL,
            )
            server_body = server_block.group(1) if server_block else ""
            if request_stream and not re.search(rf"\bRecv\(\) \(\*{request}, error\)", server_body):
                errors.append(f"Go server request-stream drift: {rpc_name}")
            server_response_method = (
                rf"\bSend\(\*{response}\) error"
                if response_stream
                else rf"\bSendAndClose\(\*{response}\) error"
            )
            if not re.search(server_response_method, server_body):
                errors.append(f"Go server streaming-response drift: {rpc_name}")

    if errors:
        print("protobuf binding drift detected:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Rust and Go protobuf bindings match canonical wire contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
