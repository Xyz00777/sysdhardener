#!/usr/bin/env python3
"""Safe Redis demo probe; filesystem tests require an explicit disposable-VM opt-in."""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import sys
from pathlib import Path
from types import TracebackType
from typing import Final, TypeAlias

DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 6379
TEST_DIRECTORY: Final = "/root/.ssh"
RespValue: TypeAlias = str | list["RespValue | None"] | None


class RedisClient:
    """Small RESP2 client that parses complete frames under a socket timeout."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.connection = socket.create_connection((host, port), timeout=timeout)
        self.connection.settimeout(timeout)
        self.reader = self.connection.makefile("rb")

    def __enter__(self) -> RedisClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.reader.close()
        self.connection.close()

    def _line(self) -> bytes:
        line = self.reader.readline()
        if not line.endswith(b"\r\n"):
            raise ConnectionError("truncated RESP line")
        return line[:-2]

    def _frame(self) -> RespValue:
        marker = self.reader.read(1)
        if marker in (b"+", b"-", b":"):
            value = self._line().decode("utf-8", "replace")
            return f"ERROR:{value}" if marker == b"-" else value
        if marker == b"$":
            length = int(self._line())
            if length == -1:
                return None
            value = self.reader.read(length)
            if len(value) != length or self.reader.read(2) != b"\r\n":
                raise ConnectionError("truncated RESP bulk string")
            return value.decode("utf-8", "replace")
        if marker == b"*":
            count = int(self._line())
            if count == -1:
                return None
            return [self._frame() for _ in range(count)]
        raise ConnectionError(f"invalid RESP marker: {marker!r}")

    def command(self, *parts: str) -> RespValue:
        """Send one command and return its fully parsed RESP2 value."""
        payload = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            encoded = part.encode()
            payload.extend((f"${len(encoded)}\r\n".encode(), encoded, b"\r\n"))
        self.connection.sendall(b"".join(payload))
        return self._frame()


class RedisSettingError(ConnectionError):
    """CONFIG GET returned a value outside the expected key/value shape."""

    def __init__(self, name: str, response: RespValue) -> None:
        self.name = name
        self.response = response
        super().__init__(f"CONFIG GET {name} returned an unexpected response: {response!r}")


def classify_save(response: RespValue) -> str:
    """Classify an explicit Redis EROFS, read-only, or permission-denied response as hardened evidence."""
    if isinstance(response, str) and response.startswith("ERROR:"):
        message = response.removeprefix("ERROR:")
        if ("Read-only file system" in message and "EROFS" in message) or "Read-only file system" in message or "Permission denied" in message:
            return "HARDENED"
    if response == "OK":
        return "WRITE_SUCCEEDED"
    return "INCONCLUSIVE"


def redis_setting(client: RedisClient, name: str) -> str:
    result = client.command("CONFIG", "GET", name)
    if not isinstance(result, list) or len(result) != 2 or not isinstance(result[1], str):
        raise RedisSettingError(name, result)
    return result[1]


def run(host: str, port: int, timeout: float, filesystem_probe: bool) -> int:
    """Run read-only baseline checks or an explicitly authorized test-file probe."""
    try:
        with RedisClient(host, port, timeout) as client:
            ping = client.command("PING")
            print(f"PING response: {ping!r}")
            if ping != "PONG":
                print("Outcome: INCONCLUSIVE (Redis did not return PONG)")
                return 20
            if not filesystem_probe:
                print("Outcome: PASS (read-only connectivity check; no enforcement claim)")
                return 0
            original_dir = redis_setting(client, "dir")
            original_filename = redis_setting(client, "dbfilename")
            target_id = secrets.token_hex(8)
            target = Path(TEST_DIRECTORY) / f"sysdhardener-test-{target_id}.rdb"
            before = target.exists() or target.is_symlink()
            if before:
                print("Outcome: INCONCLUSIVE (generated test target unexpectedly exists)")
                return 20
            target_directory = str(target.parent)
            target_filename = target.name
            responses: dict[str, RespValue] = {"PING": ping}
            outcome = "INCONCLUSIVE"
            try:
                responses["CONFIG SET dir"] = client.command("CONFIG", "SET", "dir", target_directory)
                if responses["CONFIG SET dir"] == "OK":
                    responses["CONFIG SET dbfilename"] = client.command(
                        "CONFIG", "SET", "dbfilename", target_filename
                    )
                    if responses["CONFIG SET dbfilename"] == "OK":
                        responses["SAVE"] = client.command("SAVE")
                        outcome = classify_save(responses["SAVE"])
            finally:
                try:
                    restore_dir = client.command("CONFIG", "SET", "dir", original_dir)
                except (OSError, TimeoutError, ConnectionError) as error:
                    restore_dir = f"ERROR:{type(error).__name__}: {error}"
                try:
                    restore_filename = client.command("CONFIG", "SET", "dbfilename", original_filename)
                except (OSError, TimeoutError, ConnectionError) as error:
                    restore_filename = f"ERROR:{type(error).__name__}: {error}"
            after = target.exists() or target.is_symlink()
            if restore_dir != "OK" or restore_filename != "OK":
                outcome = "INCONCLUSIVE"
                print("Restoration failed; Redis configuration may remain changed.")
            if outcome == "HARDENED" and (before or after):
                outcome = "INCONCLUSIVE"
            if outcome == "WRITE_SUCCEEDED" and not after:
                outcome = "INCONCLUSIVE"
            evidence = {
                "commands": responses,
                "original": {"dir": original_dir, "dbfilename": original_filename},
                "target": str(target),
                "target_existed_before": before,
                "target_exists_after": after,
                "restoration": {"dir": restore_dir, "dbfilename": restore_filename},
                "outcome": outcome,
            }
            print(json.dumps(evidence, sort_keys=True))
            print(f"Outcome: {outcome}; file creation is not host-compromise evidence")
            return {"HARDENED": 0, "WRITE_SUCCEEDED": 1, "INCONCLUSIVE": 20}[outcome]
    except ConnectionRefusedError as error:
        print(f"Outcome: SKIP (Redis service is not listening: {error})", file=sys.stderr)
        return 10
    except (OSError, TimeoutError, ConnectionError, ValueError) as error:
        print(f"Outcome: INCONCLUSIVE ({type(error).__name__}: {error})", file=sys.stderr)
        return 20


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--disposable-environment", action="store_true")
    parser.add_argument("--filesystem-probe", action="store_true")
    args = parser.parse_args()
    if args.filesystem_probe and not args.disposable_environment:
        parser.error("--filesystem-probe requires --disposable-environment")
    if not args.disposable_environment:
        print("Outcome: SKIP (no contact made; pass --disposable-environment in the authorized VM)")
        return 10
    return run(args.host, args.port, args.timeout, args.filesystem_probe)


if __name__ == "__main__":
    sys.exit(main())
