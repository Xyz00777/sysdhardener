"""Given/When/Then tests for the safe Redis demo runner."""

from __future__ import annotations

import socket
import contextlib
import io
import threading
import unittest
from unittest.mock import patch

from run_test import RedisClient, classify_save, run


class MockRespServer:
    """A local RESP peer which can fragment replies and capture commands."""

    def __init__(self, replies: list[bytes], fragment: bool = False) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.address = self.listener.getsockname()
        self.replies = replies
        self.fragment = fragment
        self.commands: list[bytes] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        with connection:
            stream = connection.makefile("rb")
            if not self.replies:
                count = int(stream.readline()[1:-2])
                for _ in range(count):
                    size = int(stream.readline()[1:-2])
                    stream.read(size)
                    stream.read(2)
                stream.read(1)
                return
            for reply in self.replies:
                count = int(stream.readline()[1:-2])
                parts = []
                for _ in range(count):
                    size = int(stream.readline()[1:-2])
                    parts.append(stream.read(size))
                    stream.read(2)
                self.commands.append(b" ".join(parts))
                if self.fragment:
                    for byte in reply:
                        connection.sendall(bytes((byte,)))
                else:
                    connection.sendall(reply)

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=2)


class RespClientTests(unittest.TestCase):
    def test_fragmented_complete_frames_parse(self) -> None:
        # Given a RESP server that sends each response byte separately
        server = MockRespServer([b"+OK\r\n", b"$5\r\nvalue\r\n"], fragment=True)
        try:
            # When commands are read through the complete-frame client
            with RedisClient(*server.address, timeout=1) as client:
                first = client.command("PING")
                second = client.command("GET", "key")
            # Then both frames remain distinct and complete
            self.assertEqual((first, second), ("OK", "value"))
        finally:
            server.close()

    def test_timeout_is_not_a_hardened_result(self) -> None:
        # Given a SAVE response which never arrives
        server = MockRespServer([])
        try:
            # When the bounded client waits for the response
            with RedisClient(*server.address, timeout=0.05) as client:
                with self.assertRaises(TimeoutError):
                    client.command("SAVE")
            # Then timeout remains an error, not enforcement evidence
        finally:
            server.close()

    def test_missing_service_is_skip(self) -> None:
        # Given the reserved loopback port zero with no Redis listener
        # When the opted-in probe attempts that endpoint
        with contextlib.redirect_stderr(io.StringIO()):
            result = run("127.0.0.1", 0, 1, False)
        # Then the service absence has the documented distinct SKIP status
        self.assertEqual(result, 10)

    def test_authentication_error_is_inconclusive(self) -> None:
        # Given a Redis endpoint requiring authentication
        server = MockRespServer([b"-NOAUTH authentication required\r\n"])
        try:
            # When the read-only probe sends PING
            with contextlib.redirect_stdout(io.StringIO()):
                result = run(*server.address, 1, False)
            # Then authentication failure is inconclusive, not a pass
            self.assertEqual(result, 20)
        finally:
            server.close()

    def test_config_set_rejection_is_inconclusive_and_restores(self) -> None:
        # Given CONFIG SET rejection after the original settings are captured
        server = MockRespServer([
            b"+PONG\r\n",
            b"*2\r\n$3\r\ndir\r\n$5\r\n/data\r\n",
            b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n",
            b"-ERR CONFIG SET denied\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
        ])
        try:
            # When the opt-in probe encounters the config policy error
            with patch("run_test.TEST_DIRECTORY", "/tmp"), contextlib.redirect_stdout(io.StringIO()):
                result = run(*server.address, 1, True)
            # Then it stays inconclusive and attempts restoration of both values
            self.assertEqual(result, 20)
            self.assertEqual(server.commands[-2:], [b"CONFIG SET dir /data", b"CONFIG SET dbfilename dump.rdb"])
        finally:
            server.close()

    def test_config_error_is_inconclusive(self) -> None:
        # Given a server rejecting CONFIG due to authentication or policy
        # When the outcome classifier sees that response
        # Then it never calls the outcome hardened
        self.assertEqual(classify_save("ERROR:NOAUTH authentication required"), "INCONCLUSIVE")

    def test_only_evidenced_erofs_is_hardened(self) -> None:
        # Given one EROFS diagnostic and one unexplained SAVE error
        # When each response is classified
        # Then only the specific OS-level EROFS evidence is hardened
        self.assertEqual(classify_save("ERROR:ERR Read-only file system (EROFS)"), "HARDENED")
        self.assertEqual(classify_save("ERROR:ERR opening file failed"), "INCONCLUSIVE")

    def test_filesystem_probe_restores_configuration(self) -> None:
        # Given a mock Redis with successful config writes and an EROFS SAVE
        responses = [
            b"+PONG\r\n",
            b"*2\r\n$3\r\ndir\r\n$5\r\n/data\r\n",
            b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
            b"-ERR Read-only file system (EROFS)\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
        ]
        server = MockRespServer(responses)
        try:
            with patch("run_test.TEST_DIRECTORY", "/tmp"), contextlib.redirect_stdout(io.StringIO()):
                # When the explicitly enabled probe observes the mock response
                result = run(*server.address, 1, True)
            # Then the result is hardened evidence only after restoring both settings
            self.assertEqual(result, 0)
            self.assertEqual(server.commands[-2:], [b"CONFIG SET dir /data", b"CONFIG SET dbfilename dump.rdb"])
        finally:
            server.close()

    def test_save_ok_without_target_is_inconclusive(self) -> None:
        # Given Redis returns SAVE OK but no test target was written
        server = MockRespServer([
            b"+PONG\r\n",
            b"*2\r\n$3\r\ndir\r\n$5\r\n/data\r\n",
            b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
            b"+OK\r\n",
        ])
        try:
            # When the filesystem probe sees the success reply without a file
            with patch("run_test.TEST_DIRECTORY", "/tmp"), contextlib.redirect_stdout(io.StringIO()):
                result = run(*server.address, 1, True)
            # Then the write claim is withheld and original settings are restored
            self.assertEqual(result, 20)
            self.assertEqual(server.commands[-2:], [b"CONFIG SET dir /data", b"CONFIG SET dbfilename dump.rdb"])
        finally:
            server.close()

    def test_default_invocation_skips_without_network_contact(self) -> None:
        # Given the CLI entrypoint is called without arguments
        from run_test import main
        # When invoked without explicit disposable environment opt-in
        with patch("sys.argv", ["run_test.py"]), contextlib.redirect_stdout(io.StringIO()) as out:
            result = main()
        # Then it immediately skips with exit 10 and makes no network contact
        self.assertEqual(result, 10)
        self.assertIn("SKIP", out.getvalue())


if __name__ == "__main__":
    unittest.main()
