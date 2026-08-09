import importlib.util
import os
import pathlib
import subprocess
import unittest


SCRIPT = pathlib.Path(__file__).with_name("demo.py")


class DemoTests(unittest.TestCase):
    def test_normalize_transcript_replaces_loopback_ports(self):
        spec = importlib.util.spec_from_file_location("demo", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        text = "upstream=http://127.0.0.1:43821/mcp gateway=http://127.0.0.1:51234/mcp"
        self.assertEqual(
            module.normalize_transcript(text),
            "upstream=http://127.0.0.1:<PORT>/mcp gateway=http://127.0.0.1:<PORT>/mcp",
        )

    def test_render_artifact_is_stable_and_contains_verified_result(self):
        spec = importlib.util.spec_from_file_location("demo", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        artifact = module.render_artifact(
            client_body='{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"gateway-demo-ok"}]}}',
            audit_status=202,
            audit_result="success",
        )
        self.assertIn("gateway-demo-ok", artifact)
        self.assertIn("HTTP status: `202`", artifact)
        self.assertIn("Audit result: `success`", artifact)
        self.assertNotIn("mcp-gateway-local-demo-value", artifact)

    def test_read_line_with_deadline_does_not_hang_on_silent_process(self):
        spec = importlib.util.spec_from_file_location("demo", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, "r", encoding="utf-8") as stream:
                with self.assertRaisesRegex(RuntimeError, "output before the deadline"):
                    module.read_line_with_deadline(stream, 0.01)
        finally:
            os.close(write_fd)

    def test_stop_process_does_not_abort_cleanup_if_killed_child_cannot_be_reaped(self):
        spec = importlib.util.spec_from_file_location("demo", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class StuckProcess:
            def __init__(self):
                self.killed = False

            def poll(self):
                return None

            def send_signal(self, _signal):
                return None

            def wait(self, timeout):
                raise subprocess.TimeoutExpired("fixture", timeout)

            def kill(self):
                self.killed = True

        process = StuckProcess()
        module.stop_process(process)
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
