import contextlib
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from grant_effect_audit.collector_cli import main
from grant_effect_audit.core import Verdict


class CollectorCliTests(unittest.TestCase):
    def test_loads_local_adapter_and_writes_private_file_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / "adapter.py"
            adapter.write_text(
                "def create_adapter():\n    return 'trusted local adapter'\n"
            )
            output = Path(directory) / "evidence.json"
            evidence = {"case_id": "local", "controls": []}
            verdict = Verdict(
                "local",
                "no_out_of_grant_effect_observed",
                (),
                "http://127.0.0.1:18761/mcp",
                0,
                3,
            )
            args = [
                "--adapter",
                str(adapter),
                "--output",
                str(output),
                "--case-id",
                "local",
                "--target",
                verdict.target_resource,
                "--transition",
                "refresh-resource-change",
            ]
            with patch(
                "grant_effect_audit.collector_cli.collect",
                return_value=(evidence, verdict),
            ) as run:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args), 0)
                self.assertEqual(run.call_args.args, ("trusted local adapter",))
                self.assertEqual(json.loads(output.read_text()), evidence)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                output.write_text("keep this file")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(args), 64)
                self.assertEqual(output.read_text(), "keep this file")
                self.assertEqual(run.call_count, 1)

    def test_adapter_exception_does_not_print_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / "bad_adapter.py"
            adapter.write_text(
                "def create_adapter():\n"
                "    raise RuntimeError('Bearer sensitive-secret')\n"
            )
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                code = main(
                    [
                        "--adapter",
                        str(adapter),
                        "--output",
                        str(Path(directory) / "evidence.json"),
                        "--case-id",
                        "local",
                        "--target",
                        "http://127.0.0.1:18761/mcp",
                        "--transition",
                        "refresh-resource-change",
                    ]
                )
            self.assertEqual(code, 64)
            self.assertNotIn("sensitive-secret", error.getvalue())


if __name__ == "__main__":
    unittest.main()
