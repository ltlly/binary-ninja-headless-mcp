from __future__ import annotations

import json
from pathlib import Path

from binary_ninja_headless_mcp.fuzzer import main


def test_feature_fuzzer_runs_with_fake_backend(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    sample_binary = root / "samples" / "ls"
    assert sample_binary.exists()

    report_path = tmp_path / "fuzzer-report.json"
    exit_code = main(
        [
            "--binary",
            str(sample_binary),
            "--fake-backend",
            "--iterations",
            "5",
            "--seed",
            "1234",
            "--report-json",
            str(report_path),
            "--min-success-tools",
            "1",
        ]
    )
    assert exit_code == 0
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["total_tools"] >= 150
    assert report["attempted_tools"] >= 150
    assert report["successful_tools"] >= 1

    unattempted = set(report["unattempted_tools"])
    assert "binary.save" not in unattempted
    assert "binary.get_function_disassembly_at" not in unattempted
    assert "binary.get_function_il_at" not in unattempted
    assert "disasm.function" not in unattempted
