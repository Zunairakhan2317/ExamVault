"""Smoke test for the terminal paper lifecycle demo."""

from pathlib import Path

import pytest

from crypto.services import paper_service
from demo.paper_cli import main


def test_cli_demo_creates_and_releases_exam(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI completes exam creation, share wrapping, and threshold release."""
    monkeypatch.setattr(paper_service, "DATABASE_PATH", tmp_path / "cli-demo.sqlite3")

    assert main() == 0

    output = capsys.readouterr().out
    assert "Creating an exam for three holders" in output
    assert "wrapped shares; threshold 2" in output
    assert "Exam released successfully" in output
    assert "sample exam content" not in output