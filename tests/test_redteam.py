"""Red-team script (plan 7.3): all 14 attacks are caught, and a successful attack is reported as FAIL."""
from __future__ import annotations

from crypto import feldman
from demo import redteam


def test_all_14_attacks_are_caught_and_the_report_is_written(tmp_path):
    report = tmp_path / "redteam_report.md"
    assert redteam.main(["--report", str(report)]) == 0
    text = report.read_text(encoding="utf-8")
    assert "14 of 14 attacks caught" in text
    assert all(f"| A{number} |" in text for number in range(1, 15))
    assert "FAIL" not in text.split("## Honest notes")[0]


def test_a_successful_attack_makes_the_script_fail(tmp_path, monkeypatch):
    """If Feldman verification were broken (accepts anything), A14 must be reported FAIL and the exit code non-zero."""
    monkeypatch.setattr(feldman, "verify_share", lambda *args, **kwargs: True)
    report = tmp_path / "broken.md"
    assert redteam.main(["--report", str(report), "--trials", "20"]) == 1
    text = report.read_text(encoding="utf-8")
    assert "**FAIL (not caught)**" in text
    row = next(line for line in text.splitlines() if line.startswith("| A14 |"))
    assert "FAIL" in row


def test_every_attack_reports_what_it_tried_and_what_the_system_did():
    results = redteam.run_all(trials=20)
    assert [r.code for r in results] == [f"A{n}" for n in range(1, 15)]
    assert all(r.tried and r.system and r.title for r in results)
