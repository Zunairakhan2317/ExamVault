"""Unit tests for Excel variant parser and dynamic copy generation (Plan Layer 3)."""
from __future__ import annotations

from pathlib import Path
from tracing.parser import parse_exam_excel
from tracing.copygen import assemble_dynamic_copy
from tracing.codes import generate_dynamic_codes


def test_parser_and_copygen_with_excel():
    excel_path = Path("Demo Exam.xlsx")
    if not excel_path.exists():
        return  # Skip if Excel fixture not present in working directory
        
    slots = parse_exam_excel(excel_path)
    assert len(slots) > 0
    
    codes = generate_dynamic_codes(num_users=2, slots=slots)
    assert len(codes) == 2
    
    copy_text = assemble_dynamic_copy(slots, codes[0])
    assert len(copy_text) > 0
    assert "Slot 1" in copy_text