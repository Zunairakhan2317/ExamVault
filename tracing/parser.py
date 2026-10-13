"""Parses uploaded Excel files containing variant template strings (Dynamic Slots)."""
from __future__ import annotations

import re
from pathlib import Path
import pandas as pd


def parse_exam_excel(file_path: Path | str) -> list[dict]:
    """
    Parses an Excel file containing questions with {opt1 | opt2 | opt3} syntax.
    Returns a list of variant slots with dynamic choices supporting any number of variants.
    """
    xls = pd.ExcelFile(file_path)
    sheet_name = xls.sheet_names[0]
    df = pd.read_excel(file_path, sheet_name=sheet_name)
    
    # Normalize headers based on row content if needed
    if str(df.iloc[0, 0]).strip().lower() in ["number", "no", "#"]:
        df.columns = ["number", "question", "marks"]
        df = df.iloc[1:].reset_index(drop=True)
    else:
        df.columns = ["number", "question", "marks"]

    slots = []
    slot_id = 1

    # Regex to find bracketed variant groups like {opt1 | opt2 | opt3}
    pattern = re.compile(r"\{([^}]+)\}")

    for _, row in df.iterrows():
        q_text = str(row["question"])
        marks_raw = str(row["marks"])
        
        marks_match = re.search(r"\d+", marks_raw)
        marks = int(marks_match.group()) if marks_match else 1

        matches = pattern.findall(q_text)
        if not matches:
            continue

        for group_idx, match in enumerate(matches):
            variants = [v.strip() for v in match.split("|")]
            slots.append({
                "slot_id": slot_id,
                "question_no": str(row["number"]),
                "group_index": group_idx,
                "variants": variants,
                "marks": marks
            })
            slot_id += 1

    return slots