"""Assembles personalized copy text for each invigilator from parsed dynamic slots (Plan 5.4)."""
from __future__ import annotations


def assemble_dynamic_copy(slots: list[dict], user_code: list[int]) -> str:
    """
    Assemble paper text for an invigilator based on their assigned variant index code 
    mapped against the parsed dynamic slot variants.
    """
    lines = []
    for idx, slot in enumerate(slots):
        variants = slot["variants"]
        variant_idx = user_code[idx % len(user_code)] % len(variants)
        chosen_text = variants[variant_idx]
        slot_id = slot.get("slot_id", idx + 1)
        lines.append(f"Slot {slot_id} (Q{slot.get('question_no')}): {chosen_text}")
    return "\n".join(lines)