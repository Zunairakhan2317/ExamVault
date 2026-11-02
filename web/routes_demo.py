"""Demo pages (plan 7.1): /demo/ecb shows why ExamVault uses AES-GCM and never ECB."""
from __future__ import annotations

from flask import Flask, render_template

from auth.rbac import role_required
from demo import ecb_vs_gcm

ALL_ROLES = ("admin", "examiner", "invigilator", "auditor")


def register(app: Flask) -> None:
    @app.get("/demo/ecb")
    @role_required(*ALL_ROLES)
    def demo_ecb():
        """Encrypt the sample picture with ECB and GCM (fresh random key each visit) and show the difference."""
        result = ecb_vs_gcm.run_demo()
        return render_template(
            "ecb_demo.html",
            original=ecb_vs_gcm.image_data_uri(result["original"]),
            ecb=ecb_vs_gcm.image_data_uri(result["ecb"]),
            gcm=ecb_vs_gcm.image_data_uri(result["gcm"]),
            repeated=result["repeated"],
            tamper=result["tamper"],
        )
