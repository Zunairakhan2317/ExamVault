"""Run a terminal demonstration of ExamVault's threshold paper workflow."""

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from auth.schnorr import generate_schnorr_keypair, generate_schnorr_proof, verify_schnorr_proof
from crypto.services import paper_service

_SAMPLE_PAPER = b"ExamVault CLI demo: confidential sample exam content."


def main() -> int:
    """Demonstrate encrypted exam creation and threshold-authorized release with Schnorr ZKP."""
    holder_private_keys = [
        rsa.generate_private_key(public_exponent=65537, key_size=3072)
        for _ in range(3)
    ]
    holder_public_keys = [key.public_key() for key in holder_private_keys]
    
    # Generate Schnorr keypair for the holder demonstrating ZKP
    schnorr_x, schnorr_y = generate_schnorr_keypair()
    nonce = "cli-test-nonce-999"
    timestamp = "2026-10-09T12:00:00Z"
    t_val, s_val = generate_schnorr_proof(schnorr_x, schnorr_y, nonce, timestamp)
    assert verify_schnorr_proof(schnorr_y, t_val, s_val, nonce, timestamp) is True
    print("Schnorr ZKP verification passed in CLI demo.")

    admin_private_key = ed25519.Ed25519PrivateKey.generate()
    admin_public_key = admin_private_key.public_key()
    window_now = datetime.now(timezone.utc)

    print("Creating an exam for three holders...")
    exam = paper_service.create_exam(
        _SAMPLE_PAPER,
        holder_public_keys,
        admin_private_key,
        window_now - timedelta(minutes=1),
        window_now + timedelta(hours=1),
    )
    print(
        f"Exam created: {exam['exam_id']} "
        f"({exam['num_shares']} wrapped shares; threshold {exam['threshold']})"
    )

    threshold = exam["threshold"]
    released_paper = paper_service.release_exam(
        exam["exam_id"],
        exam["wrapped_shares"][:threshold],
        holder_private_keys[:threshold],
        admin_public_key,
    )
    if released_paper != _SAMPLE_PAPER:
        print("Exam release failed: recovered content did not match.")
        return 1

    print("Exam released successfully; recovered content matches the sample.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())