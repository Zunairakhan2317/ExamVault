import pytest


@pytest.fixture(autouse=True)
def _isolated_keys_dir(tmp_path, monkeypatch):
    """Tests must never write into the real keys/ folder.

    Security purpose: a test user (for example "jake") could otherwise overwrite the public key of a real
    holder with the same name, which would silently break that holder's share.
    """
    from web import routes_admin

    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setattr(routes_admin, "KEYS_DIR", keys)
