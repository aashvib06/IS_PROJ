from cipherchat.crypto.kdf import derive_session_key

def test_kdf_context_domain_separates_keys():
    secret = b"s" * 32
    key = derive_session_key(secret, context=b"one")
    assert key == derive_session_key(secret, context=b"one")
    assert key != derive_session_key(secret, context=b"two")
    assert key != secret
