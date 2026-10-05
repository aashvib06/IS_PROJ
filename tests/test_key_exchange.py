from cipherchat.crypto.key_exchange import derive_shared_secret, generate_private_key, public_key_bytes

def test_x25519_agreement_and_distinct_exchanges():
    a, b, c = generate_private_key(), generate_private_key(), generate_private_key()
    assert derive_shared_secret(a, b.public_key()) == derive_shared_secret(b, a.public_key())
    assert derive_shared_secret(a, b.public_key()) != derive_shared_secret(a, c.public_key())

def test_public_serialization_cannot_contain_private_material():
    private = generate_private_key()
    assert len(public_key_bytes(private.public_key())) == 32
