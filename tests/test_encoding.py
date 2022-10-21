import base64
from urllib.parse import unquote_plus, quote_plus


from padding_oracle import (
    base64_encode,
    base64_decode,
    urlencode,
    urldecode,
)


def test_base64_encode():
    plaintext = b'the quick brown fox jumps over the lazy dog'
    expected = base64.b64encode(plaintext).decode()
    assert expected == base64_encode(plaintext)
    assert expected == base64_encode(list(plaintext))
    assert expected == base64_encode(plaintext.decode())


def test_base64_decode():
    plaintext = b'the quick brown fox jumps over the lazy dog'
    encoded = base64.b64encode(plaintext).decode()
    assert plaintext == base64_decode(encoded)
    assert plaintext == base64_decode(encoded.encode())
    assert plaintext == base64_decode(list(encoded.encode()))


def test_urlencode():
    plaintext = 'the quick brown fox jumps over the lazy dog'
    assert plaintext == unquote_plus(urlencode(plaintext))
    assert plaintext == unquote_plus(urlencode(plaintext.encode()))
    assert plaintext == unquote_plus(urlencode(list(plaintext.encode())))


def test_urldecode():
    plaintext = 'the quick brown fox jumps over the lazy dog'
    encoded = quote_plus(plaintext)
    assert plaintext == urldecode(encoded)
    assert plaintext == urldecode(encoded.encode())
    assert plaintext == urldecode(list(encoded.encode()))


if __name__ == '__main__':
    test_base64_encode()
    test_base64_decode()
    test_urlencode()
    test_urldecode()
