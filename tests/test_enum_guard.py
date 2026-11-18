from security.enum_guard import (
    uniform_status,
    uniform_message,
    pad_timing,
    normalize_email,
    lock_applies
)


def test_status_exists():
    assert uniform_status(True) == 401

def test_status_missing():
    assert uniform_status(False) == 401

def test_message_exists():
    assert uniform_message(True) == 'invalid credentials'

def test_message_missing():
    assert uniform_message(False) == 'invalid credentials'

def test_timing():
    assert pad_timing(0.01, 0.1) >= 0.1

def test_email():
    assert normalize_email('A@X.COM') == 'a@x.com'

def test_alias():
    assert normalize_email('a+tag@x.com') == 'a@x.com'

def test_lock_missing():
    assert lock_applies(False) is True

def test_lock_exists():
    assert lock_applies(True) is True

def test_code():
    assert uniform_status(False) == uniform_status(True)

def test_message_same():
    assert uniform_message(False) == uniform_message(True)

def test_empty():
    assert normalize_email('') == ''

def test_safe():
    assert normalize_email('a@x.com') == 'a@x.com'

def test_pad():
    assert pad_timing(0.2, 0.1) >= 0.2

def test_length():
    assert len(uniform_message(True)) == len(uniform_message(False))
