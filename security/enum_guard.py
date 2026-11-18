"""Account-enumeration defenses shared by every auth-facing endpoint.

Login, password reset, OAuth callback, registration and captcha flows all
leak account existence if any observable signal — HTTP status, message
text, error code, response size, timing, lockout behavior or email identity
— differs between "user exists" and "user does not exist". The helpers in
this module encode one uniform contract for all of those flows:

1.  uniform_status      — 统一状态码（存在/不存在都返回 401，绝不返回 404）
2.  uniform_message     — 统一提示语（不区分“用户不存在”与“密码错误”）
3.  pad_timing          — 响应时间填充（快速路径补齐到固定耗时下限）
4.  lock_applies        — 锁定覆盖不存在账号（失败计数对所有标识生效）
5.  normalize_email     — 邮箱归一（小写化 + 去除 +tag 别名）
6.  build_auth_response — 回调统一 / 注册查重脱敏（同一信封，同一输出）
7.  uniform_error_code  — 错误码粗化（只暴露一个粗粒度错误码）
8.  captcha_required    — 验证码统一（无论账号是否存在都要求）
9.  固定响应长度         — build_auth_response 将报文填充到 FIXED_BODY_LENGTH
"""

import json
import time

# 所有凭据类失败共用同一个状态码 / 提示语 / 错误码，与账号是否存在无关。
GENERIC_AUTH_STATUS = 401
GENERIC_AUTH_MESSAGE = 'invalid credentials'
GENERIC_AUTH_CODE = 'auth_failed'

# 固定响应体长度（字节）：填充使响应长度不随账号存在与否变化。
FIXED_BODY_LENGTH = 256


def uniform_status(exists):
    """Return the same HTTP status whether or not the account exists.

    A missing user must never produce 404 while a real user produces 401;
    every credential failure is answered with the generic 401 so the status
    line carries no existence information.
    """
    return GENERIC_AUTH_STATUS


def uniform_message(exists):
    """Return the same generic message whether or not the account exists.

    A constant string simultaneously fixes message-content and
    response-length enumeration (both branches serialize to the same
    number of bytes).
    """
    return GENERIC_AUTH_MESSAGE


def uniform_error_code(exists):
    """Return one coarse error code instead of reason-specific codes.

    Fine-grained codes such as ``user_not_found`` / ``bad_password`` /
    ``account_locked`` are merged into a single code so error responses
    cannot be used to distinguish failure reasons.
    """
    return GENERIC_AUTH_CODE


def pad_timing(elapsed, minimum):
    """Burn the remainder of ``minimum`` seconds when a path finished early.

    The missing-account path normally returns faster (no password hash to
    verify, no reset email to render and send), which is itself an
    enumeration oracle. Callers measure the work already done and pass it
    here; fast paths sleep off the difference while paths already over
    budget return immediately. Returns the effective elapsed time.
    """
    remaining = minimum - elapsed
    if remaining > 0:
        time.sleep(remaining)
    return max(elapsed, minimum)


def normalize_email(email):
    """Canonicalize an email so case and ``+alias`` variants share an identity.

    Lowercases local part and domain and strips a ``+tag`` alias, so
    ``A@X.COM``, ``a@x.com`` and ``a+tag@x.com`` all resolve to the same
    account — and therefore the same lockout/rate-limit record, including
    for accounts that do not exist.
    """
    if not email:
        return ''
    local, separator, domain = email.partition('@')
    if not separator:
        return email.strip().lower()
    local = local.split('+', 1)[0]
    return local.lower() + '@' + domain.lower()


def lock_applies(exists):
    """Whether failure counting / lockout applies — always ``True``.

    Locking only real accounts lets an attacker enumerate usernames by
    observing which identifiers ever lock. Failures are recorded against
    the normalized identifier regardless of existence, so a non-existent
    account locks (and is rejected) exactly like a real one.
    """
    return True


def captcha_required(exists):
    """Whether a captcha challenge is required — always ``True``.

    Demanding a captcha only for existing accounts would expose account
    state in the challenge flow; the requirement is unconditional.
    """
    return True


def build_auth_response(exists):
    """Build the uniform response envelope used by every auth flow.

    Login, password reset, third-party login callback and registration
    duplicate-check all return this same envelope: identical status,
    coarse error code, generic message, and a body padded to
    :data:`FIXED_BODY_LENGTH` so byte-length cannot distinguish accounts
    or failure reasons either.
    """
    body = json.dumps(
        {
            'error': GENERIC_AUTH_CODE,
            'message': GENERIC_AUTH_MESSAGE,
        },
        separators=(',', ':'),
    ).encode('utf-8')
    padding = max(0, FIXED_BODY_LENGTH - len(body))
    return {
        'status': GENERIC_AUTH_STATUS,
        'body': body + b' ' * padding,
    }
