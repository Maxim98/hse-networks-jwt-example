import secrets
import hashlib
import base64
import json
import datetime

import jwt

import auth.config as cfg


# Takes digest from password with pbkdf2
def get_key(password):
    salt = secrets.token_bytes(cfg.PBKDF2_KEY_LENGTH)

    digest = hashlib.pbkdf2_hmac(
        cfg.PBKDF2_DIGEST_ALG,
        bytes(password, 'utf-8'),
        salt,
        cfg.PBKDF2_ITERATIONS,
        cfg.PBKDF2_KEY_LENGTH,
    )
    parts = [
        cfg.PBKDF2_DIGEST_ALG,
        salt.hex(),
        digest.hex(),
        str(cfg.PBKDF2_ITERATIONS),
    ]

    return cfg.PBKDF2_DELIMITER.join(parts)


# Verifies password with user key
def verify_password(password, key):
    alg, salt, digest, iterations = key.split(cfg.PBKDF2_DELIMITER)
    digest = bytes.fromhex(digest)
    iterations = int(iterations)

    digest_ = hashlib.pbkdf2_hmac(
        alg,
        bytes(password, 'utf-8'),
        bytes.fromhex(salt),
        iterations,
        len(digest),
    )

    return digest == digest_


# Creates web token
def get_token(claims, expires_in=0):
    claims = json.loads(json.dumps(claims))
    claims['exp'] = (
        datetime.datetime.utcnow()
        + datetime.timedelta(seconds=expires_in)
    )

    return jwt.encode(
        claims,
        base64.decodebytes(cfg.JWT_PRIVATE_KEY.encode('utf-8')),
        cfg.JWT_ALGORITHM,
    ).decode('utf-8')


# Creates access token
def get_access_token(user_id):
    return get_token(
        {cfg.FIELD_USER_ID: user_id},
        cfg.JWT_ACCESS_EXPIRATION_SECONDS,
    )

# Creates refresh token
def get_refresh_token(access_token):
    return get_token(
        {cfg.FIELD_ACCESS_TOKEN: access_token},
        cfg.JWT_REFRESH_EXPIRATION_SECONDS,
    )


# Verifies web token
def decode_token(token, verify=True):
    try:
        return jwt.decode(
            token,
            base64.decodebytes(cfg.JWT_PUBLIC_KEY.encode('utf-8')),
            algorithms=[cfg.JWT_ALGORITHM],
            leeway=cfg.JWT_TOLERANCE_SECONDS,
            verify=verify,
        )
    except jwt.exceptions.PyJWTError:
         return

