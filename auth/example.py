import uuid

from auth import crypt
from auth import config as cfg


class FoobarStorage:
    def __init__(self):
        self.user_by_id = {}
        self.user_by_email = {}

    def signup(self, email, password):
        if email in self.user_by_email:
            raise ValueError(
                'User with email {} already exists.'.format(email),
            )

        user_id = str(uuid.uuid4())
        key = crypt.get_key(password)

        user = {
            cfg.FIELD_USER_ID: user_id,
            cfg.FIELD_EMAIL: email,
            cfg.FIELD_KEY: key,
        }
        self.user_by_id[user_id] = user
        self.user_by_email[email] = user

    def signin(self, email, password):
        msg = 'No such user or wrong password.'

        if email not in self.user_by_email:
            raise ValueError(msg)
        user = self.user_by_email[email]

        valid = crypt.verify_password(
            password,
            user[cfg.FIELD_KEY],
        )

        if not valid:
            raise ValueError(msg)

        acc = crypt.get_access_token(user[cfg.FIELD_USER_ID])
        ref = crypt.get_refresh_token(acc)

        return acc, ref


users = FoobarStorage()

users.signup('boka@boka.xyz', 'p@ssw0rd')
users.signup('zhoka@zhoka.xyz', '1234567')
users.signup('lupa@lupa.xyz', 'gfhjkm')
users.signup('pupa@pupa.xyz', 'nsytghjqltim123123')

print('Users in storage:')
for user in users.user_by_id.values():
    print(user[cfg.FIELD_USER_ID], user[cfg.FIELD_EMAIL], user[cfg.FIELD_KEY])

email = 'zhoka@zhoka.xyz'
acc, ref = users.signin(email, '1234567')

print()
print('Access token:')
print(acc, '\n')
print('Refresh token:')
print(ref, '\n')

# 0. All authenticated requests must include access token.

# Authorization could be easily performed web-server side
# in case asymmetric encryption is used.
# crypt.decode_token returns None when a token invalid or expired.

user = users.user_by_email[email]
acc_claims = crypt.decode_token(acc)

# Authorized token
assert acc_claims[cfg.FIELD_USER_ID] == user[cfg.FIELD_USER_ID]

print('Access token content:')
print(acc_claims, '\n')

# 1. In case access token is expired,
# you should send refresh token to get new tokens pair.

print('Refresh token content:')
print(crypt.decode_token(ref), '\n')

# 2. In case both of them are expired user should be followed to sign in.

# *
# In production authentication server should be extracted to separate process
# which only one holds private key.
# Public key can be even disclosed on client side
# for preventive client-side checks against token expiration.
