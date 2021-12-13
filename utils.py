import jwt
import requests
from simplejson import JSONDecodeError
import env
import ldap
from datetime import datetime, timedelta
import sys
from access.user.models import User
from access.active_directory.models import ActiveDirectory
from sqlalchemy.exc import SQLAlchemyError


def validate_authentication(email, password, active_directory):
    user = User.query.get(email)
    ad = ActiveDirectory.query.get(active_directory)

    if ad is not None:

        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.protocol_version = 3

        l_server = ldap.initialize(ad.server)
        try:
            l_server.set_option(ldap.OPT_REFERRALS, 0)
            l_server.simple_bind_s(email, password)

            if user is None:
                result = l_server.search_s(ad.base, ldap.SCOPE_SUBTREE, ad.filter, ad.attr)

                results = [entry for dn, entry in result if isinstance(entry, dict)]

                final_data = []

                for i in results:
                    attributes = {}
                    for j in ad.attr:
                        if len(i.get(j, {})) > 0:
                            attributes[j] = i.get(j, {})[0].decode('utf-8')

                    final_data.append(attributes)

                new_user = {}
                for i in final_data:
                    if i.get('mail', None) == email or i.get('email', None) == email:
                        new_user = {
                            'user_email': i.get('mail', None) if i.get('mail', None) == email else i.get('email',
                                                                                                         None),
                            'name': i.get('displayName', None)
                        }
                try:
                    User(new_user)
                except SQLAlchemyError:
                    pass

            return True
        except ldap.INVALID_CREDENTIALS:
            l_server.unbind()
            return False
    else:
        return False


def make_jwt(package):
    return jwt.encode(
        package,
        env.AUTHORIZATION_TOKEN,
        algorithm='HS256'
    )


def decrypt_jwt(token, has_exp=True):
    try:
        token = jwt.decode(
            token,
            key=env.AUTHORIZATION_TOKEN,
            algorithms='HS256',
            options={
                'verify_exp': has_exp
            }
        )

        return token
    except (jwt.exceptions.DecodeError,
            jwt.exceptions.InvalidTokenError,
            jwt.exceptions.ExpiredSignatureError):
        return None
