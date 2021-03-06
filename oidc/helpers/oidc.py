import base64
import random
import string


def base64_url_decode(strng):
    strng.replace('-', '+')
    strng.replace('_', '/')
    strng += '=' * (4 - (len(strng) % 4))
    return base64.b64decode(strng)


def decode_token(token):
    """
    Decode a jwt into readable format.

    :param token:
    :return: A decoded jwt
    :raise: Wrong JWT format
    """
    if token and len(token.split('.')) == 3:
        header, payload, signature = token.split('.')

    else:
        raise Exception('This is not jwt token!')

    return (
        base64_url_decode(header).decode('utf-8'),
        base64_url_decode(payload).decode('utf-8')
    )


def generate_random_string():
    """
    :return: a 15 character random string
    using only capital ASCII characters and digits
    """
    return ''.join(random.SystemRandom().choice(
        string.ascii_uppercase +
        string.digits) for _ in range(15))
