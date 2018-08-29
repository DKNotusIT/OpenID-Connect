import json
from time import time
from jwkest.jws import JWS
from jwkest.jwk import KEYS
from requests import request
from .helpers.oidc import decode_token


class JwtValidatorException(Exception):
    pass


class JwtValidator:
    def __init__(self, config):
        self.verify_ssl_server = (
                'verify_ssl_server' in config and
                config['verify_ssl_server']
        )
        self.jwks_url = config['jwks_uri']
        self.jwks = self.load_keys()
        self.issuer = config['issuer']
        self.client_id = config['client_id']

    def validate(self, jwt, iss, aud):
        header, payload = (json.loads(x) for x in decode_token(jwt))
        if 'iss' not in payload or iss != payload['iss']:
            raise JwtValidatorException('Invalid issuer')
        if 'aud' not in payload or aud != payload['aud']:
            raise JwtValidatorException('Invalid audience')
        if time() > payload['exp']:
            raise JwtValidatorException('JWT expired!')
        jws = JWS(alg=header['alg'])
        # Raises exception when signature is invalid
        try:
            jws.verify_compact(jwt, self.jwks)
        except Exception as e:
            raise JwtValidatorException(e)

    def get_jwks_data(self):
        req = request(
            'GET',
            self.jwks_url,
            allow_redirects=False,
            verify=self.verify_ssl_server,
            headers={'Accept': 'application/json'}
        )

        if req.status_code == 200:
            return req.text
        else:
            raise Exception('HTTP Get error: {}'.format(req.status_code))

    def load_keys(self):
        # load the jwk set.
        jwks = KEYS()
        jwks.load_jwks(self.get_jwks_data())
        return jwks
