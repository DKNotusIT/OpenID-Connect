from flask import request, abort
from oidc.connection import JwtValidator
from oidc.client import Client
from functools import wraps
import json


def open_id_connect_helper(application):
    if application.config['open_id_connect']:
        oidc_config = json.loads(
            open(application.config['open_id_connect_config_path']).read())
        oidc_config['verify_ssl_certificate'] = application.config[
            'verify_ssl_certificate']

        jwt_validator = JwtValidator(oidc_config)
        oidc_client = Client(oidc_config)

        def id_token_authorized(api_method):
            @wraps(api_method)
            def authorized(*args, **kwargs):
                id_token = request.headers.get('Authorization')

                if id_token is None:
                    abort(400, 'Missing Authorization header')
                try:
                    jwt_validator.validate(
                        id_token,
                        oidc_config['issuer'],
                        oidc_config['client_id']
                    )

                except Exception as e:
                    abort(401, str(e))
                else:
                    return api_method(*args, **kwargs)

            return authorized

        application.id_token_authorized = id_token_authorized

        def access_token_authorized(api_method):
            @wraps(api_method)
            def authorized(*args, **kwargs):
                access_token = request.headers.get('Authorization')

                if access_token is None:
                    abort(400, 'Missing Authorization header')
                try:
                    application.user_info = oidc_client.get_user_info(
                        access_token,
                        application.config['service_name']
                    )
                except Exception as e:
                    application.logger.error(str(e))
                    return {'message': 'HTTP Error 401: Authorization'}, 401
                else:
                    return api_method(*args, **kwargs)

            return authorized

        application.access_token_authorized = access_token_authorized
    else:
        application.access_token_authorized = lambda x: x
