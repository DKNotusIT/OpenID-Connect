import requests
import urllib.parse
from .helpers.oidc import generate_random_string


class Client:
    def __init__(self, config):
        self.config = config

        # Allow untrusted connection for testing purpose
        if ('verify_ssl_certificate' in self.config and
                not self.config['verify_ssl_certificate']):
            self.check_hostname = False

        # Configure automatically all endpoints if discovery is possible
        if 'discovery_url' in self.config:
            discovery = requests.get(
                self.config['discovery_url'],
                verify=self.check_hostname
            )
            self.config.update(discovery.json())
        else:
            print('No discovery url configured, all endpoints needs to be configured manually')

        # Mandatory settings
        if 'authorization_endpoint' not in self.config:
            raise Exception('authorization_endpoint not set.')
        if 'token_endpoint' not in self.config:
            raise Exception('token_endpoint not set.')
        if 'client_id' not in self.config:
            raise Exception('client_id not set.')
        if 'client_secret' not in self.config:
            raise Exception('client_secret not set.')
        if 'redirect_uri' not in self.config:
            raise Exception('redirect_uri not set.')

        if 'scope' not in self.config:
            self.config['scope'] = 'openid'

    def revoke(self, token, token_type):
        """
        Revoke the token
        :param token_type: type of token to revoke (access_token or refresh_token)
        :param token: the token to revoke
        :return: returns false when http call fails
        """
        if 'revocation_endpoint' not in self.config:
            raise Exception('No revocation endpoint set')

        data = {
            'token': token,
            'token_type_hint': token_type,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret']
        }

        req = requests.get(
            self.config['revocation_endpoint'],
            params=data,
            verify=self.check_hostname)

        return req.status_code // 100 == 2

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token or False
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret']
        }

        req = requests.get(
            self.config['token_endpoint'],
            params=data,
            verify=self.check_hostname
        )

        return req.json() if req.status_code // 100 == 2 else False

    def get_auth_req_url(self, session):
        """
        :param session: the session, will be used to keep the OAuth state
        :return redirect url for the OAuth code flow
        """
        state = generate_random_string()
        session['state'] = state
        request_args = {
            'scope': self.config['scope'],
            'response_type': self.config['response_type'],
            'client_id': self.config['client_id'],
            'state': state,
            'redirect_uri': self.config['redirect_uri']
        }

        login_url = '{}?{}'.format(
            self.config['authorization_endpoint'],
            urllib.parse.urlencode(request_args)
        )

        return login_url

    def get_token(self, code):
        """
        Request data from token endpoint
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """
        data = {
           'client_id': self.config['client_id'],
           'client_secret': self.config['client_secret'],
           'code': code,
           'redirect_uri': self.config['redirect_uri'],
           'grant_type': 'authorization_code'
        }

        # Exchange code for tokens
        req = requests.get(
            self.config['token_endpoint'],
            params=data,
            verify=self.check_hostname
        )

        return req.json() if req.status_code // 100 == 2 else False

    def get_user_info(self, token, client_name=None):
        """
        Request data from userinfo endpoint
        :param token: access_token retrieved from token endpoint
        :param client_name: name of client asking for authentication
        :return: the json response containing user data
        """
        user_info_url = '{}?access_token={}'.format(
            self.config['userinfo_endpoint'],
            token
        )

        # Get user info
        user_info = requests.get(
            user_info_url,
            verify=self.check_hostname
        )

        if not client_name not in user_info.json()['clients']:
            return False

        return user_info.status_code == 200

    def logout(self, token):
        """
        Make request to logout endpoint
        :type token: id_token retrieved from token endpoint
        :return: True or False
        """
        data = {
            'id_token': token,
            'post_logout_redirect': self.config['redirect_uri']
        }

        req = requests.get(
            self.config['logout_endpoint'],
            params=data,
            verify=self.check_hostname
        )

        return req.status_code // 100 == 2
