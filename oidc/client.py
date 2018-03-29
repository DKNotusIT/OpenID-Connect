import json
import ssl
import urllib.parse
import urllib.request
from app.infrastructure.oidc.helpers.oidc import generate_random_string


class Client:
    def __init__(self, config):
        self.ctx = ssl.create_default_context()
        self.config = config

        # Allow untrusted connection for testing purpose
        if "verify_ssl_certificate" in self.config and not self.config["verify_ssl_certificate"]:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

        # Configure automatically all endpoints if discovery is possible
        if "discovery_url" in self.config:
            discovery = urllib.request.urlopen(self.config["discovery_url"], context=self.ctx)
            raw_data = discovery.read()
            encoding = discovery.info().get_content_charset("utf8")  # JSON default
            self.config.update(json.loads(raw_data.decode(encoding)))
        else:
            print("No discovery url configured, all endpoints needs to be configured manually")

        # Mandatory settings
        if "authorization_endpoint" not in self.config:
            raise Exception("authorization_endpoint not set.")
        if "token_endpoint" not in self.config:
            raise Exception("token_endpoint not set.")
        if "client_id" not in self.config:
            raise Exception("client_id not set.")
        if "client_secret" not in self.config:
            raise Exception("client_secret not set.")
        if "redirect_uri" not in self.config:
            raise Exception("redirect_uri not set.")

        if "scope" not in self.config:
            self.config["scope"] = "openid"

    def revoke(self, token, token_type):
        """
        Revoke the token
        :param token_type: type of token to revoke (access_token or refresh_token)
        :param token: the token to revoke
        :raises: raises error when http call fails
        """
        if "revocation_endpoint" not in self.config:
            raise Exception("No revocation endpoint set")

        try:
            revoke_request = urllib.request.Request(self.config["revocation_endpoint"])
            data = {
                "token": token,
                "token_type_hint": token_type,
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"]
            }
            string_data = urllib.parse.urlencode(data).encode("utf-8")
            urllib.request.urlopen(revoke_request, string_data, context=self.ctx)
        except urllib.request.URLError as te:
            raise te

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        try:
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"]
            }
            string_data = urllib.parse.urlencode(data).encode("utf-8")
            token_response = urllib.request.urlopen(self.config["token_endpoint"], string_data, context=self.ctx)
        except urllib.request.URLError as te:
            raise te
        raw_data = token_response.read()
        encoding = token_response.info().get_content_charset("utf-8")  # JSON default
        token_response = json.loads(raw_data.decode(encoding))
        return token_response

    def get_auth_req_url(self, session):
        """
        :param session: the session, will be used to keep the OAuth state
        :return redirect url for the OAuth code flow
        """
        state = generate_random_string()
        session["state"] = state
        request_args = {"scope": self.config["scope"],
                        "response_type": self.config["response_type"],
                        "client_id": self.config["client_id"],
                        "state": state,
                        "redirect_uri": self.config["redirect_uri"]}
        login_url = "%s?%s" % (self.config["authorization_endpoint"], urllib.parse.urlencode(request_args))
        return login_url

    def get_token(self, code):
        """
        Request data from token endpoint
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """
        data = {"client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "code": code,
                "redirect_uri": self.config["redirect_uri"],
                "grant_type": "authorization_code"}
        string_data = urllib.parse.urlencode(data).encode("utf-8")
        # Exchange code for tokens
        try:
            token_response = urllib.request.urlopen(self.config["token_endpoint"], string_data, context=self.ctx)
        except urllib.request.URLError as te:
            raise te

        raw_data = token_response.read()
        encoding = token_response.info().get_content_charset("utf8")  # JSON default
        token_response = json.loads(raw_data.decode(encoding))
        return token_response

    def get_user_info(self, token):
        """
        Request data from userinfo endpoint
        :param token: access_token retrieved from token endpoint
        :return: the json response containing user data
        """
        request_args = {"access_token": token}
        userinfo_url = "%s?%s" % (self.config["userinfo_endpoint"], urllib.parse.urlencode(request_args))
        # Get user info
        try:
            user_info = urllib.request.urlopen(userinfo_url, context=self.ctx)
        except urllib.request.URLError as te:
            raise te

        raw_data = user_info.read()
        encoding = user_info.info().get_content_charset("utf8")  # JSON default
        user_info = json.loads(raw_data.decode(encoding))
        return user_info

    def logout(self, token):
        """
        Make request to logout endpoint
        :type token: id_token retrieved from token endpoint
        :return: True
        """
        logout_url = "%s?id_token_hint=%s&post_logout_redirect_uri=%s" % (
            self.config["logout_endpoint"], token, self.config["redirect_uri"]
        )
        print(logout_url)
        try:
            urllib.request.urlopen(logout_url, context=self.ctx)
        except urllib.request.URLError as te:
            raise te

        return True
