import logging
import urllib.request as urllib2
from flask import render_template, session, redirect, request
from jwkest import BadSignature
from urllib.parse import urlparse
from .client import Client
from .helpers.oidc import decode_token, generate_random_string
from .validator import JwtValidator


class UserSession:
    def __init__(self):
        pass

    access_token = None
    refresh_token = None
    id_token = None
    access_token_json = None
    id_token_json = None
    name = None
    api_response = None


def open_id_connect(service):
    namespace = service.namespace
    _session_store = service.session_store
    _config = service.oidc_config
    _client = Client(_config)
    _app = service.app
    if "base_url" in _config:
        _base_url = _config["base_url"]
    else:
        _base_url = ""

    # load the jwk set.
    if "jwks_uri" in _config:
        _jwt_validator = JwtValidator(_config)
    else:
        logging.info("Found no url to JWK set, will not be able to validate JWT signature.")

    def redirect_with_baseurl(path):
        return redirect(_base_url + path)

    def create_error(message, exception=None):
        """
        Print the error and output it to the page
        :param exception:
        :param message:
        :return: redirects to index.html with the error message
        """

        logging.info(message)
        logging.error(str(exception))

        if _app:
            user = None
            if "session_id" in session:
                user = _session_store.get(session["session_id"])
            return render_template("index.html",
                                   server_name=urlparse(_config["authorization_endpoint"]).netloc,
                                   session=user,
                                   error=message)

    @_app.route("/" + namespace + "/test")
    def home():
        """
            :return: the index page with the tokens, if set.
            """
        user = None
        if "session_id" in session:
            user = _session_store.get(session["session_id"])
        if user:
            if user.id_token:
                user.id_token_json = decode_token(user.id_token)
            if user.access_token:
                try:
                    user.access_token_json = decode_token(user.access_token)
                except Exception:
                    pass

        return render_template("index.html",
                               server_name=urlparse(_config["authorization_endpoint"]).netloc,
                               session=user)

    @_app.route("/" + namespace + "/login")
    def start_code_flow():
        """
        :return: redirects to the authorization server with the appropriate parameters set.
        """
        login_url = _client.get_auth_req_url(session)
        return redirect(login_url)

    @_app.route("/" + namespace + "/logout")
    def logout():
        """
        Logout clears the session, along with the tokens
        :return: redirects to /
        """
        user = _session_store.get(session["session_id"])
        if "session_id" in session:
            del _session_store[session["session_id"]]
        session.clear()
        if "logout_endpoint" in _config:
            try:
                _client.logout(user.id_token)
            except Exception as e:
                return create_error("Could not logout", e)

        return redirect_with_baseurl("/" + namespace + "/test")

    @_app.route("/" + namespace + "/refresh")
    def refresh():
        """
        Refreshes the access token using the refresh token
        :return: redirects to /
        """
        user = _session_store.get(session["session_id"])
        try:
            token_data = _client.refresh(user.refresh_token)
        except Exception as e:
            return create_error("Could not refresh Access Token", e)
        user.access_token = token_data["access_token"]
        user.refresh_token = token_data["refresh_token"]
        user.id_token = token_data["id_token"]
        return redirect_with_baseurl("/" + namespace + "/test")

    @_app.route("/" + namespace + "/revoke")
    def revoke():
        """
        Revokes the access and refresh token and clears the sessions
        :return: redirects to /
        """
        if "session_id" in session:
            user = _session_store.get(session["session_id"])
            if not user:
                redirect_with_baseurl("/")

            if user.refresh_token:
                try:
                    _client.revoke(user.refresh_token, "refresh_token")
                except urllib2.URLError as e:
                    return create_error("Could not revoke refresh token", e)
                user.refresh_token = None

        return redirect_with_baseurl("/")

    @_app.route("/call-api")
    def call_api():
        """
        Call an api using the Access Token
        :return: the index template with the data from the api in the parameter "data"
        """
        if "session_id" in session:
            user = _session_store.get(session["session_id"])
            if not user:
                return redirect_with_baseurl("/" + namespace + "/test")
            if "api_endpoint" in _config:
                user.api_response = None
                if user.access_token:
                    try:
                        request = urllib2.Request(_config["api_endpoint"])
                        request.add_header("Authorization", "Bearer %s" % user.access_token)
                        response = urllib2.urlopen(request)
                        user.api_response = {"code": response.code, "data": response.read()}
                    except urllib2.HTTPError as e:
                        user.api_response = {"code": e.code, "data": e.read()}
                else:
                    user.api_response = None
                    logging.info("No access token in session")
            else:
                user.api_response = None
                logging.info("No API endpoint configured")

        return redirect_with_baseurl("/" + namespace + "/test")

    @_app.route("/" + namespace + "/callback")
    def oauth_callback():
        """
        Called when the resource owner is returning from the authorization server
        :return:redirect to / with user info stored in the session.
        """
        if "state" not in session or session["state"] != request.args["state"]:
            return create_error("Missing or invalid state")

        if "code" not in request.args:
            return create_error("No code in response")

        try:
            token_data = _client.get_token(request.args["code"])
        except Exception as e:
            return create_error("Could not fetch token(s)", e)
        session.pop("state", None)

        # Store in basic server session, since flask session use cookie for storage
        user = UserSession()

        if "access_token" in token_data:
            user.access_token = token_data["access_token"]
            user_data = _client.get_user_info(user.access_token)
            user.name = user_data["nickname"]

        if "id_token" in token_data:
            # validate JWS; signature, aud and iss.
            # Token type, access token, ref-token and JWT
            if "issuer" not in _config:
                return create_error("Could not validate token: no issuer configured")

            if not _jwt_validator:
                return create_error("Could not validate token: no jwks_uri configured")
            try:
                _jwt_validator.validate(token_data["id_token"], _config["issuer"], _config["client_id"])
            except BadSignature as bs:
                return create_error("Could not validate token: %s" % bs.message)
            except Exception as ve:
                return create_error("Unexpected exception: %s" % ve.message)

            user.id_token = token_data["id_token"]

        if "refresh_token" in token_data:
            user.refresh_token = token_data["refresh_token"]

        session["session_id"] = generate_random_string()
        _session_store[session["session_id"]] = user

        return redirect_with_baseurl("/" + namespace + "/test")
