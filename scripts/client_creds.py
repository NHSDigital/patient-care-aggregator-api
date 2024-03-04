#!/usr/bin/env python3
"""
Usage: access_token.py ENVIRONMENT CLIENT_ID CLIENT_SECRET [--redirect_uri REDIRECT_URI] [--mock USERNAME]
       access_token.py ENVIRONMENT CLIENT_ID CLIENT_SECRET --refresh_token REFRESH_TOKEN
       access_token.py ENVIRONMENT CLIENT_ID --jwt_private_key JWT_PRIVATE_KEY
       access_token.py (-h | --help)

Options:
  --refresh_token REFRESH_TOKEN        use refresh token from previous call to get new access token
  --redirect_uri REDIRECT_URI          specify redirect uri [default: https://example.org/callback]
  --jwt_private_key JWT_PRIVATE_KEY    JWT private key (public key must be registered with NHSD APIM)
  --mock USERNAME                      Log in to Keycloak with username
  -h --help                            show help
"""
import docopt
import json
import sys
import requests
from lxml import html
from urllib.parse import urlparse, parse_qs
from ast import literal_eval
import uuid
from time import time
import jwt  # https://github.com/jpadilla/pyjwt

SESSION = requests.Session()

def identity_service_url(environment, mock_username=None):

    if mock_username is not None:
        if environment not in ["internal-dev", "int"]:
            raise ValueError("Not a keycloak environment!")
        base_path = "oauth2-mock"
    elif environment == "int":
        # base_path = "oauth2-no-smartcard"
        base_path = "oauth2"
    elif environment == 'prod':
        return "https://api.service.nhs.uk/oauth2"
    else:
        base_path = "oauth2-mock"

    return f"https://{environment}.api.service.nhs.uk/{base_path}"


def do_jwt(environment, client_id, private_key_file):
    with open(private_key_file, "r") as f:
        private_key = f.read()
    url = f"{identity_service_url(environment, mock_username=None)}/token"
    print(url)
    claims = {
        "sub": client_id,
        "iss": client_id,
        "jti": str(uuid.uuid4()),
        "aud": url,
        "exp": int(time()) + 300,  # 5mins in the future
    }

    additional_headers = {"kid": "test-1"}
    
    client_assertion = jwt.encode(
        claims, private_key, algorithm="RS512", headers=additional_headers
    )

    print('Client Assertion')
    print(client_assertion)
    print('URL')
    print(url)

    data = {
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "clientId": client_id,
            "client_assertion": client_assertion,
            "header": additional_headers,
            "algorithm": "RS512"
            }
    print('Data')
    print(json.dumps(data))

    resp = SESSION.post(
        url,
        # headers={"foo": "bar"},
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "clientId": client_id,
            "client_assertion": client_assertion,
            "header": additional_headers,
            "algorithm": "RS512"
            }
        )

    return resp.json()

if __name__ == "__main__":

    args = docopt.docopt(__doc__)
    environment = args["ENVIRONMENT"]
    envs = [
        "internal-dev",
        "internal-dev-sandbox",
        "internal-qa",
        "internal-qa-sandbox",
        "ref",
        "dev",
        "int",
        "sandbox",
        "prod",
    ]
    if environment not in envs:
        print("Error! Invalid environment")
        sys.exit(1)
    client_id = args["CLIENT_ID"]
    client_secret = args.get("CLIENT_SECRET")
    if args["--jwt_private_key"]:
        data = do_jwt(environment, client_id, args["--jwt_private_key"])

    print(json.dumps(data, indent=2))