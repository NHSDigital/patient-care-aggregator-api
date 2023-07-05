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
        base_path = "oauth2-no-smartcard"
    else:
        base_path = "oauth2"

    return f"https://{environment}.api.service.nhs.uk/{base_path}"


def access_token(environment, client_id, client_secret, redirect_uri, mock_username):

    identity_service_base_url = identity_service_url(
        environment, mock_username=mock_username
    )

    resp = SESSION.get(
        f"{identity_service_base_url}/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "1234567890",
        },
    )

    if resp.status_code != 200:
        print(json.dumps(resp.json(), indent=2))
        sys.exit(1)

    tree = html.fromstring(resp.content.decode())

    # Extract state param
    if mock_username:  # KEYCLOAK
        form = tree.get_element_by_id("kc-form-login")
        url = form.action
        resp2 = SESSION.post(url, data={"username": mock_username})
    else:  # Simulated Auth
        state = None
        for form in tree.body:
            assert form.tag == "form"
            input_elems = [item for item in form if item.tag == "input"]
            state = dict(input_elems[0].items())["value"]

            # TODO make this configurable
            simulated_auth_url = f"https://{environment}.api.service.nhs.uk/mock-nhsid-jwks/simulated_auth"
            resp2 = SESSION.post(simulated_auth_url, data={"state": state})

    if "herokuapp" in redirect_uri:
        # Then the herokuapp has done the POST and so we don't need to
        # pretend to be the third part, and can just parse the results
        tree2 = html.fromstring(resp2.content.decode())
        for div in tree2.body:
            assert div.tag == "div"
            for div in div:
                assert div.tag == "div"
                data_items = [item for item in div if item.tag == "pre"]
                result = literal_eval(data_items[0].text)
                return result["access_token"]
    else:
        # We do the POST identity-service expects ourselves Requests
        # will have redirected to whatever our --redirect_uri is with
        # the auth code in the query string, so we go grab that...
        qs = urlparse(resp2.history[-1].headers["Location"]).query
        auth_code = parse_qs(qs)["code"]
        if isinstance(auth_code, list):
            auth_code = auth_code[0]

        resp3 = SESSION.post(
            f"{identity_service_base_url}/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        return resp3.json()


def refresh(environment, client_id, client_secret, refresh_token):
    resp4 = SESSION.post(
        f"{identity_service_url(environment, mock_username=None)}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    return resp4.json()


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
    print(client_assertion)
    resp = SESSION.post(
        url,
        headers={"foo": "bar"},
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
        },
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
    elif args["--refresh_token"]:
        data = refresh(environment, client_id, client_secret, args["--refresh_token"])
    else:
        data = access_token(
            environment,
            client_id,
            client_secret,
            args["--redirect_uri"],
            mock_username=args["--mock"],
        )
    print(json.dumps(data, indent=2))

    # print("*"*100)
    # test_resp = SESSION.get(
    #     "https://int.api.service.nhs.uk/immunisation-history/FHIR/R4/Immunization",
    #     params={
    #         "patient.identifier": "https://fhir.nhs.uk/Id/nhs-number%7C9449307520",
    #         "procedure-code:below": "90640007",
    #         "_include": "Immunization:patient",
    #     },
    #     headers={"Authorization": f"Bearer {data['access_token']}", "foo": "bar"},
    # )

    # for _id in ["9449305552",
    #             "9449306621",
    #             "9449306613",
    #             "9449306605",
    #             "9449306494",
    #             "9449306583",
    #             "9449306680",
    #             "9449306567",
    #             "9449306559",
    #             "9449306540",
    #             "9449306532",
    #             "9449305641",
    #             "9449306524",
    #             "9449306516",
    #             "9449306257",
    #             "9449306591",
    #             "9449306281",
    #             "9449306052",
    #             "9449306044",
    #             "9449306036"]:

    #     test_resp = SESSION.get(
    #         f"https://int.api.service.nhs.uk/personal-demographics/FHIR/R4/Patient/{_id}",
    #         params={
    #         },
    #         headers={"Authorization": f"Bearer {data['access_token']}",
    #                  "foo": "bar",
    #                  "X-Request-ID": str(uuid.uuid4())

    #                  },
    #     )

    #     print(test_resp)
    #     with open(f"{_id}.json", "w") as f:
    #         f.write(test_resp.content.decode())
