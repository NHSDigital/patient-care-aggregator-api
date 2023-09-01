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
    elif environment == 'prod':
        return "https://api.service.nhs.uk/oauth2"
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
    # additional_headers = {"kid": "prod-1"}
    client_assertion = jwt.encode(
        claims, private_key, algorithm="RS512", headers=additional_headers
    )
    # resp = SESSION.post(
    #     url,
    #     headers={"foo": "bar"},
    #     data={
    #         "grant_type": "client_credentials",
    #         "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    #         "client_assertion": client_assertion,
    #     },
    # )
    
    # id_token_jwt = 'eyJhbGciOiJSUzUxMiIsImF1ZCI6IndheWZpbmRlci1hZ2dyZWdhdG9yIiwiZXhwIjoxNjg5MTAxNDIyLCJpYXQiOjE2ODkwOTc4MjIsImlzcyI6Imh0dHBzOi8vYXV0aC5hb3Muc2lnbmluLm5ocy51ayIsImp0aSI6IjAxZGYzYjZkLTAxYmMtNDhlZC1iMWY4LTM4ZWQyZjk4NmRkMyIsImtpZCI6ImY2MGViNDZmZjhhYmYwYmY5ZTkxN2VlZTYwODZjNWZhNGExNjJhNWQiLCJzdWIiOiI4MmEyOTZkMC03NTJjLTRjZjEtOWEwMC03MzgwNmJiMWY4MzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2F1dGguYW9zLnNpZ25pbi5uaHMudWsiLCJzdWIiOiI4MmEyOTZkMC03NTJjLTRjZjEtOWEwMC03MzgwNmJiMWY4MzMiLCJhdWQiOiJ3YXlmaW5kZXItYWdncmVnYXRvciIsImlhdCI6MTY4OTA5NzgyMiwidnRtIjoiaHR0cHM6Ly9hdXRoLmFvcy5zaWduaW4ubmhzLnVrL3RydXN0bWFyay9hdXRoLmFvcy5zaWduaW4ubmhzLnVrIiwiYXV0aF90aW1lIjoxNjg5MDk3ODE1LCJ2b3QiOiJQOS5DcC5DZCIsImV4cCI6MTY4OTEwMTQyMiwianRpIjoiMDFkZjNiNmQtMDFiYy00OGVkLWIxZjgtMzhlZDJmOTg2ZGQzIiwibmhzX251bWJlciI6Ijk3MjY3NzkwNTciLCJpZGVudGl0eV9wcm9vZmluZ19sZXZlbCI6IlA5IiwiaWRfc3RhdHVzIjoidmVyaWZpZWQiLCJ0b2tlbl91c2UiOiJpZCIsInN1cm5hbWUiOiJDSE9OIiwiZmFtaWx5X25hbWUiOiJDSE9OIiwiYmlydGhkYXRlIjoiMTk4NS0wOS0wNyJ9.uiwXXGxA67iL9Y1p3W-q68FJU9B5vPGSm2aWpQDzxyvjh6X_0yYvtNU-AzrwYDAoCXwpxjE_Gdu5Ud2_nBxfMBEkmfzFiqz7S-w4_hjvv3I-40lukh0obbjDcYiKJxQvchVeD0Hys0vhi85B_KQdNjfDPYttkglc4QCcmgRQAtIjlg08HxDnzqOGN4Dh-oH_lPSK_3oRdM-28okD2mYxi4TigUGcq1wUOin-tuobzy6LKnqhvq8CNmT3eUoX1p3tPJhCGQgAxmY2w7HzcR5lmdmjP5CkWuEWc2Vs41Ytnj6v0XUu64K_gv1Va3lGGGsueAWVyJd4RrDsZOrcMBU21g'

    id_token_jwt = 'eyJhbGciOiJSUzUxMiIsImF1ZCI6Im5ocy1vbmxpbmUiLCJleHAiOjE2OTI5NjU3MzUsImlhdCI6MTY5Mjk2MjEzNSwiaXNzIjoiaHR0cHM6Ly9hdXRoLmxvZ2luLm5ocy51ayIsImp0aSI6ImFkYmU2NGM5LTdhMjEtNDViYy05YTJmLTRhZjMyMWFlNTJhMyIsImtpZCI6IjhmMTc5MTBlZWEyMGM2ZTM0NTIxNDdkMGQ4Y2RkZGY4NjhkMDcxZjgiLCJzdWIiOiI2NTlmOGM2Zi05M2IwLTQwZjItODE2Mi05MzFhNjcwOGNkZGYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2F1dGgubG9naW4ubmhzLnVrIiwic3ViIjoiNjU5ZjhjNmYtOTNiMC00MGYyLTgxNjItOTMxYTY3MDhjZGRmIiwiYXVkIjoibmhzLW9ubGluZSIsImlhdCI6MTY5Mjk2MjEzNSwidnRtIjoiaHR0cHM6Ly9hdXRoLmxvZ2luLm5ocy51ay90cnVzdG1hcmsvYXV0aC5sb2dpbi5uaHMudWsiLCJhdXRoX3RpbWUiOjE2OTI5NjIxMzMsInZvdCI6IlA5LkNwLkNkIiwiZXhwIjoxNjkyOTY1NzM1LCJqdGkiOiJhZGJlNjRjOS03YTIxLTQ1YmMtOWEyZi00YWYzMjFhZTUyYTMiLCJuaHNfbnVtYmVyIjoiOTk5MDU3NzM4MiIsImlkZW50aXR5X3Byb29maW5nX2xldmVsIjoiUDkiLCJpZF9zdGF0dXMiOiJ2ZXJpZmllZCIsInRva2VuX3VzZSI6ImlkIiwic3VybmFtZSI6IlhYVEVTVFBBVElFTlQtVEtLRiIsImZhbWlseV9uYW1lIjoiWFhURVNUUEFUSUVOVC1US0tGIiwiYmlydGhkYXRlIjoiMTk1Ny0wMy0yOCJ9.nHshASNsSWrpoHiET4tzs2wkZSQJOUvqO4PZWcWYHtWRh8A2_QNxf_Dsz2HMx-RaQhdzvdR8f71P9wXwuSEK3V3TgpVg332FCj-UV1e-j4AObr4HRv_K6iDr4U70A14EPpa88lEXYF-FHJY_Fqb5RV83fae7Ge4-4Sz_OpFOXCG9lRHRIrWSkErwZXuucxj59FsQ2arZ1svHIEZvgxh3yiRYZasEuzejWM41BZUbgsBhU52_VRxqvaz2OijRn-bk2TIV7yo5DcBW415qYlGIFsDw2y3xaika8GAeVX4dP0_DqjtPLW5JGGENG_9T0FK7wvRFx4gUQSbxrJnz_PBj1A'

    resp = SESSION.post(
        url,
        headers={"foo": "bar"},
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "subject_token": id_token_jwt,
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
