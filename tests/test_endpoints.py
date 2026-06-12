import json
import os
from time import time
import uuid

import jwt
import pytest
import requests
from pytest_nhsd_apim.apigee_apis import (
    ApigeeClient,
    ApigeeNonProdCredentials,
    ApiProductsAPI,
    DeveloperAppsAPI,
)

SESSION = requests.Session()
DEFAULT_DEVELOPER = "apm-testing-internal-dev@nhs.net"


def _config():
    from .configuration import config

    return config


class TestEndpoints:

    @pytest.fixture()
    def test_app_and_product(self):
        """Create and clean up an app+product pair for the proxy-under-test."""
        print("\nCreating Default App and Product..")
        cfg = _config()

        apigee_config = ApigeeNonProdCredentials(
            apigee_access_token=os.environ["APIGEE_API_TOKEN"]
        )
        client = ApigeeClient(config=apigee_config)
        products_api = ApiProductsAPI(client=client)
        apps_api = DeveloperAppsAPI(client=client)

        developer_email = os.environ.get("APIGEE_DEVELOPER", DEFAULT_DEVELOPER)
        product_name = f"{cfg.PROXY_NAME}-e2e-{uuid.uuid4().hex[:8]}"
        app_name = f"{cfg.PROXY_NAME}-e2e-app-{uuid.uuid4().hex[:8]}"

        product_ratelimit = {
            cfg.PROXY_NAME: {
                "quota": {
                    "limit": "300",
                    "enabled": True,
                    "interval": 1,
                    "timeunit": "minute",
                },
                "spikeArrest": {"ratelimit": "100ps", "enabled": True},
            }
        }

        product = products_api.post_products(
            {
                "name": product_name,
                "displayName": product_name,
                "approvalType": "auto",
                "environments": [cfg.ENVIRONMENT],
                "proxies": [cfg.PROXY_NAME, f"identity-service-{cfg.ENVIRONMENT}"],
                "scopes": ["urn:nhsd:apim:user-nhs-login:P9:patient-care-aggregator-api"],
                "attributes": [
                    {"name": "access", "value": "private"},
                    {"name": "ratelimiting", "value": json.dumps(product_ratelimit)},
                ],
                "quota": "300",
                "quotaInterval": "1",
                "quotaTimeUnit": "minute",
            }
        )

        app_ratelimit = {
            cfg.PROXY_NAME: {
                "quota": {
                    "limit": "300",
                    "enabled": True,
                    "interval": 1,
                    "timeunit": "minute",
                },
                "spikeArrest": {"ratelimit": "100ps", "enabled": True},
            }
        }

        app = apps_api.create_app(
            email=developer_email,
            body={
                "name": app_name,
                "apiProducts": [product["name"]],
                "callbackUrl": "https://google.com/callback",
                "attributes": [
                    {
                        "name": "jwks-resource-url",
                        "value": "https://raw.githubusercontent.com/NHSDigital/"
                        "identity-service-jwks/main/jwks/internal-dev/"
                        "9baed6f4-1361-4a8e-8531-1f8426e3aba8.json",
                    },
                    {"name": "ratelimiting", "value": json.dumps(app_ratelimit)},
                ],
            },
        )

        test_app = {
            "client_id": app["credentials"][0]["consumerKey"],
            "name": app["name"],
            "developer": developer_email,
        }

        yield product, test_app

        print("\nDestroying Default App and Product..")
        apps_api.delete_app_by_name(email=test_app["developer"], app_name=test_app["name"])
        products_api.delete_product_by_name(product["name"])

    @pytest.fixture()
    def get_token(self, test_app_and_product):
        _, test_app = test_app_and_product
        cfg = _config()

        # Create and sign mock id_token
        id_token_private_key = cfg.ENV["id_token_private_key"]
        with open(id_token_private_key, "r") as f:
            id_token_private_key = f.read()

        id_token_jwt = jwt.encode(
            {
                "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
                "birthdate": "1968-02-12",
                "nhs_number": "9912003072",
                "iss": "https://internal-dev.api.service.nhs.uk",
                "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
                "aud": "some-client-id",
                "id_status": "verified",
                "token_use": "id",
                "surname": "MILLAR",
                "auth_time": 1623849201,
                "vot": "P9.Cp.Cd",
                "identity_proofing_level": "P9",
                "exp": 4114224185,
                "iat": 1623849271,
                "family_name": "MILLAR",
                "jti": "8edabe2b-c7ff-40bd-bc7f-0b8dc6a52423",
            },
            id_token_private_key,
            headers={"typ": "JWT", "alg": "RS512", "kid": "nhs-login"},
            algorithm="RS512",
        )

        # Create jwt for client assertion (APIM-authentication)
        client_assertion_private_key = cfg.ENV["client_assertion_private_key"]
        with open(client_assertion_private_key, "r") as f:
            private_key = f.read()

        token_url = "https://internal-dev.api.service.nhs.uk/oauth2/token"
        client_assertion = jwt.encode(
            {
                "sub": test_app["client_id"],
                "iss": test_app["client_id"],
                "jti": str(uuid.uuid4()),
                "aud": token_url,
                "exp": int(time()) + 300,
            },
            private_key,
            algorithm="RS512",
            headers={"kid": "test-1"},
        )

        resp = SESSION.post(
            token_url,
            headers={"foo": "bar"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "subject_token": id_token_jwt,
                "client_assertion": client_assertion,
            },
        )

        print("Auth server response:")
        print(resp.json())

        return resp.json()["access_token"]

    def test_happy_path(self, get_token):
        cfg = _config()
        token = get_token
        proxy_url = f"https://internal-dev.api.service.nhs.uk/{cfg.ENV['base_path']}/status"

        resp = SESSION.get(url=proxy_url, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
