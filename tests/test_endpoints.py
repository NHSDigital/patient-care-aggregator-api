import pytest
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
import uuid
from time import time
import jwt
import requests
from .configuration import config
import json

SESSION = requests.Session()


class TestEndpoints:

    @pytest.fixture()
    async def test_app_and_product(self):
        """Create a fresh test app and product consuming the patient-care-agregator-api proxy
        The app and products are destroyed at the end of the test
        """
        print("\nCreating Default App and Product..")
        apigee_product = ApigeeApiProducts()
        await apigee_product.create_new_product()
        await apigee_product.update_proxies(
            [config.PROXY_NAME, f"identity-service-{config.ENVIRONMENT}"]
        )
        await apigee_product.update_scopes(
            ["urn:nhsd:apim:user-nhs-login:P9:patient-care-aggregator-api"]
        )
        # Product ratelimit
        product_ratelimit = {
            f"{config.PROXY_NAME}": {
                "quota": {
                    "limit": "300",
                    "enabled": True,
                    "interval": 1,
                    "timeunit": "minute",
                },
                "spikeArrest": {"ratelimit": "100ps", "enabled": True},
            }
        }
        await apigee_product.update_attributes({"ratelimiting": json.dumps(product_ratelimit)})

        await apigee_product.update_environments([config.ENVIRONMENT])

        apigee_app = ApigeeApiDeveloperApps()
        await apigee_app.create_new_app()

        # Set default JWT Testing resource url and app ratelimit
        app_ratelimit = {
            f"{config.PROXY_NAME}": {
                "quota": {
                    "limit": "300",
                    "enabled": True,
                    "interval": 1,
                    "timeunit": "minute",
                },
                "spikeArrest": {"ratelimit": "100ps", "enabled": True},
            }
        }
        await apigee_app.set_custom_attributes(
            {
                "jwks-resource-url": "https://raw.githubusercontent.com/NHSDigital/"
                "identity-service-jwks/main/jwks/internal-dev/"
                "9baed6f4-1361-4a8e-8531-1f8426e3aba8.json",
                "ratelimiting": json.dumps(app_ratelimit),
            }
        )

        await apigee_app.add_api_product(api_products=[apigee_product.name])

        yield apigee_product, apigee_app

        # Teardown
        print("\nDestroying Default App and Product..")
        await apigee_app.destroy_app()
        await apigee_product.destroy_product()

    @pytest.fixture()
    async def get_token(self, test_app_and_product):
        test_product, test_app = test_app_and_product

        """Call identity server to get an access token"""
        # Create and sign mock id_token
        id_token_private_key = config.ENV["id_token_private_key"]
        with open(id_token_private_key, "r") as f:
            id_token_private_key = f.read()
        headers = {
            "typ": "JWT",
            "alg": "RS512",
            "kid": "nhs-login",
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "aud": "some-client-id",
            "iss": "https://internal-dev.api.service.nhs.uk",
            "exp": 1683331166,
            "iat": 1623849271,
            "jti": str(uuid.uuid4()),
        }
        claims = {
            "sub": "49f470a1-cc52-49b7-beba-0f9cec937c46",
            "birthdate": "1968-02-12",
            "nhs_number": "9912003072",  # you can change this nhs-number as required :)
            "iss": "https://internal-dev.api.service.nhs.uk",
            "vtm": "https://auth.sandpit.signin.nhs.uk/trustmark/auth.sandpit.signin.nhs.uk",
            "aud": "some-client-id",
            "id_status": "verified",
            "token_use": "id",
            "surname": "MILLAR",
            "auth_time": 1623849201,
            "vot": "P9.Cp.Cd",
            "identity_proofing_level": "P9",
            "exp": 1683331166,
            "iat": 1623849271,
            "family_name": "MILLAR",
            "jti": "8edabe2b-c7ff-40bd-bc7f-0b8dc6a52423",
        }
        id_token_jwt = jwt.encode(
            claims, id_token_private_key, headers=headers, algorithm="RS512"
        )

        # Create jwt for client assertion (APIM-authentication)
        client_assertion_private_key = config.ENV["client_assertion_private_key"]
        with open(client_assertion_private_key, "r") as f:
            private_key = f.read()
        url = "https://internal-dev.api.service.nhs.uk/oauth2/token"
        claims = {
            "sub": test_app.client_id,  # TODO:save this on secrets manager or create app on the fly
            "iss": test_app.client_id,
            "jti": str(uuid.uuid4()),
            "aud": url,
            "exp": int(time()) + 300,  # 5mins in the future
        }

        additional_headers = {"kid": "test-1"}
        client_assertion = jwt.encode(
            claims, private_key, algorithm="RS512", headers=additional_headers
        )

        # Get token using token exchange
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

        return resp.json()["access_token"]

    def test_happy_path(self, get_token):
        # Given I have a token
        token = get_token
        expected_status_code = 200
        proxy_url = f"https://internal-dev.api.service.nhs.uk/{config.ENV['base_path']}/aggregator/status"
        # When calling the proxy
        headers = {"Authorization": f"Bearer {token}"}
        resp = SESSION.get(url=proxy_url, headers=headers)
        # Then
        assert resp.status_code == expected_status_code
