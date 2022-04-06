import pytest
# from api_test_utils.oauth_helper import OauthHelper
from api_test_utils.apigee_api_apps import ApigeeApiDeveloperApps
from api_test_utils.apigee_api_products import ApigeeApiProducts
import uuid
from time import time
import jwt
import requests
from .configuration import config

SESSION = requests.Session()


class TestEndpoints:
    @pytest.fixture()
    def app(self):
        """
        Import the test utils module to be able to:
            - Create apigee test application
                - Update custom attributes
                - Update custom ratelimits
                - Update products to the test application
        """
        return ApigeeApiDeveloperApps()

    @pytest.fixture()
    def product(self):
        """
        Import the test utils module to be able to:
            - Create apigee test product
                - Update custom scopes
                - Update environments
                - Update product paths
                - Update custom attributes
                - Update proxies to the product
                - Update custom ratelimits
        """
        return ApigeeApiProducts()

    # in the future you should implement the example in
    # https://github.com/NHSDigital/booking-and-referral-fhir-api/blob/master/tests/conftest.py#L31
    # @pytest.fixture()
    # async def test_app_and_product(self, app, product):
    #     """Create a test app and product which can be modified in the test"""
    #     await product.create_new_product()
    #     await product.update_proxies(
    #         []
    #     )

    #     await app.create_new_app()

    #     await product.update_scopes(
    #         [
    #             "urn:nhsd:apim:app:level3:patient-care-aggregator-api",
    #             "urn:nhsd:apim:user-nhs-id:aal3:patient-care-aggregator-api",
    #         ]
    #     )
    #     await app.add_api_product([product.name])

    #     yield product, app

    #     await app.destroy_app()
    #     await product.destroy_product()

    @pytest.fixture()
    async def get_token(self):
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
        print(url)
        claims = {
            "sub": "GZGJb7VC02GHC91qlaycTn5i7QHPVbsJ",  # TODO:save this on secrets manager or create app on the fly
            "iss": "GZGJb7VC02GHC91qlaycTn5i7QHPVbsJ",
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
