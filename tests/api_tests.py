import os
from time import sleep, time

import pytest

from .conftest import APISessionClient, APITestSessionConfig


def _is_deployed(resp, api_test_config: APITestSessionConfig) -> bool:

    if resp.status_code != 200:
        return False
    body = resp.json()

    return body.get("commitId") == api_test_config.commit_id


def is_401(resp) -> bool:
    return resp.status_code == 401


def poll_until(make_request, until, timeout=120, interval=2):
    deadline = time() + timeout
    while time() < deadline:
        response = make_request()
        if until(response):
            return
        sleep(interval)
    pytest.fail(f"Condition not met within {timeout} seconds")


@pytest.mark.e2e
@pytest.mark.smoketest
def test_output_test_config(api_test_config: APITestSessionConfig):
    print(api_test_config)


@pytest.mark.e2e
@pytest.mark.smoketest
def test_wait_for_ping(
    api_client: APISessionClient, api_test_config: APITestSessionConfig
):
    """
    test for _ping ..  this uses poll_until to wait until the correct SOURCE_COMMIT_ID ( from env var )
    is available
    """

    poll_until(
        make_request=lambda: api_client.get("_ping"),
        until=lambda resp: _is_deployed(resp, api_test_config),
        timeout=120,
    )


@pytest.mark.e2e
@pytest.mark.smoketest
def test_check_status_is_secured(api_client: APISessionClient):

    poll_until(
        make_request=lambda: api_client.get("_status"), until=is_401, timeout=120
    )


@pytest.mark.e2e
@pytest.mark.smoketest
def test_wait_for_status(
    api_client: APISessionClient, api_test_config: APITestSessionConfig
):
    """
    test for _status ..  this uses poll_until to wait until the correct SOURCE_COMMIT_ID ( from env var )
    is available
    """

    poll_until(
        make_request=lambda: api_client.get(
            "_status", headers={"apikey": os.environ["STATUS_ENDPOINT_API_KEY"]}
        ),
        until=lambda resp: _is_deployed(resp, api_test_config),
        timeout=120,
    )
