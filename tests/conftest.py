from dataclasses import dataclass
import os

import pytest
import requests


@dataclass
class APITestSessionConfig:
    environment: str
    base_path: str
    commit_id: str

    @property
    def base_url(self) -> str:
        return f"https://{self.environment}.api.service.nhs.uk"


class APISessionClient:
    def __init__(self, base_url: str, base_path: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._base_path = base_path.strip("/")
        self._session = requests.Session()

    def get(self, endpoint: str, headers: dict | None = None) -> requests.Response:
        path = endpoint.lstrip("/")
        url = f"{self._base_url}/{self._base_path}/{path}"
        return self._session.get(url=url, headers=headers)


@pytest.fixture(scope="session")
def api_test_config() -> APITestSessionConfig:
    return APITestSessionConfig(
        environment=os.environ["APIGEE_ENVIRONMENT"],
        base_path=os.environ["SERVICE_BASE_PATH"],
        commit_id=os.environ["SOURCE_COMMIT_ID"],
    )


@pytest.fixture(scope="session")
def api_client(api_test_config: APITestSessionConfig) -> APISessionClient:
    return APISessionClient(
        base_url=api_test_config.base_url,
        base_path=api_test_config.base_path,
    )
