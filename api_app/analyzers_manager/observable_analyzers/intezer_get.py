# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.file_analyzers.intezer_scan import (
    get_access_token,
    INTEZER_BASE_URL,
)

from tests.mock_utils import if_mock_connections, patch, MockResponse

logger = logging.getLogger(__name__)


class IntezerGet(classes.ObservableAnalyzer):
    base_url: str = INTEZER_BASE_URL

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        # intezer access token
        self.intezer_token = get_access_token(self.__api_key)

    def run(self):
        return self.__intezer_analysis()

    def __intezer_analysis(self):
        session = requests.session()
        session.headers["Authorization"] = f"Bearer {self.intezer_token}"

        summary_url = f"/files/{self.observable_name}"

        dict_result = {}
        logger.info(f"intezer md5 about to get data for {self.observable_name}")
        response = session.get(self.base_url + summary_url)
        if response.status_code == 404:
            dict_result["not_found"] = True
        elif response.status_code == 200:
            json_response = response.json()
            dict_result = json_response
        else:
            response.raise_for_status()
            logger.debug(
                f"intezer md5 {self.observable_name} status code {response.status_code}"
            )

        return dict_result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
