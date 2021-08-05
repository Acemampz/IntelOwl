# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.file_analyzers.intezer_scan import (
    get_access_token,
    get_intezer_base_url,
)

from tests.mock_utils import if_mock_connections, patch, MockResponse

logger = logging.getLogger(__name__)


class IntezerGet(classes.ObservableAnalyzer):
    base_url: str = get_intezer_base_url()

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        # retrieve detailed analysis
        self.detailed_analysis = params.get("detailed_analysis", True)
        # intezer access token
        self.intezer_token = get_access_token(self.__api_key)

    def run(self):
        return self.__intezer_analysis()

    def __intezer_analysis(self):
        session = requests.session()
        session.headers["Authorization"] = f"Bearer {self.intezer_token}"

        summary_url = f"/files/{self.observable_name}"

        dict_result = {}
        analysis_succeded = False
        logger.info(f"intezer md5 about to get data for {self.observable_name}")
        response = session.get(self.base_url + summary_url)
        response.raise_for_status()
        json_response = response.json()
        if response.status_code == 200:
            dict_result = json_response
            success = json_response.get("status", "")
            if success == "succeeded":
                analysis_succeded = True
        else:
            logger.debug(
                f"intezer md5 {self.observable_name} status code {response.status_code}"
            )

        # retrieve detailed analysis
        if self.detailed_analysis and analysis_succeded:
            analysis_id = dict_result.get("result", {}).get("analysis_id", "")
            detailed_analysis_url = f"/analyses/{analysis_id}/root"
            response = session.get(self.base_url + detailed_analysis_url)
            if response.status_code == 200:
                dict_result["detailed_analysis"] = response.json()
                dict_result["detailed_analysis"]["success"] = True
            else:
                dict_result["detailed_analysis"] = {"success": False}

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
