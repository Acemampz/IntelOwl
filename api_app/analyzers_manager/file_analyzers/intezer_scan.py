# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
import os
import time
import requests
import logging
from datetime import datetime, timedelta

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.helpers import get_now_str, get_now, get_binary

from tests.mock_utils import (
    patch,
    if_mock_connections,
    MagicMock,
    MockResponse,
)

logger = logging.getLogger(__name__)


def _retrieve_access_token_from_intezer(api_key):
    """
    this should be done just once in a day
    """
    base_url = "https://analyze.intezer.com/api/v2-0"
    response = requests.post(
        base_url + "/get-access-token", json={"api_key": api_key}
    )  # lgtm [py/uninitialized-local-variable]
    response.raise_for_status()
    response_json = response.json()
    token = response_json.get("result", "")
    os.environ["INTEZER_TOKEN"] = token
    os.environ["INTEZER_TOKEN_DATE"] = get_now_str()
    return token


def get_access_token(api_key):
    intezer_token = os.environ.get("INTEZER_TOKEN", "")
    intezer_token_date = os.environ.get("INTEZER_TOKEN_DATE", None)
    intezer_token_datetime_object = datetime.strptime(
        intezer_token_date, "%Y-%m-%d %H:%M:%S"
    )
    now = get_now()
    if not intezer_token or (intezer_token_datetime_object < now - timedelta(hours=9)):
        intezer_token = _retrieve_access_token_from_intezer(api_key)
        if not intezer_token:
            raise AnalyzerRunException("token extraction failed")

    return intezer_token


def get_intezer_base_url():
    return "https://analyze.intezer.com/api/v2-0"


class IntezerScan(FileAnalyzer):
    base_url: str = get_intezer_base_url()

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        # max no. of tries when polling for result
        self.max_tries = params.get("max_tries", 200)
        # interval b/w HTTP requests when polling
        self.poll_distance = params.get("poll_distance", 2)
        # retrieve detailed analysis
        self.detailed_analysis = params.get("detailed_analysis", True)
        # upload file or not
        self.upload_file = params.get("upload_file", True)
        # intezer access token
        self.intezer_token = get_access_token(self.__api_key)

    def run(self):
        return self.__intezer_analysis()

    def __intezer_analysis(self):
        session = requests.session()
        session.headers["Authorization"] = f"Bearer {self.intezer_token}"

        if self.upload_file:
            name_to_send = self.filename if self.filename else self.md5
            binary = get_binary(self.job_id)
            files = {"file": (name_to_send, binary)}
            logger.info(f"intezer md5 {self.md5} sending sample for analysis")
            response = session.post(self.base_url + "/analyze", files=files)
            if response.status_code != 201:
                raise AnalyzerRunException(
                    f"failed analyze request, status code {response.status_code}"
                )
            summary_url = response.json().get("result_url", "")
        else:
            summary_url = f"/files/{self.md5}"

        dict_result = {}
        result_received = False
        analysis_succeded = False
        for chance in range(self.max_tries):
            # no need to wait if the sample was not uploaded
            if not (chance == 0 and not self.upload_file):
                time.sleep(self.poll_distance)
            logger.info(f"intezer md5 {self.md5} polling for result try #{chance + 1}")
            response = session.get(self.base_url + summary_url)
            response.raise_for_status()
            json_response = response.json()
            if response.status_code == 200:
                dict_result = json_response
                result_received = True
                success = json_response.get("status", "")
                if success == "succeeded":
                    analysis_succeded = True
                break
            else:
                logger.debug(
                    f"intezer md5 {self.md5} status code {response.status_code} "
                    f"for try #{chance + 1}. Trying again"
                )

        if not result_received and not settings.TEST_MODE:
            raise AnalyzerRunException("received max tries attempts")

        # retrieve detailed analysis
        if self.detailed_analysis and result_received and analysis_succeded:
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
                patch("requests.Session.get", return_value=MockResponse({}, 200)),
                patch("requests.Session.post", return_value=MockResponse({}, 201)),
                patch(
                    "api_app.analyzers_manager.file_analyzers.intezer_scan._get_access_token",  # noqa: E501
                    MagicMock(return_value="tokentest"),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
