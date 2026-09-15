"""Offline Requests transport for existing HTTPX-shaped Shodan benchmark fixtures."""

from collections.abc import Callable
from typing import Any

import httpx
import requests
from requests.adapters import BaseAdapter


class ShodanFixtureTransport(BaseAdapter):
    """Exercise the real SDK without a network-capable transport."""

    def __init__(self, respond: Callable[[httpx.Request], httpx.Response]):
        self.respond = respond

    def send(
        self, request: requests.PreparedRequest, *args: Any, **kwargs: Any
    ) -> requests.Response:
        raw = self.respond(httpx.Request(request.method or "GET", request.url or ""))
        response = requests.Response()
        response.status_code = raw.status_code
        response.headers.update(raw.headers)
        response._content = raw.read()
        response.encoding = "utf-8"
        response.request = request
        response.url = request.url or ""
        return response

    def close(self) -> None:
        pass
