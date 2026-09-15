# Client, metadata and errors

Official Shodan SDK excerpts for `shodan==1.31.0`, revision `87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8`. These are developer API references; hunting agents submit through the gateway. [Index](README.md).

The adapter runs this synchronous SDK outside the event loop and replaces its private `_session` with a Requests session that applies timeouts, disables redirects and environment trust, captures responses, and counts dispatches. The base URL is fixed to Shodan. Requests defaults alone are insufficient. `info()` serves connectivity checks, not hunting queries. HTTP status determines safe failure codes because `APIError` does not retain it. SDK source excerpts below describe upstream behavior; the gateway supplies these controls.

Source: [shodan/client.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L294), original lines 294–324.

```python
    def __init__(self, key, proxies=None):
        """Initializes the API object.

        :param key: The Shodan API key.
        :type key: str
        :param proxies: A proxies array for the requests library, e.g. {'https': 'your proxy'}
        :type proxies: dict
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.base_exploits_url = 'https://exploits.shodan.io'
        self.base_trends_url = 'https://trends.shodan.io'
        self.data = self.Data(self)
        self.dns = self.Dns(self)
        self.exploits = self.Exploits(self)
        self.trends = self.Trends(self)
        self.labs = self.Labs(self)
        self.notifier = self.Notifier(self)
        self.org = self.Organization(self)
        self.tools = self.Tools(self)
        self.stream = Stream(key, proxies=proxies)
        self._session = requests.Session()
        self.api_rate_limit = 1  # Requests per second
        self._api_query_time = None

        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False

        if os.environ.get('SHODAN_API_URL'):
            self.base_url = os.environ.get('SHODAN_API_URL')
```

Source: [shodan/client.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L326), original lines 326–404.

```python
    def _request(self, function, params, service='shodan', method='get', json_data=None):
        """General-purpose function to create web requests to SHODAN.

        Arguments:
            function  -- name of the function you want to execute
            params    -- dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """
        # Add the API key parameter automatically
        params['key'] = self.api_key

        # Determine the base_url based on which service we're interacting with
        base_url = {
            'shodan': self.base_url,
            'exploits': self.base_exploits_url,
            'trends': self.base_trends_url,
        }.get(service, 'shodan')

        # Wait for API rate limit
        if self._api_query_time is not None and self.api_rate_limit > 0:
            while (1.0 / self.api_rate_limit) + self._api_query_time >= time.time():
                time.sleep(0.1 / self.api_rate_limit)

        # Send the request
        try:
            method = method.lower()
            if method == 'post':
                if json_data:
                    data = self._session.post(base_url + function, params=params,
                                            data=json.dumps(json_data),
                                            headers={'content-type': 'application/json'},
                        )
                else:
                    data = self._session.post(base_url + function, params)
            elif method == 'put':
                data = self._session.put(base_url + function, params=params)
            elif method == 'delete':
                data = self._session.delete(base_url + function, params=params)
            else:
                data = self._session.get(base_url + function, params=params)
            self._api_query_time = time.time()
        except Exception:
            raise APIError('Unable to connect to Shodan')

        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                # If the response looks like HTML then it's probably the 401 page that nginx returns
                # for 401 responses by default
                if data.text.startswith('<'):
                    error = 'Invalid API key'
                else:
                    # Otherwise lets raise the error message
                    error = u'{}'.format(e)

            raise APIError(error)
        elif data.status_code == 403:
            raise APIError('Access denied (403 Forbidden)')
        elif data.status_code == 502:
            raise APIError('Bad Gateway (502)')

        # Parse the text into JSON
        try:
            data = data.json()
        except ValueError:
            raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])

        # Return the data
        return data
```

Source: [shodan/client.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L443), original lines 443–447.

```python
    def info(self):
        """Returns information about the current API key, such as a list of add-ons
        and other features that are enabled for the current user's API plan.
        """
        return self._request('/api-info', {})
```

Source: [shodan/exception.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/exception.py#L1), original lines 1–7.

```python
class APIError(Exception):
    """This exception gets raised whenever a non-200 status code was returned by the Shodan API."""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
```
