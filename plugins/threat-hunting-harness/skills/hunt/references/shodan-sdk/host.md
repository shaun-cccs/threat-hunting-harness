# Host history

Official Shodan SDK excerpts for `shodan==1.31.0`, revision `87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8`. These are developer API references; hunting agents submit through the gateway. [Index](README.md).

The gateway calls `host(ip, history=history, minify=False)`, defaulting history to true. False options are omitted on the wire. The response contains host metadata and `data` banners. Preserve each banner timestamp; the upstream method establishes no complete history bounds. [REST contract](https://developer.shodan.io/api#shodan-host-details).

Source: [shodan/client.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L423), original lines 423–441.

```python
    def host(self, ips, history=False, minify=False):
        """Get all available information on an IP.

        :param ip: IP of the computer
        :type ip: str
        :param history: (optional) True if you want to grab the historical (non-current) banners for the host, False otherwise.
        :type history: bool
        :param minify: (optional) True to only return the list of ports and the general host information, no banners, False otherwise.
        :type minify: bool
        """
        if isinstance(ips, basestring):
            ips = [ips]

        params = {}
        if history:
            params['history'] = history
        if minify:
            params['minify'] = minify
        return self._request('/shodan/host/{}'.format(','.join(ips)), params)
```
