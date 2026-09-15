# Search and explicit pages

Official Shodan SDK excerpts for `shodan==1.31.0`, revision `87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8`. These are developer API references; hunting agents submit through the gateway. [Index](README.md).

The gateway calls `search(query, page=page, minify=False)`. This overrides upstream truncation and retains full banners. Each page is a separate gateway query. The SDK cursor automatically pages and retries; it is outside this adapter. `matches` are the returned banners and `total` is the reported total. [REST contract](https://developer.shodan.io/api#shodan-host-search).

Source: [shodan/client.py](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L534), original lines 534–571.

```python
    def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True, fields=None):
        """Search the SHODAN database.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param page: (optional) Page number of the search results
        :type page: int
        :param limit: (optional) Number of results to return
        :type limit: int
        :param offset: (optional) Search offset to begin getting results from
        :type offset: int
        :param facets: (optional) A list of properties to get summary information on
        :type facets: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        :param fields: (optional) List of properties that should get returned. This option is mutually exclusive with the "minify" parameter
        :type fields: str

        :returns: A dictionary with 2 main items: matches and total. If facets have been provided then another property called "facets" will be available at the top-level of the dictionary. Visit the website for more detailed information.
        """
        args = {
            'query': query,
            'minify': minify,
        }
        if limit:
            args['limit'] = limit
            if offset:
                args['offset'] = offset
        else:
            args['page'] = page

        if facets:
            args['facets'] = create_facet_string(facets)

        if fields and isinstance(fields, list):
            args['fields'] = ','.join(fields)

        return self._request('/shodan/host/search', args)
```

Source: [docs/tutorial.rst](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/docs/tutorial.rst#L62), original lines 62–88.

```rst
Stepping through the code, we first call the :py:func:`Shodan.search` method on the `api` object which
returns a dictionary of result information. We then print how many results were found in total,
and finally loop through the returned matches and print their IP and banner. Each page of search results
contains up to 100 results.

There's a lot more information that gets returned by the function. See below for a shortened example
dictionary that :py:func:`Shodan.search` returns:

.. code-block:: python

	{
		'total': 8669969,
		'matches': [
			{
				'data': 'HTTP/1.0 200 OK\r\nDate: Mon, 08 Nov 2010 05:09:59 GMT\r\nSer...',
				'hostnames': ['pl4t1n.de'],
				'ip': 3579573318,
				'ip_str': '89.110.147.239',
				'os': 'FreeBSD 4.4',
				'port': 80,
				'timestamp': '2014-01-15T05:49:56.283713'
			},
			...
		]
	}

Please visit the `REST API documentation <https://developer.shodan.io/api>`_ for the complete list of properties that the methods can return.
```
