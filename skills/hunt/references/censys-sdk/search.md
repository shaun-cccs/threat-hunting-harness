# search

Official Censys SDK excerpts, package `censys-platform==0.16.2`, revision `43a8a3ac1161e655eff3061ba3b7ab934c185c55`. Read only the method relevant to the current task. These SDK examples are developer references; hunting agents submit through the gateway. [Index](README.md).

The gateway accepts `query`, optional `fields`, `page_size` (gateway default 50; maximum 100), and optional `page_token`. The SDK receives these in `search_query_input_body`. The official SDK schema permits nullable `fields` and `page_size`; the gateway schema remains authoritative for analyst inputs. Missing fields may limit evidence interpretation.

## Official operation documentation

Source: [docs/sdks/globaldata/README.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/globaldata/README.md#L1000); original lines 1000–1048.

## search

Run a search query across Censys data. Reference the [documentation on Censys Query Language](https://docs.censys.com/docs/censys-query-language#/) for information about query syntax. Host services that match your search criteria will be returned in a `matched_services` object.

### Example Usage

<!-- UsageSnippet language="python" operationID="v3-globaldata-search-query" method="post" path="/v3/global/search/query" -->
```python
from censys_platform import SDK


with SDK(
    organization_id="11111111-2222-3333-4444-555555555555",
    personal_access_token="<YOUR_BEARER_TOKEN_HERE>",
) as sdk:

    res = sdk.global_data.search(search_query_input_body={
        "fields": [
            "host.ip",
        ],
        "page_size": 1,
        "query": "host.services: (protocol=SSH and not port: 22)",
    })

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                                                                                                                                                                                                   | Type                                                                                                                                                                                                                                                                                                                        | Required                                                                                                                                                                                                                                                                                                                    | Description                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `search_query_input_body`                                                                                                                                                                                                                                                                                                   | [models.SearchQueryInputBody](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/searchqueryinputbody.md)                                                                                                                                                                                                                                                         | :heavy_check_mark:                                                                                                                                                                                                                                                                                                          | N/A                                                                                                                                                                                                                                                                                                                         |
| `organization_id`                                                                                                                                                                                                                                                                                                           | *Optional[str]*                                                                                                                                                                                                                                                                                                             | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | The ID of a Censys organization to associate the request with. If omitted, the request will be processed using the authenticated user's free wallet where applicable. See the [Getting Started docs](https://docs.censys.com/reference/get-started#step-3-find-and-use-your-organization-id-optional) for more information. |
| `retries`                                                                                                                                                                                                                                                                                                                   | [Optional[utils.RetryConfig]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/utils/retryconfig.md)                                                                                                                                                                                                                                                            | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | Configuration to override the default retry behavior of the client.                                                                                                                                                                                                                                                         |

### Response

**[models.V3GlobaldataSearchQueryResponse](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldatasearchqueryresponse.md)**

### Errors

| Error Type                 | Status Code                | Content Type               |
| -------------------------- | -------------------------- | -------------------------- |
| models.AuthenticationError | 401                        | application/json           |
| models.ErrorModel          | 400, 403, 422              | application/problem+json   |
| models.ErrorModel          | 500                        | application/problem+json   |
| models.SDKError            | 4XX, 5XX                   | \*/\*                      |

## Exact async signature

Source: [src/censys_platform/global_data.py](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/global_data.py#L4763); original lines 4763–4774.

```python
    async def search_async(
        self,
        *,
        search_query_input_body: Union[
            models.SearchQueryInputBody, models.SearchQueryInputBodyTypedDict
        ],
        organization_id: Optional[str] = None,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.V3GlobaldataSearchQueryResponse:
```

## Official model: searchqueryinputbody

Source: [docs/models/searchqueryinputbody.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/searchqueryinputbody.md#L1); original lines 1–11.

# SearchQueryInputBody


## Fields

| Field                                                                                                                                                                                                                               | Type                                                                                                                                                                                                                                | Required                                                                                                                                                                                                                            | Description                                                                                                                                                                                                                         | Example                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fields`                                                                                                                                                                                                                            | List[*str*]                                                                                                                                                                                                                         | :heavy_minus_sign:                                                                                                                                                                                                                  | Specify fields to only return in the response. If you provide fields and omit `host.services.port`, `host.services.transport_protocol`, and `host.services.protocol`, then `matched_services` will not be returned in the response. | host.ip                                                                                                                                                                                                                             |
| `page_size`                                                                                                                                                                                                                         | *OptionalNullable[int]*                                                                                                                                                                                                             | :heavy_minus_sign:                                                                                                                                                                                                                  | Number of results to return to per page. The default and maximum is 100.                                                                                                                                                            | 1                                                                                                                                                                                                                                   |
| `page_token`                                                                                                                                                                                                                        | *Optional[str]*                                                                                                                                                                                                                     | :heavy_minus_sign:                                                                                                                                                                                                                  | page token for the requested page of search results                                                                                                                                                                                 |                                                                                                                                                                                                                                     |
| `query`                                                                                                                                                                                                                             | *str*                                                                                                                                                                                                                               | :heavy_check_mark:                                                                                                                                                                                                                  | CenQL query string to search upon                                                                                                                                                                                                   | host.services: (protocol=SSH and not port: 22)                                                                                                                                                                                      |

## Official model: v3globaldatasearchqueryresponse

Source: [docs/models/v3globaldatasearchqueryresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldatasearchqueryresponse.md#L1); original lines 1–9.

# V3GlobaldataSearchQueryResponse


## Fields

| Field                                                                                          | Type                                                                                           | Required                                                                                       | Description                                                                                    |
| ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `headers`                                                                                      | Dict[str, List[*str*]]                                                                         | :heavy_check_mark:                                                                             | N/A                                                                                            |
| `result`                                                                                       | [models.ResponseEnvelopeSearchQueryResponse](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopesearchqueryresponse.md) | :heavy_check_mark:                                                                             | N/A                                                                                            |

## Official model: responseenvelopesearchqueryresponse

Source: [docs/models/responseenvelopesearchqueryresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopesearchqueryresponse.md#L1); original lines 1–8.

# ResponseEnvelopeSearchQueryResponse


## Fields

| Field                                                                    | Type                                                                     | Required                                                                 | Description                                                              |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `result`                                                                 | [Optional[models.SearchQueryResponse]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/searchqueryresponse.md) | :heavy_minus_sign:                                                       | N/A                                                                      |

## Official model: searchqueryresponse

Source: [docs/models/searchqueryresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/searchqueryresponse.md#L1); original lines 1–12.

# SearchQueryResponse


## Fields

| Field                                                      | Type                                                       | Required                                                   | Description                                                |
| ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- |
| `hits`                                                     | List[[models.SearchQueryHit](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/searchqueryhit.md)] | :heavy_check_mark:                                         | N/A                                                        |
| `next_page_token`                                          | *str*                                                      | :heavy_check_mark:                                         | N/A                                                        |
| `previous_page_token`                                      | *str*                                                      | :heavy_check_mark:                                         | N/A                                                        |
| `query_duration_millis`                                    | *int*                                                      | :heavy_check_mark:                                         | N/A                                                        |
| `total_hits`                                               | *float*                                                    | :heavy_check_mark:                                         | N/A                                                        |
