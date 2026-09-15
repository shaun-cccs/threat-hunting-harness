# get_host

Official Censys SDK excerpts, package `censys-platform==0.16.2`, revision `43a8a3ac1161e655eff3061ba3b7ab934c185c55`. Read only the method relevant to the current task. These SDK examples are developer references; hunting agents submit through the gateway. [Index](README.md).

The gateway accepts `host_id` and optional `at_time`; omitted `at_time` requests the current provider record. The SDK takes a timezone-aware `datetime` or `None`. Observation time comes from returned service data, not the requested snapshot time.

## Official operation documentation

Source: [docs/sdks/globaldata/README.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/globaldata/README.md#L310); original lines 310–355.

## get_host

Retrieve information about a single host. A host ID is its IP address.

### Example Usage

<!-- UsageSnippet language="python" operationID="v3-globaldata-asset-host" method="get" path="/v3/global/asset/host/{host_id}" -->
```python
from censys_platform import SDK
from censys_platform.utils import parse_datetime


with SDK(
    organization_id="11111111-2222-3333-4444-555555555555",
    personal_access_token="<YOUR_BEARER_TOKEN_HERE>",
) as sdk:

    res = sdk.global_data.get_host(host_id="8.8.8.8", at_time=parse_datetime("2025-01-01T00:00:00Z"))

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                                                                                                                                                                                                   | Type                                                                                                                                                                                                                                                                                                                        | Required                                                                                                                                                                                                                                                                                                                    | Description                                                                                                                                                                                                                                                                                                                 | Example                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `host_id`                                                                                                                                                                                                                                                                                                                   | *str*                                                                                                                                                                                                                                                                                                                       | :heavy_check_mark:                                                                                                                                                                                                                                                                                                          | The IP address of a host.                                                                                                                                                                                                                                                                                                   | 8.8.8.8                                                                                                                                                                                                                                                                                                                     |
| `organization_id`                                                                                                                                                                                                                                                                                                           | *Optional[str]*                                                                                                                                                                                                                                                                                                             | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | The ID of a Censys organization to associate the request with. If omitted, the request will be processed using the authenticated user's free wallet where applicable. See the [Getting Started docs](https://docs.censys.com/reference/get-started#step-3-find-and-use-your-organization-id-optional) for more information. |                                                                                                                                                                                                                                                                                                                             |
| `at_time`                                                                                                                                                                                                                                                                                                                   | [date](https://docs.python.org/3/library/datetime.html#date-objects)                                                                                                                                                                                                                                                        | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | RFC3339 Timestamp to view a host at a specific point in time. Must be a valid RFC3339 string. Ensure that you suffix the date with T00:00:00Z or a specific time.                                                                                                                                                           | 2025-01-01T00:00:00Z                                                                                                                                                                                                                                                                                                        |
| `retries`                                                                                                                                                                                                                                                                                                                   | [Optional[utils.RetryConfig]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/utils/retryconfig.md)                                                                                                                                                                                                                                                            | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | Configuration to override the default retry behavior of the client.                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                             |

### Response

**[models.V3GlobaldataAssetHostResponse](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassethostresponse.md)**

### Errors

| Error Type                 | Status Code                | Content Type               |
| -------------------------- | -------------------------- | -------------------------- |
| models.AuthenticationError | 401                        | application/json           |
| models.ErrorModel          | 400, 403, 404              | application/problem+json   |
| models.ErrorModel          | 500                        | application/problem+json   |
| models.SDKError            | 4XX, 5XX                   | \*/\*                      |

## Exact async signature

Source: [src/censys_platform/global_data.py](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/global_data.py#L1541); original lines 1541–1551.

```python
    async def get_host_async(
        self,
        *,
        host_id: str,
        organization_id: Optional[str] = None,
        at_time: Optional[datetime] = None,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.V3GlobaldataAssetHostResponse:
```

## Official model: v3globaldataassethostresponse

Source: [docs/models/v3globaldataassethostresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassethostresponse.md#L1); original lines 1–9.

# V3GlobaldataAssetHostResponse


## Fields

| Field                                                                      | Type                                                                       | Required                                                                   | Description                                                                |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `headers`                                                                  | Dict[str, List[*str*]]                                                     | :heavy_check_mark:                                                         | N/A                                                                        |
| `result`                                                                   | [models.ResponseEnvelopeHostAsset](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopehostasset.md) | :heavy_check_mark:                                                         | N/A                                                                        |

## Official model: responseenvelopehostasset

Source: [docs/models/responseenvelopehostasset.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopehostasset.md#L1); original lines 1–8.

# ResponseEnvelopeHostAsset


## Fields

| Field                                                | Type                                                 | Required                                             | Description                                          |
| ---------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| `result`                                             | [Optional[models.HostAsset]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/hostasset.md) | :heavy_minus_sign:                                   | N/A                                                  |
