# get_host_timeline

Official Censys SDK excerpts, package `censys-platform==0.16.2`, revision `43a8a3ac1161e655eff3061ba3b7ab934c185c55`. Read only the method relevant to the current task. These SDK examples are developer references; hunting agents submit through the gateway. [Index](README.md).

Gateway time bounds are chronological: `start_time` is oldest, `end_time` is newest. The SDK uses the opposite names: pass the gateway upper bound as SDK `start_time`, and its lower bound as SDK `end_time`. `scanned_to` is retained raw; the harness owns continuation. There is no SDK auto-pagination or adjustable timeline page size.

## Official operation documentation

Source: [docs/sdks/globaldata/README.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/globaldata/README.md#L408); original lines 408–454.

## get_host_timeline

Retrieve event history for a host. A host ID is its IP address.<br><br>Note that when a service protocol changes after a new scan (for example, from `UNKNOWN` to `NETBIOS`), this information will be reflected in the `scan` object.

### Example Usage

<!-- UsageSnippet language="python" operationID="v3-globaldata-asset-host-timeline" method="get" path="/v3/global/asset/host/{host_id}/timeline" -->
```python
from censys_platform import SDK
from censys_platform.utils import parse_datetime


with SDK(
    organization_id="11111111-2222-3333-4444-555555555555",
    personal_access_token="<YOUR_BEARER_TOKEN_HERE>",
) as sdk:

    res = sdk.global_data.get_host_timeline(host_id="8.8.8.8", start_time=parse_datetime("2025-01-02T00:00:00Z"), end_time=parse_datetime("2025-01-01T00:00:00Z"))

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                                                                                                                                                                                                                                                     | Type                                                                                                                                                                                                                                                                                                                                                                          | Required                                                                                                                                                                                                                                                                                                                                                                      | Description                                                                                                                                                                                                                                                                                                                                                                   | Example                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `host_id`                                                                                                                                                                                                                                                                                                                                                                     | *str*                                                                                                                                                                                                                                                                                                                                                                         | :heavy_check_mark:                                                                                                                                                                                                                                                                                                                                                            | The IP address of a host.                                                                                                                                                                                                                                                                                                                                                     | 8.8.8.8                                                                                                                                                                                                                                                                                                                                                                       |
| `start_time`                                                                                                                                                                                                                                                                                                                                                                  | [date](https://docs.python.org/3/library/datetime.html#date-objects)                                                                                                                                                                                                                                                                                                          | :heavy_check_mark:                                                                                                                                                                                                                                                                                                                                                            | Start time of the host timeline. Equivalent to the To field in the event history UI. This must be the timestamp closest to the current time. For example, if you want events from January 1, 2025 to the start of January 2, 2025, input the January 2 timestamp here. Must be a valid RFC3339 string. Ensure that you suffix the date with T00:00:00Z or a specific time.    | 2025-01-02T00:00:00Z                                                                                                                                                                                                                                                                                                                                                          |
| `end_time`                                                                                                                                                                                                                                                                                                                                                                    | [date](https://docs.python.org/3/library/datetime.html#date-objects)                                                                                                                                                                                                                                                                                                          | :heavy_check_mark:                                                                                                                                                                                                                                                                                                                                                            | End time of the host timeline. Equivalent to the From field in the event history UI. This must be the timestamp furthest from the current time. For example, if you want events from January 1, 2025 to the start of January 2, 2025, input the January 1 timestamp here. Must be a valid RFC3339 string. Ensure that you suffix the date with T00:00:00Z or a specific time. | 2025-01-01T00:00:00Z                                                                                                                                                                                                                                                                                                                                                          |
| `organization_id`                                                                                                                                                                                                                                                                                                                                                             | *Optional[str]*                                                                                                                                                                                                                                                                                                                                                               | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                                                                            | The ID of a Censys organization to associate the request with. If omitted, the request will be processed using the authenticated user's free wallet where applicable. See the [Getting Started docs](https://docs.censys.com/reference/get-started#step-3-find-and-use-your-organization-id-optional) for more information.                                                   |                                                                                                                                                                                                                                                                                                                                                                               |
| `retries`                                                                                                                                                                                                                                                                                                                                                                     | [Optional[utils.RetryConfig]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/utils/retryconfig.md)                                                                                                                                                                                                                                                                                                              | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                                                                            | Configuration to override the default retry behavior of the client.                                                                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                                                               |

### Response

**[models.V3GlobaldataAssetHostTimelineResponse](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassethosttimelineresponse.md)**

### Errors

| Error Type                 | Status Code                | Content Type               |
| -------------------------- | -------------------------- | -------------------------- |
| models.AuthenticationError | 401                        | application/json           |
| models.ErrorModel          | 400, 403, 404              | application/problem+json   |
| models.ErrorModel          | 500                        | application/problem+json   |
| models.SDKError            | 4XX, 5XX                   | \*/\*                      |

## Exact async signature

Source: [src/censys_platform/global_data.py](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/global_data.py#L1990); original lines 1990–2001.

```python
    async def get_host_timeline_async(
        self,
        *,
        host_id: str,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[str] = None,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.V3GlobaldataAssetHostTimelineResponse:
```

## Official model: v3globaldataassethosttimelineresponse

Source: [docs/models/v3globaldataassethosttimelineresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassethosttimelineresponse.md#L1); original lines 1–9.

# V3GlobaldataAssetHostTimelineResponse


## Fields

| Field                                                                            | Type                                                                             | Required                                                                         | Description                                                                      |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `headers`                                                                        | Dict[str, List[*str*]]                                                           | :heavy_check_mark:                                                               | N/A                                                                              |
| `result`                                                                         | [models.ResponseEnvelopeHostTimeline](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopehosttimeline.md) | :heavy_check_mark:                                                               | N/A                                                                              |

## Official model: responseenvelopehosttimeline

Source: [docs/models/responseenvelopehosttimeline.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopehosttimeline.md#L1); original lines 1–8.

# ResponseEnvelopeHostTimeline


## Fields

| Field                                                      | Type                                                       | Required                                                   | Description                                                |
| ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- |
| `result`                                                   | [Optional[models.HostTimeline]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/hosttimeline.md) | :heavy_minus_sign:                                         | N/A                                                        |

## Official model: hosttimeline

Source: [docs/models/hosttimeline.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/hosttimeline.md#L1); original lines 1–9.

# HostTimeline


## Fields

| Field                                                                      | Type                                                                       | Required                                                                   | Description                                                                |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `events`                                                                   | List[[models.HostTimelineEventAsset](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/hosttimelineeventasset.md)] | :heavy_check_mark:                                                         | N/A                                                                        |
| `scanned_to`                                                               | [date](https://docs.python.org/3/library/datetime.html#date-objects)       | :heavy_check_mark:                                                         | N/A                                                                        |

## Official model: hosttimelineevent

Source: [docs/models/hosttimelineevent.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/hosttimelineevent.md#L1); original lines 1–16.

# HostTimelineEvent


## Fields

| Field                                                                  | Type                                                                   | Required                                                               | Description                                                            |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `endpoint_scanned`                                                     | [Optional[models.EndpointScanned]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/endpointscanned.md)       | :heavy_minus_sign:                                                     | N/A                                                                    |
| `event_time`                                                           | *Optional[str]*                                                        | :heavy_minus_sign:                                                     | N/A                                                                    |
| `forward_dns_resolved`                                                 | [Optional[models.ForwardDNSResolved]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/forwarddnsresolved.md) | :heavy_minus_sign:                                                     | N/A                                                                    |
| `jarm_scanned`                                                         | [Optional[models.JarmScanned]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/jarmscanned.md)               | :heavy_minus_sign:                                                     | N/A                                                                    |
| `location_updated`                                                     | [Optional[models.LocationUpdated]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/locationupdated.md)       | :heavy_minus_sign:                                                     | N/A                                                                    |
| `reverse_dns_resolved`                                                 | [Optional[models.ReverseDNSResolved]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/reversednsresolved.md) | :heavy_minus_sign:                                                     | N/A                                                                    |
| `route_updated`                                                        | [Optional[models.RouteUpdated]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/routeupdated.md)             | :heavy_minus_sign:                                                     | N/A                                                                    |
| `service_scanned`                                                      | [Optional[models.ServiceScanned]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/servicescanned.md)         | :heavy_minus_sign:                                                     | N/A                                                                    |
| `whois_updated`                                                        | [Optional[models.WhoisUpdated]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/whoisupdated.md)             | :heavy_minus_sign:                                                     | N/A                                                                    |
