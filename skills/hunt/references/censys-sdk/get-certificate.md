# get_certificate

Official Censys SDK excerpts, package `censys-platform==0.16.2`, revision `43a8a3ac1161e655eff3061ba3b7ab934c185c55`. Read only the method relevant to the current task. These SDK examples are developer references; hunting agents submit through the gateway. [Index](README.md).

The gateway and SDK take a SHA-256 certificate fingerprint as `certificate_id`. A certificate's validity interval does not date a deployment or host association.

## Official operation documentation

Source: [docs/sdks/globaldata/README.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/sdks/globaldata/README.md#L127); original lines 127–170.

## get_certificate

Retrieve information about a single certificate. A certificate ID is its SHA-256 fingerprint in the Censys dataset.

### Example Usage

<!-- UsageSnippet language="python" operationID="v3-globaldata-asset-certificate" method="get" path="/v3/global/asset/certificate/{certificate_id}" -->
```python
from censys_platform import SDK


with SDK(
    organization_id="11111111-2222-3333-4444-555555555555",
    personal_access_token="<YOUR_BEARER_TOKEN_HERE>",
) as sdk:

    res = sdk.global_data.get_certificate(certificate_id="3daf2843a77b6f4e6af43cd9b6f6746053b8c928e056e8a724808db8905a94cf")

    # Handle response
    print(res)

```

### Parameters

| Parameter                                                                                                                                                                                                                                                                                                                   | Type                                                                                                                                                                                                                                                                                                                        | Required                                                                                                                                                                                                                                                                                                                    | Description                                                                                                                                                                                                                                                                                                                 | Example                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `certificate_id`                                                                                                                                                                                                                                                                                                            | *str*                                                                                                                                                                                                                                                                                                                       | :heavy_check_mark:                                                                                                                                                                                                                                                                                                          | The SHA-256 certificate fingerprint.                                                                                                                                                                                                                                                                                        | 3daf2843a77b6f4e6af43cd9b6f6746053b8c928e056e8a724808db8905a94cf                                                                                                                                                                                                                                                            |
| `organization_id`                                                                                                                                                                                                                                                                                                           | *Optional[str]*                                                                                                                                                                                                                                                                                                             | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | The ID of a Censys organization to associate the request with. If omitted, the request will be processed using the authenticated user's free wallet where applicable. See the [Getting Started docs](https://docs.censys.com/reference/get-started#step-3-find-and-use-your-organization-id-optional) for more information. |                                                                                                                                                                                                                                                                                                                             |
| `retries`                                                                                                                                                                                                                                                                                                                   | [Optional[utils.RetryConfig]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/utils/retryconfig.md)                                                                                                                                                                                                                                                            | :heavy_minus_sign:                                                                                                                                                                                                                                                                                                          | Configuration to override the default retry behavior of the client.                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                             |

### Response

**[models.V3GlobaldataAssetCertificateResponse](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassetcertificateresponse.md)**

### Errors

| Error Type                 | Status Code                | Content Type               |
| -------------------------- | -------------------------- | -------------------------- |
| models.AuthenticationError | 401                        | application/json           |
| models.ErrorModel          | 400, 403, 404              | application/problem+json   |
| models.ErrorModel          | 500                        | application/problem+json   |
| models.SDKError            | 4XX, 5XX                   | \*/\*                      |

## Exact async signature

Source: [src/censys_platform/global_data.py](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/src/censys_platform/global_data.py#L614); original lines 614–623.

```python
    async def get_certificate_async(
        self,
        *,
        certificate_id: str,
        organization_id: Optional[str] = None,
        retries: OptionalNullable[utils.RetryConfig] = UNSET,
        server_url: Optional[str] = None,
        timeout_ms: Optional[int] = None,
        http_headers: Optional[Mapping[str, str]] = None,
    ) -> models.V3GlobaldataAssetCertificateResponse:
```

## Official model: v3globaldataassetcertificateresponse

Source: [docs/models/v3globaldataassetcertificateresponse.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/v3globaldataassetcertificateresponse.md#L1); original lines 1–9.

# V3GlobaldataAssetCertificateResponse


## Fields

| Field                                                                                    | Type                                                                                     | Required                                                                                 | Description                                                                              |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `headers`                                                                                | Dict[str, List[*str*]]                                                                   | :heavy_check_mark:                                                                       | N/A                                                                                      |
| `result`                                                                                 | [models.ResponseEnvelopeCertificateAsset](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopecertificateasset.md) | :heavy_check_mark:                                                                       | N/A                                                                                      |

## Official model: responseenvelopecertificateasset

Source: [docs/models/responseenvelopecertificateasset.md](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/responseenvelopecertificateasset.md#L1); original lines 1–8.

# ResponseEnvelopeCertificateAsset


## Fields

| Field                                                              | Type                                                               | Required                                                           | Description                                                        |
| ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `result`                                                           | [Optional[models.CertificateAsset]](https://github.com/censys/censys-sdk-python/blob/43a8a3ac1161e655eff3061ba3b7ab934c185c55/docs/models/certificateasset.md) | :heavy_minus_sign:                                                 | N/A                                                                |
