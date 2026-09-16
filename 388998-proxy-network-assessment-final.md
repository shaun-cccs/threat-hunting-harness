# Proxy network assessment — 388998.xyz and eight associated zones

**Assessment date:** 16 September 2026  
**Subject:** Infrastructure associated with a probable commercial censorship-circumvention proxy service  
**Sources:** Censys Platform host, certificate and historical DNS observations; Certificate Transparency; Cloudflare Origin CA certificate and revocation records; retained GreyNoise classifications and activity tags  
**Collection boundary:** No direct connections to infrastructure in scope. Host findings reflect Censys observations.

## 1. Executive assessment

The infrastructure associated with `388998.xyz` is assessed with **high confidence** to support a commercial proxy-subscription service aimed at users circumventing Chinese internet restrictions. Its naming scheme groups nodes by geography, consumer ISP and apparent bandwidth tier. Management-panel evidence, shared certificates and coordinated historical DNS link **nine zones and 219 hostnames**.

The recorded inventory contains **65 addresses after excluding 12 Cloudflare addresses** from a 77-address union. It comprises 26 addresses provisionally grouped with consumer-access ISP networks, 31 hosting and support addresses, seven probable relays and one principal management address. Inventory membership records a DNS or certificate association; it does not establish ownership or a confirmed proxy exit at every address.

The strongest certificate link is a Cloudflare Origin CA wildcard for `*.388998.xyz`, presented by **16 hosts across nine named providers and six country/territory codes**. Together with DNS evidence, this strongly supports coordinated operation. The observations do not establish that every host stores the certificate's private key: TLS forwarding can expose the same certificate at multiple addresses.

Consumer-ISP addresses account for **26 of the 57 addresses in the consumer and hosting/support groups (46%)**. This is an address classification, not a measured share of residential egress or traffic. Synology services and shared NAT gateways indicate a mixture of small-site hardware and reseller infrastructure. Owner participation, consent and the ultimate egress paths remain unverified.

The principal management hostname, **`3xui.mydocshub.org`**, maps to **`13.212.96.176` (AWS Singapore)** in the snapshot. Historical DNS links it to six additional AWS and Linode addresses. Two consumer-ISP nodes also connect the estate to a 27-host HAProxy/Mieru/AnyTLS fleet, supporting a probable operational relationship without establishing a common owner.

**The operator's identity is not established.** Later GreyNoise enrichment classified six associated IPs as malicious and two as suspicious, including exploit-attempt tags for the Canadian node. Censys history across these eight addresses shows persistent hosted proxy deployments and changing public-IP service populations, with one SSH identity recurring across two HKT addresses. The observations do not establish successful compromise or determine whether traffic originated with the operator, a customer or another party using shared infrastructure. See §4.3 and §5.2.

## 2. Infrastructure and attribution

### 2.1 Associated zones

The counts below describe the recorded certificate and hostname enumeration, including historical names. They are not counts of currently resolving services.

| Zone | CT certificates | Hostnames | Assessed role |
|---|---:|---:|---|
| `388998.xyz` | 45 | 8 | Original certificate history; anchor wildcard certificate |
| `388898.xyz` | 381 | 71 | Main node namespace |
| `piaomiaox.com` | 25 | 18 | ISP- and bandwidth-labelled nodes |
| `pmxu.link` | 126 | 61 | Historical node catalogue; no live DNS recorded in the snapshot |
| `mydocshub.org` | 102 | 18 | Management, documentation and subscription-related names |
| `848999.xyz` | 110 | 12 | Storefront, management and API-related names |
| `yun7.de` | 105 | 19 | Nodes and web-service names |
| `ai00.de` | 42 | 8 | Node namespace |
| `cn9.eu` | 29 | 4 | Nodes and a second Origin CA wildcard |
| **Total** | **965** | **219** | |

The main links are:

| Relationship | Evidence | Assessment |
|---|---|---|
| `388998.xyz` and `388898.xyz` | Shared anchor certificate on 16 hosts, 11 bearing `388898.xyz` names | High-confidence operational association |
| `388898.xyz`, `piaomiaox.com`, `yun7.de`, `pmxu.link` | Canadian names followed the same six TELUS addresses in the same sequence | High-confidence coordinated DNS administration; `pmxu.link` participation is historical |
| `cn9.eu` | `104.37.184.48` presents both zones' Origin CA certificates | Strong certificate linkage |
| `mydocshub.org` | Co-resident names with `piaomiaox.com` at `118.232.199.4` and `103.127.218.124` | Strong association when combined with the management naming |
| `ai00.de` | Shared labels and certificate co-residency at `188.253.7.9` | High-confidence association |
| `848999.xyz` | `interxui` on the dual-certificate host; `bbs` co-resident with node names | High-confidence association |

These links support assessment of a coordinated service. Co-residency alone does not establish ownership of an entire server, reseller platform or network.

### 2.2 Anchor certificate

```text
Names:        *.388998.xyz, 388998.xyz
SHA-256:      70105c643d2021557a2ef1c0b0b986a006e7c95e325c45ede5098e5e9e36939f
SPKI SHA-256: d7a92108be65b7099ddb95a43f5dce7c0e47757f6f7d47acb15d1a4325949748
Serial:       2f5cb79a44b341f6265280d04cd60b6d62c89b9d
Issuer:       CloudFlare Origin SSL Certificate Authority
Key:          RSA 2048, exponent 65537
Validity:     2026-04-27 14:54 UTC to 2041-04-23 14:54 UTC
Observed:     16 hosts; ports 443, 2053, 2083, 2087, 2096 and 8443
```

The assessment records verification against Cloudflare's published Origin CA RSA root. The certificate serial was absent from the Origin CA revocation list updated **2026-09-16 02:05 UTC**. This is a time-specific revocation check.

Origin CA certificates authenticate origins to Cloudflare and are not generally trusted by browsers. This certificate was discoverable through host scanning; its Censys record contains no CT entry. The long validity period reduces certificate-renewal requirements across distributed nodes.

The 16 anchor hosts are marked in Appendix A. Their listed providers are AT&T, KDDI, HKT, NTT InfoSphere, Interserver, Akari, netcup, DartNode and WireCat, spanning US, JP, HK, SG, TW and DE.

Several anchor services return an empty HTTP `404` or a Go-style missing-Host-header response. These observations are consistent with a shared application configuration. They do not independently locate TLS termination or prove private-key possession. If the same private key is deployed locally across nodes, compromise of one deployment could expose the shared TLS identity.

A second Origin CA certificate links `cn9.eu`:

```text
Names:        *.cn9.eu, cn9.eu
SHA-256:      6bb4cb398ccd338411cb5ecd5d53543deeb54d544c732e7b44f3a02474306e56
SPKI SHA-256: c266fe90995aeb2b08434542afb013cfa18a78f6e730e68657508c7d63cc1920
Validity:     2026-01-05 to 2041-01-01
Observed:     2 hosts; ports 443, 2053 and 8443
```

`104.37.184.48`, also associated with `interxui.848999.xyz`, presents both certificates.

### 2.3 Discovery chain

The investigation began with `108.172.195.22`, whose observed names included `ca.388898.xyz` and `ca.piaomiaox.com`. The anchor certificate was not observed on this seed. The connection to the certificate population was established through DNS expansion and examination of neighbouring hosts, rather than a certificate match on the Canadian address itself. Dated seed observations are retained in [E1](#e1-dated-telus-observations).

| Step | Pivot | Recorded result and significance |
|---|---|---|
| 1 | Seed address → associated DNS names | Identified the `388898.xyz` node namespace and a `piaomiaox.com` association |
| 2 | DNS namespace → neighbouring hosts | Revision 2 records an initial 42-host population, reduced to 38 after excluding four Cloudflare addresses; this was an intermediate population, not the final nine-zone inventory |
| 3 | Aggregate certificates on neighbouring hosts | Identified the anchor certificate on 11 hosts in that population |
| 4 | Search the anchor public key (SPKI) | Revision 2 records expansion to 16 hosts, including five absent from the initial DNS pivot; SPKI matching can retain links across certificate reissuance |
| 5 | Certificate SANs and CT names → additional namespaces | Distinguished `388998.xyz`, the certificate's zone, from `388898.xyz`, the main node namespace, and expanded the historical name catalogue |
| 6 | Historical DNS → cross-zone address sequences | Linked Canadian names in four zones through the six-address TELUS sequence, including historical `pmxu.link` names |

The intermediate yields above are preserved from [E5](#e5-september-16-assessment-record). The separately retained September 15 exact-leaf export contains **14 hosts**, with dated service observations; it does not reproduce the later 16-host total. These results differ in collection and query context and require reconciliation against the later export before treating the two-host difference as growth. See [E2](#e2-anchor-certificate-and-ssh-background-export).

## 3. Service architecture

### Architecture overview

The diagram summarises the observed infrastructure and the assessed service model. DNS and certificate associations establish the inventory; the customer path, authenticated routing and management connections remain inferred. The four address groups below partition the 65-address inventory after excluding Cloudflare.

```text
                PROBABLE COMMERCIAL PROXY-SUBSCRIPTION SERVICE
           Assessed audience: users circumventing Chinese restrictions
                 Customer software and sessions not observed
                                    |
                     Catalogue / subscription context
               pmxu.link: 61 historical names; no live DNS
          subserver.mydocshub.org: historical Cloudflare resolution
                   Current subscription delivery unconfirmed
                                    :
                         Inferred customer access
                                    :
                +-------------------+-------------------+
                |                                       |
         DIRECT NODE DNS                        CLOUDFLARE-FRONTED DNS
     Most resolving node names                  fr.388898.xyz
       point to node addresses                  hkz.388898.xyz
                :                                       :
                +-------------------+-------------------+
                                    :
                    ASSOCIATED NODE / SERVICE ESTATE
       Anchor TLS certificate: 16 hosts, 9 providers, 6 country/territory codes
           Observed ports: 443 / 2053 / 2083 / 2087 / 2096 / 8443
          3x-ui evidence: 108.172.195.22:2053; Xray family inferred
       Fleet protocols, TLS termination and egress paths unconfirmed
                                    |
              INVENTORY GROUPS (not a demonstrated traffic sequence)
         +------------------+------------------+------------------+
         |                  |                  |                  |
   CONSUMER ISP       HOSTING / SUPPORT   PROBABLE RELAYS    PRINCIPAL MANAGEMENT
   26 addresses       31 addresses        7 addresses       1 snapshot address
   AT&T, KDDI, HKT,   Interserver,        AS139341, HK      13.212.96.176
   TELUS, HiNet       netcup, WireCat     Multiple upstream AWS Singapore
   and others        and others          TLS identities    3xui.mydocshub.org
   NAS / shared NAT  Proxy exits         Consistent with   Six historical
   observed          not all confirmed   TLS passthrough   panel addresses
   Owner consent                         Direction and     API-like :9999
   unverified                            role unresolved   on six nodes

   ASSOCIATED COMMERCIAL NAMES: bbs / store / shop / pan / API names
   Cloudflare-fronted web names; copyapi.848999.xyz associated with
   116.80.47.44, where squid was observed on port 8080.

   Legend: | and + group observations; : denotes an inferred access path.
```

Cloudflare's TLS mode was not observed. The shared certificate supports coordinated operation but does not establish private-key possession on every host. Management and commercial roles may overlap other inventory groups; one principal management address does not imply that administration is confined to one host.

### 3.1 Node access and software

Most resolving node names in the examined set point directly to node addresses. `fr.388898.xyz` and `hkz.388898.xyz` point to Cloudflare. The commercial web surface also includes Cloudflare-fronted names. The anchor's observed ports match Cloudflare-supported HTTPS ports, making direct and proxied access technically compatible; the actual Cloudflare TLS mode and authenticated client configuration were not observed.

The strongest software identification is at **`108.172.195.22:2053`**, where Censys recorded a `3x-ui` session cookie, login-page and proxy labels, and threat classification `THREAT-521` with confidence 0.75. The cookie decoded to a Go gob session containing `CSRF_TOKEN`. Hostnames containing `3xui` or `xui` provide additional contextual support.

The estate is consistent with an Xray/3x-ui deployment. Specific proxy protocols and fleet-wide software uniformity are inferred. Empty HTTP responses alone cannot establish them.

### 3.2 Commercial and catalogue names

The naming scheme combines apparent carriers, locations, bandwidth tiers and contributor identifiers:

| Pattern | Examples | Interpretation |
|---|---|---|
| Consumer ISP | `comcast`, `kddi02`, `krlgu`, `hinet01` | Apparent service or route labels |
| Bandwidth | `hkt200m`, `hkt500m1`, `hkt1g-qf`, `hkbn2g1` | Apparent product tiers |
| Contributor suffix | `-qf`, `-vivi` | Possible supplier or contributor identifiers |
| Commercial services | `bbs`, `store`, `shop`, `pan` | Forum, storefront and storage-related roles |
| API services | `claudeapi`, `claudecodeapi`, `copyapi` | Possible AI/API proxy or resale services |
| Documentation/subscriptions | `guide`, `wiki`, `subserver` | Documentation and subscription-related roles |

`pmxu.link` contains 61 historically observed names, including a random label beneath `hkt1g-qf.pmxu.link`, consistent with a private routing or customer namespace. Its lack of current DNS does not establish how clients presently use it.

`copyapi.848999.xyz` is associated with **`116.80.47.44`**, where squid was observed on port 8080. The API-related names suggest a commercial API offering, but scan data does not establish upstream account provenance, authorisation or contractual violations.

Nine labels differ from the network hosting the corresponding address: `comcast`, `spacex`, `atthome-3`, `atthome-5`, `verzion-los`, `frontier`, `krhome`, `att-1` and `hkbn`. They may be inaccurate labels or may describe a downstream egress network. No authenticated end-to-end routing evidence resolves this distinction.

### 3.3 Relay infrastructure

Seven addresses in **AS139341 (ACE, Hong Kong)** carry `pan.yun7.de` and `tcip.848999.xyz` associations:

```text
43.174.79.4      43.174.150.6     43.174.151.95    43.174.151.243
43.175.130.34    43.175.130.108   43.175.132.103
```

The recorded certificates include genuine CA-issued identities for `*.cdn.myqcloud.com` and `*.unionpayintl.com`, with other names referencing Akamai and Tencent EdgeOne. Multiple unrelated upstream identities are consistent with TLS passthrough. Certificate presentation alone does not demonstrate that these hosts possess the upstream private keys or impersonate those organisations.

Two roles remain plausible: forwarding customers to Chinese services, or using upstream TLS identities as camouflage for proxy traffic. Similar CloudFront observations at `75.18.211.16:443` and `13.212.96.176:20327` support investigation of the latter. The traffic direction and exact forwarding mechanism are unresolved.

### 3.4 Management infrastructure

| Role | Hostname or address | Evidence |
|---|---|---|
| Principal management hostname | `3xui.mydocshub.org` | Maps to `13.212.96.176`, AWS Singapore, in the snapshot |
| Historical AWS Tokyo addresses | `35.77.91.126`, `52.199.118.137` | Historical panel DNS |
| Historical AWS Singapore addresses | `54.255.241.130`, `52.221.248.196` | Historical panel DNS |
| Historical Linode Singapore addresses | `172.104.178.48`, `172.104.182.189` | Historical panel DNS |
| Panel on a consumer-ISP node | `108.172.195.22:2053` | Direct 3x-ui cookie evidence |
| Additional management candidate | `104.37.184.48` | `interxui` name and both Origin CA certificates |

The principal panel's DNS history shows changes between Linode Singapore, AWS Tokyo and AWS Singapore, approximately monthly. The hostname is a more durable association than any one address. One principal address in the snapshot does not establish a single-host administrative surface.

Five additional panel names did not resolve: `sg.3xui.mydocshub.org`, `xuihk.mydocshub.org`, `sufepanel.848999.xyz`, `london3xui.848999.xyz` and `googlehkpanel.yun7.de`.

`subserver.mydocshub.org` historically resolved to Cloudflare addresses `104.21.0.249` and `172.67.151.129`; the last recorded resolution was **2026-05-08**. Current subscription delivery was not confirmed.

Six nodes expose port 9999 with an HTTP `401 Unauthorized` JSON response, consistent with an agent or management API:

```text
108.172.195.22    202.184.42.57    210.92.144.134
216.236.6.54      1.53.215.198     103.127.218.124
```

Port 9999 is common across the internet and is not an attribution indicator on its own.

## 4. Timeline and historical infrastructure

### 4.1 Recorded milestones

| Date | Observation |
|---|---|
| 2024-03-23 | First recorded certificate for `388998.xyz` |
| 2025-05-23 | Certificate history begins for `388898.xyz` |
| 2025-08-14 to 2026-04-27 | Approximately eight-month gap in the recorded `388998.xyz` certificate history |
| 2026-04-27 | Anchor Origin CA certificate issued alongside other certificates; Censys `added_at` timestamp later that day |
| May–September 2026 | Management DNS moves among Linode Singapore, AWS Tokyo and AWS Singapore |
| 2026-07-19 | Brief `ca.388898.xyz` resolution to Trellian parking address `103.224.212.113` |
| 2026-08-20 | Four `att-b-01` through `att-b-04` names appear; the inventory associates them with five AT&T addresses |
| 2026-08-23 | `greenjp` appears |
| 2026-08-26 | `kddi02` appears |
| 2026-09-03 | `comcast` appears |

The first certificate dates the zone's observed history. It does not establish the service's start date or continuous operation. Certificate and hostname appearances also do not establish when a service first became usable.

### 4.2 TELUS DNS history

The Canadian infrastructure is associated with TELUS access addresses in British Columbia. Historical DNS records show the following sequence:

| Recorded interval | Address |
|---|---|
| 2026-05-01 to 2026-05-03 | `64.180.22.81` |
| 2026-05-04 to 2026-06-12 | `108.180.92.87` — five recorded intervals |
| 2026-06-12 to 2026-07-07 | `173.180.95.145` |
| 2026-07-08 to 2026-07-29 | `209.53.145.69` |
| From 2026-07-29 through the recorded snapshot | `108.172.195.22` |
| Brief observation on 2026-07-30 | `108.172.110.252` |

`ca.388898.xyz`, `ca.piaomiaox.com`, `ca.yun7.de` and `ca.pmxu.link` followed the same sequence. This strongly supports coordinated DDNS administration. A single subscriber line is plausible, but cannot be proven from the DNS sequence alone. The `pmxu.link` association is historical.

Three addresses subsequently lost the operator names and were observed with only ISP reverse DNS:

| Address | Operator-name association ended | Later ISP reverse DNS observed |
|---|---|---|
| `64.180.22.81` | 2026-05-03 | 2026-08-23 |
| `173.180.95.145` | 2026-07-07 | 2026-08-21 |
| `108.172.110.252` | 2026-07-30 | 2026-08-20 |

This is consistent with retirement or address reassignment. Subscriber reassignment itself requires provider confirmation. The inventory contains one Canadian address, `108.172.195.22`, and no Canadian anchor-certificate host.

### 4.3 Censys history of the eight flagged IPs

Collected 16 September 2026. Case `abe618a1eea14801bd5a7697198dcbe8`. Timeline window: **18 June 2026 00:00 UTC through 16 September 2026 15:00 UTC**, supplemented by full historical host snapshots and latest September 16 records. All eight timeline chains were retrieved to completion: **3,662 unique retained events**. Retrieval completeness does not mean continuous monitoring.

**The history shows a mixture of persistent hosted proxy deployments and changing public-IP service populations.** The strongest new connection is the same HKT SSH identity recurring across two addresses. The records do not establish compromised telecom devices or identify the process/customer that originated the GreyNoise attempts.

#### Per-IP findings

| IP / provider | Historical observations | Interpretation |
|---|---|---|
| **124.146.156.66 — NTTPC InfoSphere, Japan** | Same SSH key from June 22 through September 16; shared `*.388998.xyz` certificate on 8443 from June 23. Ubuntu OpenSSH package banners progress from `3ubuntu13.16` to `.18` to `.19`, while the key persists. Names include `osaka.388898.xyz`, `sakura.388898.xyz`, `jp.yun7.de`. | Persistent associated server deployment preceding the Flowise attempts and Ollama crawling. The registry allocation explicitly says **Server Hosting Service**, not residential access. |
| **210.231.188.27 — NTTPC InfoSphere, Japan** | Same distinct SSH key from July 28 through September 15; shared certificate on 443 from July 29 and 8443 from August 3. Ubuntu package changes while retaining its key. | Another persistent hosted deployment. The two NTT hosts share the TLS certificate, but **have different SSH keys**. |
| **220.246.52.90 — HKT, Hong Kong** | Shared proxy certificate July 5–7; Debian SSH key `5dd3…66ec` July 6–7. Intervening history includes a different Dropbear key, Synology and ASUS identities. That Debian identity and proxy certificate reappear September 15–16. | Recurring deployment identity on an address that also carries other service populations. September 16 suspicious/Ollama-related context should be associated with the dated deployment, not every prior device on the IP. |
| **220.246.52.229 — HKT, Hong Kong** | Earlier July Debian key differs; August 11–September 1 shows a separate Dropbear key. September 12–13 includes Hikvision/RTSP/Tomcat observations. The `5dd3…66ec` Debian key appears September 13–14 with the shared proxy certificate September 13–15. Latest host response contains DNS context but no service objects. | Strong service-identity link to `.90`; migration, forwarding or copied keys remain alternatives. A later DNS-only record does not negate the September 14 malicious observation. |
| **108.172.195.22 — TELUS, Canada** | Sign-in service on 2053 observed July 30; stable SSH key from July 31; HAProxy statistics on 10404 from August 9. September records identify 3x-ui and HAProxy sections `Trojan-gRPC-TLS-offload` and `AnyTLS-offload`. | Proxy-management context predates the September abuse. The September 14 HAProxy page reports both relevant backends **DOWN / connection refused**; configuration does not establish functioning traffic paths. |
| **123.204.3.73 — SeedNet, Taiwan** | Changing history includes Windows SMB/DCERPC June 20, DDNS-GO July 30–August 5, an SSH key August 1–5, AirTunes August 27, HTTP/RTSP around August 31, ASUS September 6–12, and three distinct Debian SSH keys on ports 22, 22222 and 12000 September 12–14. A September snapshot names `nat05-seednet.fachost.cloud`. | Consistent with changing tenants/devices, reassignment or a gateway forwarding multiple systems. No basis to attribute the SysAid attempts specifically to the ASUS router. These observations do not prove all systems were simultaneous. |
| **1.162.157.141 — HiNet, Taiwan** | July 21–23 records show Akamai-style HTTP 400 responses through an Apple-issued certificate chain. September 15 shows HTTP **407 Proxy Authentication Required** across ports 10001, 52200, 52528, 52785 and 52340, and `hinet.ai00.de` TLS on 2083. | Direct evidence of authenticated HTTP proxy exposure around its September suspicious activity. Apple/CA names do not identify the IP's operator. |
| **162.220.11.79 — InterServer, US** | Shared `*.388998.xyz` certificate observed from June 18; stable SSH identity on port 2024 from June 26. September names include `ash.388898.xyz` and `clw2.mangoo.network`. | Enduring associated hosted service. Its SSH key was already known from the earlier assessment to have broad InterServer reuse, so the key is not a unique operator identifier. |

Earliest dates above mean earliest observed **within this requested window**, not first-ever deployment dates. Recurrence across observations does not prove uninterrupted uptime.

#### HKT identity chronology

The exact shared SSH fingerprint is:

`5dd3f5ee9e7220cc3f818dd518957da1d9b8510e285d77e0ea2617b60da766ec`

| Recorded period | Address | Evidence |
|---|---|---|
| July 6–7 | 220.246.52.90 | Same Debian SSH key, with associated proxy certificate observations July 5–7 |
| September 13 21:26 – September 14 23:41 UTC | 220.246.52.229 | Same SSH key and Debian banner; shared certificate observed September 13–15 |
| September 15 20:50 – September 16 04:07 UTC | 220.246.52.90 | Same SSH key returns; shared certificate also observed September 15–16 |

GreyNoise's last-malicious timestamp for `.229` is September 14 04:42:42 UTC; its last-suspicious timestamp for `.90` is September 16 05:51:00 UTC. Those are aggregate activity timestamps, not exact dates of individual exploit or Ollama tags. They align with the respective periods in which this proxy-associated identity was observed. This supports a deployment relationship, while leaving the traffic source behind it unresolved.

Different intervening Dropbear keys and router/NAS identities make it unsafe to treat either IP as one unchanging physical host. The same key can move with an endpoint, be copied, or be exposed through forwarding.

#### Implications for the AI-service hypothesis

The Flowise-attempt source `124.146.156.66` has a persistent hosted service identity dating back to June, with recurring SSH/certificate observations and package-banner updates. It was not first observed as a newly created service during the September attempt window.

The Ollama-crawling HKT address `220.246.52.90` shares an SSH identity with the SysAid-tagged `.229`. This is a stronger infrastructure link than generic scanning-tag overlap. It still does not establish that the operator directed either activity.

Inspected NTT/HKT full host snapshots did not identify Flowise, Ollama or Claude API services on these source IPs. Authenticated, unscanned or unrecognised services remain uncovered. There is still no demonstrated connection from the scan activity to the credentials, backend or supply of the Claude-labelled API offering.

#### Coverage and review

| IP | Unique timeline events | Timeline retrieval |
|---|---:|---|
| 1.162.157.141 | 40 | Complete |
| 108.172.195.22 | 416 | Complete |
| 123.204.3.73 | 247 | Complete |
| 124.146.156.66 | 811 | Complete |
| 162.220.11.79 | 287 | Complete |
| 210.231.188.27 | 244 | Complete |
| 220.246.52.90 | 933 | Complete |
| 220.246.52.229 | 684 | Complete |
| **Total** | **3,662** | |

This pass submitted **99 Censys API requests**, including historical snapshots, timeline pages and explicit retries. Credit cost is unknown. Event totals include probes and metadata events; they are not service counts or attack counts. Unsuccessful protocol probes are not evidence that a host runs the probed application.

Some historical **snapshot** requests repeatedly failed with transport errors, despite complete retrieval of the corresponding event timelines. The retained request ledger preserves those failures and successful retries. Snapshot time, scan time, DNS resolution time, certificate validity and GreyNoise activity time have different meanings.

Seven new historical findings were independently reviewed across the two investigation branches. The session's thread limit prevented an additional reviewer thread, so each investigator reviewed the other branch's findings and original retained evidence. Reviewer agreement is not additional source evidence.

The case remains **paused**, with unavailable snapshot details and prior provider gaps retained. Seven new historical findings and the six earlier GreyNoise findings await analyst decisions. No uninspected or zone-authority deferrals remain. The completed history task does not establish subscriber consent, successful compromise, actor identity or which process sent outbound attempts.

The source report, structured observations, request ledgers and review artifacts are linked in [E6](#e6-eight-ip-censys-history-and-greynoise-context).

## 5. Consumer bandwidth and abuse assessment

### 5.1 Supply mechanisms

The 26 addresses remaining in the consumer-ISP group are provisionally classified by their networks' access-provider roles. Historical registry evidence places `124.146.156.66` and `210.231.188.27` in NTTPC Server Hosting Service (`HOSTING-NET4`); these two addresses have been moved to hosting/support. The other NTT InfoSphere addresses in this inventory, `116.80.47.44` and `116.80.77.41`, were outside this eight-IP historical review and still require allocation-level validation. That classification does not establish that every address belongs to a household. The observations include business services, NAS devices and shared reseller gateways.

Five identified nodes expose Debian OpenSSH banners on port 22:

| Address | Provider | Observed banner |
|---|---|---|
| `106.178.204.31` | KDDI | `OpenSSH_10.0p2 Debian-7+deb13u4` |
| `108.172.195.22` | TELUS | `OpenSSH_9.2p1 Debian-2+deb12u7` |
| `172.127.58.213` | AT&T | `OpenSSH_10.0p2 Debian-7+deb13u4` |
| `220.246.52.229` | HKT | `OpenSSH_9.2p1 Debian-2+deb12u5` |
| `125.103.212.118` | UCOM | `OpenSSH_10.0p2 Debian-7` |

These banners support Linux service deployments, including possible containers or forwarded services. They do not establish who holds SSH access, exclude bundled software elsewhere on the host, or establish consent.

Six Synology devices are recorded across five inventory addresses, with two at `118.232.199.4`. Their presence supports use of small-site hardware. The observations do not prove physical household location or that the proxy and NAS services run on the same device behind a public address.

At `111.246.227.31`, six SSH endpoints expose distinct host keys and mixed Debian/Ubuntu versions, alongside reseller-related names. `123.204.3.21` exposes two SSH instances. These are consistent with shared NAT or reseller infrastructure.

| Supply mechanism | Assessment |
|---|---|
| Owner-participating bandwidth sharing | Plausible; consistent with NAS hardware, heterogeneous deployments and contributor-style labels |
| Wholesale or reseller capacity | Supported for specific shared gateways and by the second-fleet associations |
| Operator-owned connections | Plausible for some clusters, including the five AT&T addresses |
| Compromised devices | Not established; cannot be excluded by scan data |
| Bundled software or SDK sourcing | Not established; public service banners alone do not rule it out |

Multiple sourcing mechanisms may coexist. Consent and commercial arrangements remain unknown.

### 5.2 Reputation and reported exploitation

Of 46 hosts with recorded reputation observations, `108.172.195.22` had the highest reported score, **0.760**, compared with a median of **0.142**. Other examples include `1.162.157.141` at 0.429 and `188.253.4.65` at 0.398. These are provider scores, not probabilities of maliciousness.

The TELUS node's Censys reputation evidence array contained five entries, but their documented subfields were empty in the API response. Subsequent GreyNoise enrichment returned ShareFile CVE-2026-2699 and CitrixBleed2 CVE-2025-5777 attempt tags for this IP. These provider observations add abuse context but do not recover the original external incident's packet details or establish successful exploitation.

The September 16 enrichment classified `108.172.195.22`, `123.204.3.73`, `124.146.156.66`, `162.220.11.79`, `210.231.188.27` and `220.246.52.229` as malicious; `1.162.157.141` and `220.246.52.90` were suspicious. The NTT source `124.146.156.66` carried Flowise CVE-2025-59528 and CVE-2025-8943 attempt tags and an Ollama crawler tag; `.90` also carried an Ollama crawler tag. **Ollama crawling is not evidence of exploitation.** Outbound attempt tags do not establish that the source itself runs the targeted software. Returned GreyNoise records were entitlement-restricted; aggregate activity dates do not timestamp individual tags. See [E6](#e6-eight-ip-censys-history-and-greynoise-context) for the retained classifications and tags.

A proxy address appearing in attack logs identifies the visible source of a connection. Attribution to the service operator requires additional evidence, particularly where customer traffic, shared gateways and address reassignment are possible.

## 6. Associated HAProxy/Mieru/AnyTLS fleet

A second population contains **27 hosts presenting certificates with a shared public key**:

```text
SPKI SHA-256: 07ef494c012f5e332f96a9fbfd9bd9fcfd4a03894a84e9e0b65ec55cfbf65ab6
Certificate:  ac50226c9e7601807ba4dc6b6294918f1da19615fb6dab94434da5b3392f8d5b
Validity:     2025-03-05 to 2025-06-03
Certificate:  fcdaef946b3b2d25f780ed5a2ca320b383f2d413b2df6261c5eb64e01dbf98e1
Validity:     2026-04-29 to 2026-11-13
```

Censys captured unauthenticated HAProxy statistics pages on port 10404, identifying versions 3.3.10 and 3.3.7 and sections such as `Trojan-gRPC-TLS-offload`, `AnyTLS-offload`, `ss2022-relay`, `Mieru-relay`, `Germany-mieru-relay` and `US-mieru-relay`. These names are consistent with TLS termination and onward forwarding in a multi-hop design. Session counters and a rendered “Kill Sessions” control were visible; the control's functionality was not tested.

Two nodes connect this population to the main estate through different evidence types:

| Address | Main-estate name | Second-fleet evidence |
|---|---|---|
| `202.184.42.57` — TIME dotCom, Malaysia | `mytimes.piaomiaox.com` | Certificate from the second population on port 15213 |
| `210.92.144.134` — LG DACOM, South Korea | `krlgu.piaomiaox.com` | HAProxy statistics on port 10404 with `KR-mieru`, `KR-ss` and `status` sections |

The first link is cryptographic; the second is configuration-based and less specific. Together they support a **probable operational relationship**, such as a shared operator, wholesale capacity or a close partnership. A common deployment guide remains an alternative for the configuration resemblance.

### Relationship diagram

```text
                 MAIN ESTATE: nine associated DNS zones
                                  |
                     piaomiaox.com node names
                    +-------------+-------------+
                    |                           |
          mytimes.piaomiaox.com          krlgu.piaomiaox.com
             202.184.42.57                 210.92.144.134
             Malaysia                     South Korea
                    |                           :
          TLS certificate :15213        HAProxy statistics :10404
          ac50226c...f8d5b               KR-mieru / KR-ss / status
          SPKI 07ef494c...65ab6          Configuration resemblance
                    |                           :
                    +-------------+.............+
                                  |
               ASSOCIATED HAProxy / Mieru / AnyTLS FLEET
                    27 hosts by shared SPKI in the assessment

   Solid connection: observed DNS or certificate relationship.
   Dotted connection: less-specific configuration association.
   Connections describe evidence, not demonstrated traffic paths.
   The Korean configuration link does not establish SPKI membership.
```

The bridge observations are dated **2026-09-15 12:57:16 UTC** for the Malaysian certificate service and **2026-09-15 11:58:36 UTC** for the Korean statistics page. The Malaysian service returned HTTP `503`; certificate presentation does not establish a working proxy session. [E3](#e3-bridge-host-and-api-evidence) retains the service evidence identifiers and certificate query identifier. The later 27-host population count is recorded in [E5](#e5-september-16-assessment-record).

Additional associated evidence includes:

- A certificate naming `icloud.com` and `www.icloud.com`, with a purported GlobalSign issuer and validity extending to 3024, presented by 17 hosts. Its SPKI overlaps the second population on 14 hosts. The certificate is inconsistent with legitimate public-CA issuance and is consistent with domain camouflage. The three non-overlapping hosts and broader distribution of the key remain unresolved.
- A shared SSH host key at `45.145.72.47`, `45.145.72.51` and `45.145.72.123`, all using port 10777 and the same Debian OpenSSH build. This supports common provisioning.
- A certificate covering `v2hub.icu`, `v2hub.top`, `vhub.cfd`, `vhub.sbs`, `vplus.sbs`, `xplus.icu` and `xplus.sbs`, including wildcards and apexes. The associated key matched four hosts; 324 CT certificates were recorded across these zones. These are associated namespaces, not a proven complete domain inventory.

```text
Purported iCloud certificate SHA-256:
3a9592f18c368c7fee3ee99eee74d3ed134d59cc9b4515b927a27018ea8be782
Purported iCloud SPKI SHA-256:
3b3197fd5f7514fd32a8fdfc4564d7543991459ba3d82a6d8ac663c0bda1009d
Shared SSH host-key fingerprint:
2009e13984ad0e203491781b97c8b41597926ed8cb0551d29ac5bc4dd3d2c8d8
Seven-zone certificate SHA-256:
8e437599ea23f451b19dbb58ee0d1ca0810d866b99c93979cd4b1ed068167c2f
```

## 7. Confidence, limitations and follow-up

### 7.1 Key judgments

| Judgment | Confidence and basis |
|---|---|
| Commercial circumvention service | High — node catalogue, management evidence and proxy software context |
| Coordinated operation across the principal zones | High — shared certificates, historical DDNS sequence and multiple co-residencies |
| Anchor certificate presented by 16 hosts | Recorded observation; private-key placement remains unresolved |
| 26 addresses provisionally grouped as consumer-ISP | Two confirmed NTT hosting allocations moved to hosting; remaining allocation, household status and ultimate egress unverified |
| Principal panel at `13.212.96.176` | Snapshot DNS association; additional administrative endpoints exist |
| AS139341 hosts provide TLS forwarding | Strongly supported; exact mechanism and traffic direction unresolved |
| Relationship with the second fleet | Probable — certificate overlap on one node and configuration resemblance on another |
| Owner-consented bandwidth sourcing | Plausible; consent not established |
| Operator identity or responsibility for attacks | Not established |

### 7.2 Collection and attribution limits

The assessment relies on retained Censys observations, certificate records and historical DNS. It includes no authenticated proxy sessions, endpoint inspection or direct service testing. Complete timeline chains were retrieved for the eight flagged addresses in §4.3 within June 18–September 16; some supplemental historical snapshots failed. Equivalent historical coverage is unavailable for the full inventory, and these observations are not a simultaneous live-service census.

The recorded estate query combines nine DNS zones with the anchor SPKI. Parent-domain matching in `host.dns.names` has not been independently confirmed, which limits confidence in query completeness. The 65-address inventory is explicitly listed; the 12 excluded Cloudflare addresses were not fully enumerated. Hostname counts include historical records and do not describe active subscriptions or capacity.

#### Indicator specificity

Population size and collection scope affect how much a match supports association. The counts below are recorded observations, not current measurements or probabilities of common ownership. Revision 2 supplies the broad population figures; [E2](#e2-anchor-certificate-and-ssh-background-export) and [E3](#e3-bridge-host-and-api-evidence) also retain bounded samples. Truncated identifiers are display labels and must not be used as complete search values.

| Indicator | Recorded population or sample | Attribution value and limit |
|---|---|---|
| Anchor certificate / SPKI, full values in §2.2 | 16 hosts in the September 16 assessment; 14 in the retained September 15 exact-leaf export | Selective deployment link when combined with DNS and dates; does not establish local key possession or exclusive control |
| Second-fleet SPKI, full value in §6 | 27 hosts | Selective certificate association; a complete dated export is still needed to reproduce this count |
| Second-fleet SSH key `2009e13984ad0e20…` | 3 hosts in the recorded global search | Supports common provisioning in conjunction with matching service context; key reuse alone does not identify an operator |
| Interserver-associated SSH key `04374fb49ef6776e…` | 1,062 hosts reported; 1,061 in Interserver networks; a separate retained export samples 100 hosts | Broad reuse makes it a poor service-specific discriminator; a shared provisioning source is plausible but unproven |
| JA4S `t130200_1303_a56c5b993250` | 30,193,447 hosts | Common TLS behaviour; little attribution value on its own |
| Empty-404 response hash examined in revision 2 | 276,888 hosts | Common response; not an independent operator identifier |
| JARM examined in revision 2 | 37,303 hosts | Shared TLS behaviour; insufficient for attribution |
| Cloudflare-compatible HTTPS port-set probe | 824,946 hosts reported | Common deployment pattern; the exact background query must be recovered before reproducing the count |
| `Api key Incorrect` / `E_UNAUTHORIZED` / `schemaVersion` response interface | 25-host background page, 24 outside the original 50-host domain population; more results available | Reused interface, not a unique controller or software identity; this is a sample, not a global total |
| Bare full-text `"388898.xyz"` search | 453 results reported | Mixed host and web-property collections; not a valid host census |

A trait discovered among hosts already grouped by certificate is not automatically independent corroboration. Reused public keys can reflect shared provisioning, forwarding or distributed software. Combine them with dated DNS and service evidence. Broad reuse of the Interserver-associated SSH key is documented; its private-key provenance and distribution mechanism were not established. See [E4](#e4-retained-evidence-review) and [E5](#e5-september-16-assessment-record).

### 7.3 Use of indicators

Use hostnames, certificate identities, ports and observation dates together. IP-only blocking or attribution can affect unrelated users of shared infrastructure or reassigned addresses.

| Infrastructure | Attribution concern |
|---|---|
| `206.189.39.100` | Cloudways-managed third-party site, `magp.com.tw` |
| `165.232.159.145` | Third-party cPanel/mail services associated with `netsecuredadp.duckdns.org` |
| `111.246.227.31`, `123.204.3.21`, `123.204.3.73` | Shared reseller or NAT infrastructure |
| `172.236.131.108` | Shared landing-page hosting; excluded from the management inventory |
| AS139341 relay addresses | Upstream certificate identities do not establish ownership of upstream organisations or keys |
| Consumer-ISP and historical cloud addresses | Association must be checked against the relevant time window |

Service labels and infrastructure associations do not establish unlawful activity, a contract violation or a device owner's consent. Any provider report should identify a corroborated event and its timestamp.

### 7.4 Recommended follow-up

1. Extend the completed eight-IP timeline review to the remaining inventory and historical management addresses; recover failed supplemental snapshots and validate the remaining NTT allocation classifications.
2. Validate parent-domain matching and retain the full query result, including excluded Cloudflare addresses.
3. Examine retained service evidence for forwarding and downstream egress on the nine nodes whose labels differ from their hosting networks.
4. Review available TLS evidence to distinguish local termination from forwarding at the 16 anchor addresses.
5. Recover historical DNS for unresolved management and subscription names; use domain RDAP/WHOIS to investigate registration links.
6. Retrieve the underlying reputation evidence and external incident details for `108.172.195.22` before attributing abuse.
7. Recover the September 16 query exports and reconcile their 16-host anchor and 27-host second-fleet counts with the earlier retained evidence; attach service timestamps and query parameters to the evidence index in Appendix C.

## Appendix A. Address inventory

**Snapshot: 16 September 2026.** The inventory has 65 distinct addresses: 26 provisionally classified consumer-ISP, 31 hosting/support, seven relay and one principal management address. Categories describe recorded associations and assessed roles. They do not establish exclusive control or confirmed egress at every address.

Names are abbreviated as recorded in the assessment; a bare node label generally refers to `388898.xyz`. `ANCHOR` marks presentation of the `*.388998.xyz` certificate. Country codes describe the recorded network location, not verified physical premises. Historical management and TELUS addresses listed in the body are additional time-scoped records and are not added to this snapshot count.

### A.1 Provisionally classified consumer-ISP addresses — 26

| IP | CC | Network | Names | Notes |
|---|---|---|---|---|
| `108.172.195.22` | CA | TELUS BC | `ca.388898`, `ca.piaomiaox` | reputation 0.760; observed 3x-ui panel |
| `116.80.47.44` | JP | NTT InfoSphere | `copyapi.848999` | squid :8080 |
| `116.80.77.41` | JP | NTT InfoSphere | `jp01` | OpenSSH 7.4 |
| `106.178.204.31` | JP | KDDI | `kddi02` | ANCHOR; Synology NAS |
| `125.103.212.118` | JP | UCOM fibre | `spacex-2`, `spacex-2.cn9.eu` | |
| `1.160.128.11` | TW | HiNet | `hinet10` | |
| `1.160.132.147` | TW | HiNet | `hinet10` | Synology NAS |
| `1.162.157.141` | TW | HiNet | `hinet02`, `twhome.yun7.de` | rep 0.429; Synology NAS |
| `111.246.227.31` | TW | HiNet | `hinet01` | shared NAT; six SSH host keys |
| `123.204.3.21` | TW | SeedNet | `seednet-2` | shared reseller NAT |
| `123.204.3.73` | TW | SeedNet | `seednet-2` | shared reseller NAT |
| `203.73.217.189` | TW | SeedNet | `tw-sn.piaomiaox` | |
| `118.232.199.4` | TW | kbro | `kbro.piaomiaox`, `kbro70.mydocshub` | **2** Synology NAS |
| `220.246.52.83` | HK | HKT | `hkbn`, `hkhome03` | label names a competing carrier |
| `220.246.52.90` | HK | HKT | `hkhome03` | ANCHOR; MySQL :3306/:13306; `jesoffice.com` |
| `220.246.52.229` | HK | HKT | `hkbn`, `hkhome03` | ANCHOR; Synology NAS |
| `210.92.144.134` | KR | LG DACOM | `krlgu.piaomiaox` | HAProxy statistics :10404; second-fleet association |
| `220.118.183.239` | KR | Korea Telecom | `web.piaomiaox` | |
| `75.3.98.2` | US | AT&T | `att-b-04` | |
| `75.18.211.3` | US | AT&T | `att-b-02` | ANCHOR |
| `75.18.211.16` | US | AT&T | `att-b-01` | CloudFront response/certificate :443; forwarding mechanism unresolved |
| `75.37.237.62` | US | AT&T | `att-b-01` | same name as `75.18.211.16` |
| `172.127.58.213` | US | AT&T | `att-b-03` | ANCHOR |
| `202.184.42.57` | MY | TIME dotCom | `mytimes.piaomiaox` | second-fleet certificate :15213 |
| `1.53.215.198` | VN | FPT Telecom | `vnfpt.piaomiaox` | |
| `102.207.41.137` | NG | Suburban Broadband | `ngro` | |

### A.2 Hosting and support addresses — 31

| IP | Network | Names | Notes |
|---|---|---|---|
| `124.146.156.66` | NTTPC InfoSphere, JP — Server Hosting Service | `osaka`, `sakura`, `jp.yun7.de` | ANCHOR; HOSTING-NET4; stable SSH identity June–September |
| `210.231.188.27` | NTTPC InfoSphere, JP — Server Hosting Service | (cert only) | ANCHOR; HOSTING-NET4; distinct stable SSH identity July–September |
| `188.253.4.65` | Akari SG | `sggo`, `sgoracle` | ANCHOR; binds **all six** CF ports |
| `188.253.7.9` | Akari TW | (cert only) | ANCHOR; also served `*.ai00.de` |
| `104.37.184.48` | Interserver | `interxui.848999` | **ANCHOR**; presents BOTH Origin CA certificates |
| `162.220.11.79` | Interserver | `ash` | ANCHOR |
| `69.164.255.244` | Interserver | `atthome-4`, `blue`, `dous`, `usca` | ANCHOR |
| `104.37.184.166` | Interserver | `loshome-166` | |
| `45.45.224.80` | WireCat | `comcast`, `spacex` | ANCHOR; labels differ from hosting network |
| `45.45.224.82` | WireCat | `atthome`, `loshome` | `cn9.eu` certificate |
| `45.45.224.97` | WireCat | (cert only) | ANCHOR |
| `152.53.143.195` | netcup DE | `dodef` | ANCHOR |
| `152.53.166.69` | netcup US | `net` | |
| `2a0a:4cc0:5:822::22:5396` | netcup AT | `cn9.eu` apex | IPv6 |
| `108.165.122.159` | DartNode | `dtlos` | ANCHOR |
| `166.88.142.19` | DartNode | `s3` | |
| `152.70.125.78` | Oracle | `frontier`, `vircs` | label differs from hosting network |
| `64.181.251.66` | Oracle | `pavhome`, `sj`, `ushome01`, `verzion-los` | label differs from hosting network |
| `129.153.124.211` | Oracle | `us` | |
| `23.95.179.243` | ColoCrossing | `att-1` | label differs from hosting network |
| `206.189.39.100` | DigitalOcean | `dopo` | third-party Cloudways site; ownership unresolved |
| `165.232.159.145` | DigitalOcean | `krhome`, `ustest` | third-party cPanel server; ownership unresolved |
| `47.91.2.8` | Alibaba JP | `atthome-3`, `twgo`, `bbs.848999` | label differs from hosting network |
| `43.161.248.165` | Tencent HK | `twtc` | |
| `43.161.220.114` | Tencent HK | `atthome-5`, `hkg` | label differs from hosting network |
| `45.153.245.167` | xTom JP | `greenjp` | |
| `216.236.6.54` | Catixs HK | `hkxz.piaomiaox` | agent API :9999 |
| `103.127.218.124` | Pittqiao TW | `tweco2.piaomiaox`, `yaoyueshare150326` | agent API :9999 |
| `103.97.200.149` | Zouter HK | `hk01.yun7.de` | |
| `162.4.173.126` | VAYNE SG | `sg-yin-net.mydocshub` | per-host cert, not the wildcard |
| `194.114.138.19` | Misaka SG | `misaka-sg.mydocshub` | per-host cert, not the wildcard |

### A.3 Relay addresses — 7

| Address | Network | Associated names |
|---|---|---|
| `43.174.79.4` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.174.150.6` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.174.151.95` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.174.151.243` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.175.130.34` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.175.130.108` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |
| `43.175.132.103` | AS139341, ACE, Hong Kong | `pan.yun7.de`, `tcip.848999.xyz` |

### A.4 Principal management address — 1

| Address | Network | Name | Observations |
|---|---|---|---|
| `13.212.96.176` | AWS, Singapore | `3xui.mydocshub.org` | SSH :22; CloudFront response/certificate :20327 |

## Appendix B. Censys queries

These queries preserve the principal certificate and DNS pivots. Counts are tied to the assessment snapshot and can change as observations change. Confirm `host.dns.names` parent-domain matching against known hosts before treating the union as complete.

### B.1 Anchor public key

```text
host.services.cert.parsed.subject_key_info.fingerprint_sha256 =
  "d7a92108be65b7099ddb95a43f5dce7c0e47757f6f7d47acb15d1a4325949748"
```

### B.2 Nine-zone union with anchor key, excluding Cloudflare

```text
(host.dns.names: "388898.xyz" or host.dns.names: "388998.xyz"
 or host.dns.names: "piaomiaox.com" or host.dns.names: "yun7.de"
 or host.dns.names: "ai00.de" or host.dns.names: "cn9.eu"
 or host.dns.names: "848999.xyz" or host.dns.names: "pmxu.link"
 or host.dns.names: "mydocshub.org"
 or host.services.cert.parsed.subject_key_info.fingerprint_sha256 =
    "d7a92108be65b7099ddb95a43f5dce7c0e47757f6f7d47acb15d1a4325949748")
and not host.autonomous_system.asn = 13335
```

The recorded totals are 77 before the AS13335 exclusion and 65 after it. The anchor clause retains hosts absent from the initial DNS pivot.

### B.3 Additional certificate pivots

```text
# cn9.eu Origin CA key
host.services.cert.parsed.subject_key_info.fingerprint_sha256 =
  "c266fe90995aeb2b08434542afb013cfa18a78f6e730e68657508c7d63cc1920"

# Associated HAProxy/Mieru/AnyTLS population
host.services.cert.parsed.subject_key_info.fingerprint_sha256 =
  "07ef494c012f5e332f96a9fbfd9bd9fcfd4a03894a84e9e0b65ec55cfbf65ab6"

# Purported iCloud certificate key
host.services.cert.parsed.subject_key_info.fingerprint_sha256 =
  "3b3197fd5f7514fd32a8fdfc4564d7543991459ba3d82a6d8ac663c0bda1009d"
```

### B.4 Historical certificate-name enumeration

Run each query separately, substituting the other zones as needed:

```text
cert.names: "388998.xyz"
cert.names: "388898.xyz"
cert.names: "pmxu.link"
cert.names: "mydocshub.org"
```

Historical DNS linkage used the Censys Platform SDK methods `list_dns_ip_resolution_ranges` and `list_dns_name_resolution_ranges`. Retain query parameters and returned observation intervals with any subsequent evidence export.


## Appendix C. Evidence references and reproducibility

The references below identify retained local artifacts inspected for this revision. JSON companions contain structured evidence extracts, query identifiers and, where available, sensor observation times; they are not a substitute for every original provider response. Links are relative to this report and require the companion files when sharing it. All times below are UTC. Query request times, certificate validity dates and service observation times describe different events.

### E1. Dated TELUS observations

**Artifact:** [TELUS history and peer context JSON](Projects/hunts/CVE-2026-19490/telus-history-and-peer-context-2026-09-15.json).

Case `7c9709a2ffc9432ba7e18f38457f1adf`; snapshot query `7f445372f2ef4b60884c3704ae2ad5ab`; requested historical snapshot `2026-09-12T02:31:57Z`. Relevant retained fields are `dns.forward_dns` and `services`.

| Observation | Sensor time | Evidence identifier |
|---|---|---|
| `ca.388898.xyz` DNS association | 2026-09-11 18:19:14 | Retained under `dns.forward_dns` |
| `ca.piaomiaox.com` DNS association | 2026-09-11 09:26:34 | Retained under `dns.forward_dns` |
| `108.172.195.22:2053`, 3x-ui software identification and sign-in page | 2026-09-11 21:10:35 | `80d27db09cd8705e9d9a807c541cfc227b303fe4644da4a0d8054cabc30325ce` |
| `108.172.195.22:9999`, API error interface | 2026-09-11 21:56:43 | `5a96db0fdd7ce62362b7890133a3e00c6210d71b9c62531c522a54ef5c166795` |
| `108.172.195.22:10404`, HAProxy offload-labelled sections | 2026-09-11 17:46:49 | `d905f2deae62a93d027c85091aa74d1cb7ba7c6b4831a5a743381396722f6ade` |

These records support the seed's DNS and proxy-management context. The historical HAProxy observation is additional configuration context, not a certificate match to the second fleet. The retained review records its offload backends as DOWN. These timestamps neither establish uninterrupted service nor supply the full six-address historical DNS sequence in §4.2.

### E2. Anchor certificate and SSH background export

**Artifacts:** [Structured certificate and SSH comparison](Projects/hunts/CVE-2026-19490/telus-ssh-pair-followup-2026-09-15.json) and [accompanying report](Projects/hunts/CVE-2026-19490/telus-ssh-pair-followup-2026-09-15.md), dated September 15.

- Exact-leaf query `340acf8a2d904d24847845783c352e5b`: full query string in `queries.certificate.query`; **14 distinct hosts, nine ASNs, 26 raw certificate-bearing service bindings**. Retained certificate service observations span **2026-09-14 09:58:17 to 2026-09-15 16:52:11**. These are the earliest and latest observations in the export, not a continuous deployment interval.
- SSH-key query `01eb98ef74954f25922345b89cc5e40a`: full query string in `queries.ssh.query`; **100 distinct hosts**, with `complete: false` and no continuation fetched. This sample establishes broad reuse but does not independently reproduce the later 1,062-host count.

This export supports anchor-certificate reuse and the absence of that certificate on the TELUS seed in the examined records. It does not substantiate the later 16-host total, nine-provider classification or six-country/territory spread. Nine ASNs and nine named providers are different measures.

### E3. Bridge-host and API evidence

**Artifacts:** [API peer follow-up](Projects/hunts/CVE-2026-19490/telus-api-followup.md) and [JSON companion](Projects/hunts/CVE-2026-19490/telus-api-followup.json), reviewed September 15.

| Claim | Observation time | Retained reference |
|---|---|---|
| Malaysian bridge presents the second-fleet certificate at `202.184.42.57:15213` | 2026-09-15 12:57:16 | Host evidence `73a8a2490204aef286b9cc835ba6825fb37cd39e44a392a2564af5bb7b4c1cff` |
| Korean bridge exposes `KR-mieru` / `KR-ss` HAProxy sections at `210.92.144.134:10404` | 2026-09-15 11:58:36 | Host evidence `ad6275efeec71db106dfc13026d0fdf5584bcd76ca3d1b40da8dee0240175900` |
| Expired certificate `ac50226c…f8d5b` has the SPKI used for the second-fleet pivot | Certificate validity 2025-03-05 to 2025-06-03; not a service observation window | Certificate query `26d7cf8041d8481988aad1f1a9c22810`; evidence `72c88172aa03b36d57b6a0d99c2d2d0a642369632c48d4926641b7c6468a2b16` |
| API error interface has broader distribution | Sample service observations 2026-09-14 20:57:52 to 2026-09-15 18:03:48 | Background query `2626c14e22834901932da4f3bb811ebb`; query text in the accompanying report; 25 hosts, continuation available |

The JSON retains parsed certificate metadata under `certificate.parsed`, including the full SPKI, and service evidence identifiers under `peers`. The dated service details are described in the accompanying report. The 27-host SPKI population and later replacement certificate require the separate September 16 export to reproduce.

### E4. Retained evidence review

**Artifact:** [Independent TELUS evidence review, September 15](Projects/hunts/CVE-2026-19490/telus-final-evidence-review-2026-09-15.md).

This review records checks of complete host/service payloads, date semantics, certificate counts and background samples. It is an analyst work product, not an independent collection source or a record of human acceptance. It also discusses separate GreyNoise hourly tag context; that context does not recover the empty Censys reputation-evidence subfields, timestamp a specific exploit packet or prove successful exploitation. Linking this review does not resolve the incident-attribution gap in §5.2.

### E5. September 16 assessment record

**Artifact:** [Assessment revision 2](388998-proxy-network-assessment-rev2.md), particularly §§3–6, 9–10 and 14.

Revision 2 is the retained narrative source for the 16-host anchor population, 65-address nine-zone inventory, six-address TELUS sequence, 27-host associated fleet, broader fingerprint counts and discovery-chain yields. It also records the Origin CA verification and revocation check. The matching September 16 provider exports, complete historical DNS response intervals, full background query parameters and verification artifacts were not located among the local hunt exports inspected for this revision. Those results remain recorded assessment claims rather than independently reproduced results in this evidence index.

Appendix B preserves the principal certificate and union queries. To complete the audit trail, attach the original response artifacts and map each reported population to its exact query, collection time and per-service observation times. The earlier 14-host certificate export must not be cited as proof of the later 16-host result. The existing address inventory and assessment date are preserved pending that reconciliation.


### E6. Eight-IP Censys history and GreyNoise context

**Collection:** September 16, 2026; case `abe618a1eea14801bd5a7697198dcbe8`. Section 4.3 incorporates the [consolidated historical report](Projects/hunts/CVE-2026-19490/388898-censys-history-2026-09-16.md). All eight event timeline chains completed for June 18 00:00–September 16 15:00 UTC, retaining 3,662 unique events. Supplemental snapshot failures remain documented; completed pagination does not imply continuous monitoring.

- [NTT/HKT snapshot extracts and request ledger](Projects/hunts/CVE-2026-19490/388898-censys-history-east-snapshots-2026-09-16.json) and [readable comparison](Projects/hunts/CVE-2026-19490/388898-censys-history-east-snapshots-2026-09-16.md).
- [NTT/HKT timeline evidence](Projects/hunts/CVE-2026-19490/388898-censys-timeline-east-2026-09-16.json): 2,672 unique events.
- [TELUS/HiNet/SeedNet/InterServer evidence](Projects/hunts/CVE-2026-19490/388898-censys-history-west-2026-09-16.json) and [report](Projects/hunts/CVE-2026-19490/388898-censys-history-west-2026-09-16.md): 990 unique events.
- [Independent NTT/HKT review](Projects/hunts/CVE-2026-19490/388898-censys-east-independent-review-2026-09-16.md); reciprocal reviews and addenda remain in the retained case.
- [GTI/GreyNoise enrichment report](Projects/hunts/CVE-2026-19490/388898-gti-greynoise-2026-09-16.md) and [GreyNoise structured results](Projects/hunts/CVE-2026-19490/388898-greynoise-results-2026-09-16.json), preserving classifications and associated tags.

The new history corrects two allocation classifications in Appendix A without changing its 65-address membership: `124.146.156.66` and `210.231.188.27` move from consumer-ISP to hosting/support. The prior 28/29 split becomes 26/31; the remaining consumer-ISP classification is provisional. These artifacts do not resolve the separate 14-versus-16 anchor-host count discrepancy recorded in E2/E5. Inclusion in this assessment does not record human acceptance of the case's pending findings.
