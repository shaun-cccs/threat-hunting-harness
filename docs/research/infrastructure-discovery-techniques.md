# Censys TSA knowledge to adapt for threat hunting

Reviewed 2026-09-15. Source: `/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent`, commit `765fd14e0a844abd2e0a4cf6316d630b0827f266`. Compared with the current threat-hunting harness at commit `a6cf95a4477491cb28ce8bd9776ab0bf1975900a`. One matching Auto TSA project was found under `~/Projects`; the workshop directory contains earlier harness planning documents. This is a review of encoded investigative knowledge, not a live Censys investigation or a review of implementation. Source measurements below are historical examples recorded by that project, not results reproduced during this review.

The user clarified the comparison: TSA is threat surface analysis of a product, including its exposure in Canada. The purpose of this review is to extract techniques useful to both product exposure analysis and threat hunting. TSA's product-identification rules should be assessed against its own objective; they are not intended as campaign-association rules.

Implementation follow-up: the shared techniques are now distilled into the hunt skill's [infrastructure discovery guide](../../skills/hunt/references/infrastructure-discovery.md), [Censys query guidance](../../skills/hunt/references/censys.md), and [runtime playbooks](../../src/hunting_harness/playbooks.py). The skill routes investigators to relevant sections, and the playbooks provide triggers, pivots, validation and stopping criteria. The assessment below records the original comparison; the separate temporal-migration extension remains a proposal.

The strongest reusable material is the method for turning an observed artifact into a defensible discovery pivot, checking what that pivot adds and misses, and diagnosing misleading empty results. In TSA, the property being tested is product identity. In the harness, it is the relationship described by the hunt hypothesis. The search mechanics can transfer while the evidence needed to accept a match changes.

## Shared techniques to prioritize

| Shared technique | Use in product TSA | Use in threat hunting |
| --- | --- | --- |
| Derive fingerprints from observed records | Find exposed instances that lack a usable product tag | Find infrastructure sharing an observed service, content or configuration artifact |
| Inspect decoded protocols and raw fields | Recover appliances missed by HTTP fingerprints | Discover leads when a seed offers little useful web content |
| Search a signature outside the seed set | Determine whether it finds additional instances of the product | Examine new candidates without letting known seeds make the results look convincing |
| Measure matches and misses in both directions | Detect a fingerprint that excludes older or fronted deployments | Detect a pivot that misses relevant variants or expands into unrelated infrastructure |
| Make patterns specific and combine complementary signals | Separate products sharing titles, paths or components | Reduce collisions from public software, copied content and common configurations |
| Read redirect relationships in the correct direction | Distinguish the product host from a client referring to it | Discover destinations and distinguish the roles of linked infrastructure |
| Validate queries and inspect evidence provenance | Avoid silent empty results and circular tag confirmation | Avoid closing a lead because of query errors or overstating support from derived labels |
| Understand indexed evidence and population counts | Report defensible host exposure and geographic subsets | Assess prevalence and evidence coverage without confusing hosts, services or certificates |

These are the core additions. Release-artifact comparison is useful when a hunt involves software or kit lineage. Full certificate/DNS migration playbooks are a separate hunting extension, not a technique established by this TSA project.

## What the harness already knows

The existing [playbooks](../../src/hunting_harness/playbooks.py) describe certificate reuse, historical DNS, service fingerprints and contextual relationships. They already require dated, distinctive or independently supported evidence and list shared hosting, defaults, reassignment and copied reports as alternatives. The [hunt skill](../../skills/hunt/SKILL.md) already covers retained candidates, evidence review and separate relatedness/current-use/attribution claims. The [Censys guide](../../skills/hunt/references/censys.md) explains operation choice, historical coverage, pagination and source gaps.

The missing detail is how to choose, construct and challenge a pivot. Techniques 1–6 provide that practical procedure; 7–9 deepen existing independence and source-gap guidance with concrete failure modes; 10 is a conditional transfer for artifact lineage. The separate sections on temporal recipes and worked cases describe extensions and teaching material. The current service-fingerprint playbook names Shodan observations and operations, so the shared techniques should explicitly include relevant Censys evidence rather than leaving Censys knowledge confined to certificate lookups.

## Source inventory

| Source | Knowledge it owns |
| --- | --- |
| [Discovery skill](../../../Censys-Auto-TSA-Opencode-Agent/.opencode/skill/censys-tsa/SKILL.md) | Entry point and TSA remit; most investigative knowledge lives in the references. |
| [Principles](../../../Censys-Auto-TSA-Opencode-Agent/references/principles.md) | Three tag trees, raw evidence fallback, limits of vulnerability/version labels. |
| [Fingerprinting](../../../Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md) | Probe, decoded protocols, tag provenance, population inversion and contamination checks. |
| [Deep dive](../../../Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md) | Unique tokens, fronting and redirects, signal roles, independent corroboration, incremental and missed populations. |
| [CenQL rules](../../../Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md) | Same-object binding, matching semantics, positive controls, gate selection. |
| [Aggregation semantics](../../../Censys-Auto-TSA-Opencode-Agent/references/aggregation-semantics.md) | Host/service/occurrence counts, query filtering, overlapping buckets, empty-result controls. |
| [CVE and version workflow](../../../Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md) | Observable version hierarchy, artifact lineage, packaging and component ambiguity. |
| [Worked examples](../../../Censys-Auto-TSA-Opencode-Agent/references/examples.md) | Examples of widening, release inference, false negative controls and body truncation. |
| [Leads](../../../Censys-Auto-TSA-Opencode-Agent/references/leads.md) and [orchestrator](../../../Censys-Auto-TSA-Opencode-Agent/.opencode/agent/censys-tsa.md) | Testable hypotheses and explicit coverage of evidence layers. |
| [CenQL reference](../../../Censys-Auto-TSA-Opencode-Agent/docs/censys_query_language.md), [regex reference](../../../Censys-Auto-TSA-Opencode-Agent/docs/censys_regex_language.md), [host fields](../../../Censys-Auto-TSA-Opencode-Agent/docs/queryable_fields/host_censys_queryable_fields.md) | Local copies of provider documentation plus project-recorded observations. |

## Transferable techniques and their adaptations

### 1. An observation-to-pivot playbook

Teach the hunt to begin with a small, understood seed and inventory what is actually visible: decoded protocol, tags, certificate, HTTP content, redirect relationships, DNS and routing. For a few seeds, read complete retained records; for larger populations, examine distributions when available. Turn each lead into one testable hypothesis with an observed value, proposed query, expected confirming result and disconfirming result.

The actionable loop is: **inspect seed → extract distinctive artifact → search artifact outside the seed → inspect newly found population → identify the next independent question**. This adds concrete discovery judgment to a generic list of pivot types.

Sources: [fingerprinting:346](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:346), [fingerprinting:396](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:396), [leads:65](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/leads.md:65), [evidence-layer coverage:335](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/.opencode/agent/censys-tsa.md:335).

Hunting adaptation: keep a candidate discovery set distinct from a supported campaign cluster. An observed product, copied page or default artifact is useful for discovery without being an operator identity.

### 2. Decoded protocol and all-tag-tree discovery

Teach the distinction between a port, a recognized protocol and its parsed fields. Inspect `host.services.protocol`, then the corresponding structured document; do not conclude that a service has no useful fingerprint after exhausting HTTP fields. Also check software, hardware and OS tags before declaring an appliance untagged.

The source's concrete failure is an ASA/FTD assessment that searched many HTTP/TLS fields yet missed `ANYCONNECT` and `any_connect.groups`; `DefaultWEBVPNGroup` found a population the content fingerprints missed. The transferable lesson is protocol-aware inspection, not hardcoding that value as a malicious indicator.

Sources: [fingerprinting:77](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:77), [fingerprinting:120](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:120), [ANYCONNECT fields:2555](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/docs/queryable_fields/host_censys_queryable_fields.md:2555), [IKE fields:2386](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/docs/queryable_fields/host_censys_queryable_fields.md:2386).

Hunting adaptation: parsed protocol behavior is often more specific than a string mention but remains observable and potentially emulatable. A vendor default identifies technology, not a campaign. Prefer unusual combinations or configuration values only after measuring their background prevalence.

### 3. Distinctive content fingerprints and portable favicon pivots

Add a ranked extraction checklist: unusual support-link parameters, legacy names, internal codenames, exact HTML attributes, distinctive cookie names, custom headers, static asset paths, form fields, JavaScript identifiers, error text and structured multi-segment paths. Search the exact structure, not a common word stripped out of it. A path's later segments and parameter vocabulary can distinguish a product when its root is generic.

For favicons, retain the algorithm and value. Censys `hash_shodan` is the signed decimal mmh3 value used by Shodan's `http.favicon.hash`; quote negative values in CenQL. This makes an observed favicon a practical cross-provider pivot. Retain SHA-256 identity where useful rather than discarding it because it is less portable.

Sources: [unique identifiers:166](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:166), [structured paths:379](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:379), [favicon translation:362](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:362), [attribute escaping:126](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:126).

Hunting adaptation: rare in a seed is not rare globally. A vendor link, favicon or template can be copied by a phish, scanner or unrelated deployment. In particular, the source's `JSESSIONID` example is generic and should not enter a product-specific or campaign-specific signature catalog.

### 4. Directed redirect and fronting pivots

When retained records show an empty body, generic redirect title or missing favicon, inspect every available redirect hop and destination hostname. Missing content suggests a fronting or redirect path worth investigating; it does not prove an SSO deployment. At small seed sizes, reading each chain is more useful than counting generic `302 Found` titles.

For each link, record which system emitted it, what destination it names, and what the matched token identifies. A service redirecting to an identity provider may reveal the provider's hostname without itself running that product. The source's Shibboleth example found that most matching redirect emitters were service-provider clients, while their destinations were the useful discovery targets.

Sources: [empty harvest:230](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:230), [redirect direction:243](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:243), [destination as pivot:288](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:288), [redirect fields:2709](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/docs/queryable_fields/host_censys_queryable_fields.md:2709).

Hunting adaptation: distinguish redirector, destination, shared identity provider, vendor cloud, CDN, lure and referenced brand. Preserve the directed observation; do not propagate maliciousness or ownership across every hop. Continue through retained provider evidence rather than requesting the destination directly.

### 5. Incremental population and missed-population validation

For seed/base `B` and candidate `C`, inspect `C AND NOT B`, not only `C` or `B AND C`. That tests whether the pivot generalizes beyond the examples that suggested it. Also inspect `B AND NOT C` before replacing a fingerprint. Compare the two differences explicitly; similar totals can conceal substantial membership changes.

A zero incremental result is ambiguous: `C` may match nothing or may already be covered by `B`. Count or inspect `C` itself to distinguish them. Examine background prevalence, actual matching records and the cause of mismatches, rather than treating a large count as success. Check whether misses concentrate in older versions, different packaging or fronted deployments.

Sources: [incremental testing:446](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:446), [zero increment:463](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:463), [missed population:389](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:389), [symmetric difference:409](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:409).

Hunting adaptation: a newly found coherent product population is still a candidate pool. Keep the original seed as historical evidence, but allow the working cluster to shrink when evidence disproves relationships. Never adopt TSA's unconditional “OR onto the intact baseline” as a campaign-membership rule.

### 6. Signal roles, constructive gates and reversible rejection judgments

Give every proposed signal an explicit role: **discovery predicate**, **filter/gate**, **exclusion**, or **corroborating evidence**. A broad proxy, platform or neighboring component may be useless as a discovery predicate yet useful as a filter inside an already meaningful candidate set.

Inspect contamination before adding a gate. Prefer making the primary pattern more specific—quoted markup or path grammar—before requiring unrelated infrastructure. Choose a gate based on the observed false positives, and check that it is visible in the retained anonymous response. If almost everything disappears, investigate the gate and its coverage rather than concluding the original lead was empty. Record what deployments the gate excludes.

Sources: [roles:161](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:161), [constructive gate choice:172](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:172), [neighbor gates:293](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:293), [contamination first:361](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:361).

Retain three different dispositions: **untested**, **empirically negative within tested scope**, and **rejected for a particular role**. Reopen a role-based rejection when the role changes; a generic signal rejected for expansion can become a useful gate. Do not turn an unqueried idea into a negative observation. Source: [rejection classification:520](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:520).

Hunting adaptation: neither high recall nor a clean small sample makes a gate proof of common control. Empirical negatives remain bounded by query validity, provider coverage and observation dates.

### 7. Tag provenance and a concrete independence test

Inspect a tag's `evidence[].data_path` and confidence before using it as corroboration. A product label derived from a favicon and a match on that same favicon are one underlying observation. Test the candidate and tag in both directions; near-identical sets are a warning to investigate derivation, not a second vote for attribution.

Check tag contamination at the matching service before rejecting it. A host running several products can look heterogeneous merely because an unbound query included every service. Preserve a useful tag for enrichment even when it is too broad to identify the intended population.

Sources: [tag provenance:244](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:244), [service-scope check:299](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:299), [circularity:330](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md:330).

Hunting adaptation: different providers or different technical layers are not automatically independent. A shared image, deployment template, upstream scanner or detection rule can explain both. State the generating process where known, and keep unknown dependence explicit. Near-equality suggests dependence; it does not prove it.

### 8. CenQL query validity and positive controls

Add a compact query interpretation reference because these errors change investigative conclusions:

- Bind vendor/product/version to the same software or hardware object; bind port/content to the same service, and header key/value to the same header object.
- Distinguish tokenized case-insensitive `:` from exact case-sensitive `=` and case-sensitive `=~`.
- Use the supported regex syntax and escaping; the project recorded silent failures for inline flags and unescaped quotation marks.
- Quote CIDRs and specify their field. A fieldless CIDR is a text search, not subnet containment. Distinguish a queried IP range from an exact stored prefix value.
- On an unexpected zero, test a known-positive record/population, field existence, simpler pattern and alternate scope before treating it as absence.

Sources: [CenQL rules:29](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:29), [CIDRs:81](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:81), [same-object binding:113](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:113), [regex controls:139](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:139).

Hunting adaptation: provider behavior can change. Treat these as documented failure modes to verify with controlled queries, not universal guarantees. A failed control invalidates the negative conclusion but may reflect data/coverage issues as well as malformed syntax.

### 9. Searchability, returned evidence and counting are different

Teach that “not visible in this response” can mean truncated, redacted, unrequested, unparsed or unindexed; these are different limitations. The TSA Jellyfin example found searchable asset names beyond a 2,048-byte returned-body cutoff. Its cookie examples show values hidden in aggregation output but still regex-queryable. Neither observation licenses treating invisible bytes as locally inspected evidence.

Sources: [truncated-body example:211](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/examples.md:211), [cookie behavior:191](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cenql-rules.md:191), [documented body limits:2728](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/docs/queryable_fields/host_censys_queryable_fields.md:2728). The field documentation describes different limits from the example; do not promote 2,048 bytes to a universal provider guarantee.

For population evidence, distinguish host counts, service counts and repeated field occurrences; distinguish values on the matching service from values anywhere on a matching host. Bucket counts overlap, so summing them does not count a union. Full-text search can also return host, web and certificate records; a certificate count is not a count of hosting infrastructure.

Sources: [count semantics:64](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/aggregation-semantics.md:64), [overlapping buckets:131](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/aggregation-semantics.md:131), [mixed record types:152](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md:152).

Hunting adaptation: state the counted entity—IP, service, hostname, certificate or supported cluster member—and preserve provider-match evidence separately from returned body evidence. Aggregation advice is conceptual where the current harness gateway does not expose that operation; a partial retained sample cannot substitute for a global distribution.

### 10. Artifact lineage and version-aware hunting

Distinguish a product path, an asset content hash, a per-build hash and a deployment-specific value. Compare authoritative or retained target artifacts with adjacent versions and packaging variants. A shared bundle may identify a release family or kit version rather than a particular operator. Test the same artifact outside the known population for collisions.

Keep frontend, backend, plugin and firmware versions separate. In version-led hunts, distinguish provider-parsed versions, directly visible version strings, artifact-based inference and unknown versions. Do not infer vulnerability, exploitation or compromise from product exposure. Watch lexicographic version comparisons and do not silently discard unknown versions from an exposure question.

Sources: [artifact workflow:249](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md:249), [component distinction:287](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md:287), [range traps:212](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md:212), [packaging example:189](/home/shaun.mathew/Projects/Censys-Auto-TSA-Opencode-Agent/references/examples.md:189).

Hunting adaptation: this supports cautious infrastructure/kit lineage and exposed-target discovery. Shared public tooling or identical release assets are not enough to assign campaign membership. Preserve older and differently packaged variants as explicit coverage questions.

## Separate hunting extension: dated certificate, DNS and service migration recipes

Extend the existing certificate and DNS playbooks with explicit next-question sequences: **seed host at campaign time → certificate fingerprint and names → other recorded deployments → dated DNS relationships → candidate service history**. Examine when a certificate or distinctive content appears, disappears or changes and whether those changes coincide with DNS moves. A replacement certificate on the same service can provide another candidate pivot when continuity has supporting evidence; it does not inherit the old certificate's campaign association automatically.

Distinguish exact certificate reuse from shared subject text, common SAN patterns, default certificates, JARM similarity and public software defaults. Check prevalence and dated deployment evidence before expansion. Certificate issuance/validity, DNS resolution, provider observation and retrieval dates answer different questions. Cross-provider repetition improves coverage but may still repeat one underlying observation.

This is a proposed hunting synthesis, not a temporal procedure already established by Auto TSA. It combines TSA's [certificate-to-host pivot](../../../Censys-Auto-TSA-Opencode-Agent/references/counting-and-report.md), [fingerprint families](../../../Censys-Auto-TSA-Opencode-Agent/references/fingerprinting.md), and [artifact comparison](../../../Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md) with the harness's existing [dated certificate/DNS playbooks](../../src/hunting_harness/playbooks.py) and [history guidance](../../skills/hunt/references/censys.md). Use only observations supported by enabled operations and preserve unavailable history as a source gap.

## Teaching the shared techniques through worked cases

Capture short annotated investigations showing the seed, observed artifact, candidate query, new population, alternative explanation and justified next action. Prioritize: a copied favicon that fails to support campaign membership; a useful destination discovered through a redirect; an HTTP-poor seed with a decoded-protocol lead; a tag and its generating artifact mistaken for two sources; a malformed zero-hit query; a replacement fingerprint that loses older deployments; and a dated certificate/DNS migration complicated by reassignment.

For every example, include a failed pivot and explain whether it was untested, empirically negative within scope, or rejected only for its proposed role. Use synthetic examples explicitly labeled as such, or retained and cited real observations. This transfers the teaching method of the TSA [worked examples](../../../Censys-Auto-TSA-Opencode-Agent/references/examples.md) into campaign analysis. The harness's [existing benchmark corpus](../../benchmarks/README.md) already labels its synthetic certificate relationships and shared-hosting controls; it does not establish these additional investigative lessons or live detection performance.

## Decisions that depend on the objective

- **Geography and output.** TSA reports global and Canada-scoped product exposure. A hunt's geographic scope comes from its question; a Canadian victim or seed does not by itself make Canada the right boundary for related infrastructure. Country-count reporting is not a default hunting addition. Source: [counting and reporting](../../../Censys-Auto-TSA-Opencode-Agent/references/counting-and-report.md).
- **What makes a match useful.** A product-specific help link can be an excellent TSA fingerprint. In a hunt, it supplies technology context unless the hypothesis and other evidence give it a stronger meaning. Preserve the extraction technique and change the acceptance criterion. Source: [unique identifiers](../../../Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md).
- **Widening the population.** TSA adds validated product signatures to improve exposure coverage. A hunt can use the same union to discover candidates, then evaluate their relationships separately and revise its working cluster. Source: [incremental testing and widening](../../../Censys-Auto-TSA-Opencode-Agent/references/deep-dive.md).
- **Version and CVE scope.** Version derivation supports affected-product exposure questions. Its artifact-comparison technique can support kit or software lineage, but a CVE intake and counting workflow need not become part of every hunt. Source: [CVE and version workflow](../../../Censys-Auto-TSA-Opencode-Agent/references/cve-workflow.md).
- **Exclusions and provider order.** The TSA kit's honeypot exclusion and Censys-first workflow serve that assessment. Hunting should choose source order and exclusions according to the hypothesis and retained evidence. Sources: [principles](../../../Censys-Auto-TSA-Opencode-Agent/references/principles.md), [aggregation semantics](../../../Censys-Auto-TSA-Opencode-Agent/references/aggregation-semantics.md).

The useful transfer is the investigative method and its measured failure modes. Product-specific values, dated example counts and workflow defaults retain their original context. Shared observation patterns remain hypotheses to test; their meaning depends on the population under investigation.

## Review limits

The original review used local primary sources, with no live provider queries or direct requests to infrastructure. Provider syntax and historical measurements were inspected as recorded source claims, not independently reproduced. The implementation follow-up adds agent guidance and playbook content; it does not establish live hunting performance or enable new provider operations. These methods remain conditional on the evidence and operations available during a hunt.
