# Infrastructure discovery

Use these techniques to turn retained seed observations into testable pivots. Choose the section that addresses the current branch. Product identity, shared tooling and a campaign relationship are different conclusions; decide which property the proposed signature can establish.

| Branch question | Technique |
| --- | --- |
| What can I pivot on? | [Inspect the seed](#inspect-the-seed) |
| Does this signature find useful candidates? | [Test additions and misses](#test-additions-and-misses) |
| Why are the matches noisy? | [Refine a signal](#refine-a-signal) |
| Who controls this zone? | [Read zone authority](#read-zone-authority) |
| Where does this redirect lead? | [Read directed relationships](#read-directed-relationships) |
| Does an asset identify a build or kit? | [Compare artifacts](#compare-artifacts) |
| Should this branch stop or reopen? | [Record the decision](#record-the-decision) |

For Censys fields, matching syntax and unexpected empty results, use [the Censys guide](censys.md). Use enabled provider operations and retained observations throughout. Missing operations or coverage remain source gaps; this guide does not enable aggregation, artifact downloads or fresh collection.

## Inspect the seed

**Trigger:** an understood seed needs a next pivot, or a content-only search has stalled.

Read the individual service records and their observation dates. With a few seeds, inspect each record before relying on distributions. Look for:

- Decoded protocol and its structured configuration. A port number is not a decoded protocol. Parsed groups, capabilities or implementation details can provide leads even when HTTP content is absent.
- Software, hardware and OS tags. Appliances may be tagged outside the software tree. Inspect a tag's evidence paths where available: a tag derived from a favicon supplies the same underlying signal as that favicon.
- Exact certificate fingerprint, names and deployment observations. Shared subject text, default certificates and JARM similarity can describe common technology. Certificate validity dates do not establish deployment dates.
- Exact HTML attributes, unusual cookie names, custom headers, form fields, internal names, error text and asset paths. Structured path segments and parameters can distinguish deployments that share a generic root. Standard cookies such as `JSESSIONID` are weak alone.
- Redirects and linked hostnames, including evidence of fronting when the body contains little information.

For each useful artifact, name the observed value, its service and date, its proposed role, the relationship it might reveal, and a competing explanation. A value repeated among seeds needs a background-prevalence check before being called rare. A vendor link or default asset can precisely identify public software while providing little campaign discrimination.

**Continue when:** a retained observation supports a concrete search and you can state what a useful new match would show. If a field is missing, try another evidence layer or record the source gap. Exhausting titles and favicons does not exhaust protocol or relational evidence.

## Test additions and misses

**Trigger:** a candidate signature is ready to search, or an existing fingerprint is being replaced.

Let `B` represent the current discovery population and `C` the candidate query. Inspect `C AND NOT B` to learn what the candidate adds. If `B` is a retained list rather than a query, compare retrieved identities locally and state any retrieval limits. Preserve the complete retrieved candidate set before narrowing.

A zero increment has two explanations: `C` finds nothing, or its matches are already in `B`. Test `C` itself when that distinction changes the next action. For an unexpected zero, use the provider's query controls before recording a negative result.

Before replacing a fingerprint, inspect `B AND NOT C` as well. Similar totals can hide different membership. Check whether misses concentrate in old versions, alternate packaging, other fronting components or different observation periods. A historical baseline and a current search are not comparable populations without accounting for their dates and coverage.

Read newly matched records and the reason each matched. Assess common software, copied pages, shared hosting, emulation and tag derivation at the matching service. A small clean sample supports that sample; it does not establish the precision of an entire result set. Distinguish host, service, hostname and certificate counts. A partial sample does not establish global prevalence, and overlapping buckets cannot be summed into a unique-host count.

**Continue when:** new candidates have the dated, distinctive relationship or independent supporting observations required by the case. Discovery-query membership alone is not that decision. If the result adds only common technology, retain the candidates and refine or defer the branch. Keep seed provenance while correcting unsupported relationships.

## Refine a signal

**Trigger:** a promising pattern also returns unrelated infrastructure.

Assign a role before judging a signal: a **discovery predicate** finds candidates, a **gate** filters them, an **exclusion** removes a supported unwanted class, and **corroboration** supports a claim. A signal rejected for discovery may still help as a gate.

Inspect actual contaminants first. Prefer a more specific primary pattern, such as an exact HTML attribute or deeper path grammar. If another observable feature separates the contaminants from useful matches, combine it with the primary pattern on the same service or endpoint as appropriate. Test the gate against known relevant observations and examine what it removes.

A proxy or identity provider can be a useful gate but seldom establishes a campaign relationship by itself. A gate that removes nearly everything may be absent from the relevant deployment's observable boundary. Record its coverage cost and try an evidence-backed alternative when available. Geography and hosting concentration are contextual features; exclusions need a reason tied to the hunt's scope.

**Continue when:** the refinement removes an understood false-positive class while retaining relevant examples. Reconsider the gate when it erases known matches. If the original pattern is already discriminating, an extra gate needs a demonstrated benefit.

## Read zone authority

**Trigger:** a domain pivot returned hosts, or a candidate resolves under a zone you did not register.

Resolving *under* a zone and *serving* that zone are different relationships, and only one implies control. A wildcard zone answers every label, so a host that merely appears as an answer inside it may be a routing artefact, a rotation target, or an address the operator does not control at all. Test the zone for a wildcard before reading any co-resolution as a relationship: query a label nobody would have provisioned. If it answers, co-resolution establishes nothing on its own, however many hosts share the name.

A host named in the zone's `NS` records, or answering DNS for it, is a different class. Serving a zone's authoritative DNS is operator-controlled infrastructure, whoever owns the address underneath. Before deferring any host in a domain-pivot result set, check it against the registry `NS` records and against its own services: a nameserver name or a DNS responder is never an end-user, CPE, or exit-node class, and must not be given that disposition.

Read the registry epochs before carrying any of this backwards. A domain that lapsed and was re-registered has disjoint operators, and its earlier resolutions, certificates and provider first-seen dates belong to the prior registrant. State which epoch each artefact falls in.

**Continue when:** you can say for each host whether it serves the zone, is served by it, or is an unrelated address the zone happens to name. Where a nameserver host has its own services, inspect them: authoritative DNS beside unexplained listeners is a question worth asking, not a coincidence to note.

## Read directed relationships

**Trigger:** a stored redirect, form action or linked hostname supplies a lead, especially from sparse web content.

Read each available hop. Identify the emitting service, destination and what the matched token names. Distinguish a redirector, application, identity provider, vendor cloud, referenced brand and final destination. A client referring to a product's login path is not necessarily running that product. Empty content suggests a fronting or redirect hypothesis; an incomplete scan is another explanation.

Treat a destination hostname as a candidate for stored host, certificate or DNS lookups when supported by enabled operations. Establish its own dated observations and the meaning of the link. A shared authentication service or copied brand link does not transfer ownership or malicious use between endpoints.

**Continue when:** the directed relationship supports a specific question about the destination or emitter. Stop expanding when the only connection is a shared third-party dependency, unless the hypothesis supplies another reason to investigate it.

## Compare artifacts

**Trigger:** a hunt hypothesis concerns shared software builds, deployment templates or kit lineage, and retained artifacts contain a possible identifier.

Distinguish an asset path, content hash, per-build hash and deployment-specific token. Compare available target artifacts with adjacent releases or packaging variants where retained evidence supports that comparison. A public asset reused across releases identifies a family; a changed compilation hash may distinguish packaging without distinguishing product versions.

Keep frontend, backend, plugin and firmware versions separate. Search outside the known population for reuse and examine whether the same public package explains the match. Infer a release only as narrowly as the evidence allows. Unavailable comparison artifacts leave uniqueness unestablished; product exposure or a build match does not establish exploitation.

**Continue when:** artifact identity and scope are understood and the next query tests the lineage hypothesis. Record family-level inference or unknown version when the evidence cannot distinguish releases. This is a conditional technique, not a required version survey for every hunt.

## Record the decision

Use branch rationale and retained evidence/query IDs to record the artifact, its role, the hypothesis tested, result coverage, alternatives and next action. These are analytical dispositions recorded in rationale, not new tool status values. Distinguish:

- **Untested:** no valid observation answers the question yet; attach no invented count.
- **Empirically negative within scope:** a valid query or inspected population failed the hypothesis for the recorded dates and coverage. A negative is only admissible when the retrieved records actually contained the fields in which the thing would have appeared. A projected search, a restricted entitlement, or a provider holding no record of the subject supplies no evidence about it: that is *untested*, whatever the response looked like. This applies to your own inspection of retained artefacts as much as to a provider response — searching a retained payload for a value the retrieval never requested returns a guaranteed absence that means nothing.
- **Unsuitable for this role:** the signal was too broad for discovery or too restrictive as a gate; reconsider when its role changes.
- **Waiting on a source gap:** the question remains unresolved because evidence or a required operation is unavailable.

Narrowing carries the same burden as expansion. Deferring a candidate states which class it belongs to, the retained field evidence placing it there, and what would reopen it. A candidate you have not inspected is not explained by anything: record it as an open lead so it survives settling, and never let a provider's silence stand as the class evidence. Absence of detection corroborates at most; it closes nothing.

Apply the existing candidate selection/defer and branch-state workflow. Provider agreement, tag agreement and reviewer agreement are not automatically independent evidence: check whether they share the same observation, detection rule or deployment artifact. Reconsider a role judgment within an active hunt when the role changes. To resume a settled case, follow the existing rules for new inputs or an explicit refresh.

## Worked decisions

These are synthetic teaching examples, not observed campaigns.

**Copied favicon.** A seed's favicon finds many public admin portals, and a Censys product tag was derived from that same favicon. Treat the tag and favicon as one technology signal. An unusual path plus custom header on the same seed service offers a narrower candidate query. Examine its new matches and dates before selecting any for expansion; a shared public plugin could still explain the combination.

**Sparse redirect.** A seed returns a stored redirect to a login hostname with little body content. Inspect the recorded chain and identify the destination's role. A common identity-provider domain explains a dependency; a distinctive destination with supporting dated observations warrants another branch. Missing later hops remain a coverage gap.

**Lost variants.** A new asset pattern returns about as many hosts as the old fingerprint. Comparing both differences shows that it adds current deployments but loses older relevant observations. Retain both discovery routes where justified, report the version/observation bias, and assess candidates individually.
