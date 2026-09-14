# Threat hunting

This context describes investigations that start from known malicious indicators and seek additional infrastructure associated with a campaign.

## Language

**Hunt**:
An investigation of a campaign that starts from selected indicators and seeks additional candidate infrastructure within a defined time window.
_Avoid_: Scan, enrichment lookup when referring to the whole investigation.

**Seed**:
A known malicious domain or IP address selected as the starting point of a hunt.
_Avoid_: Candidate when referring to an initial indicator.

**Candidate infrastructure**:
A domain or IP address whose relationship to hunt evidence warrants investigation; the relationship alone does not establish malicious use or actor ownership.
_Avoid_: Confirmed threat actor infrastructure, attributed infrastructure without supporting evidence.

**Pivot path**:
The sequence of evidence-backed relationships connecting a seed to a candidate.
_Avoid_: Attribution when referring only to relatedness.

**Attribution**:
A claim that infrastructure is associated with a particular threat actor, requiring evidence beyond a finding of relatedness or malicious use alone.
_Avoid_: Similarity, shared hosting as synonyms for attribution.

**Historical association**:
An evidence-backed relationship between infrastructure and a campaign during a specified past period, which can remain relevant after reassignment of the infrastructure.
_Avoid_: Current malicious use when describing a past relationship.

**Current malicious use**:
A claim of malicious activity relevant to the present, assessed separately from historical association with a campaign.
_Avoid_: Historical association as sufficient evidence of current use.

**External query batch**:
A bounded set of proposed intelligence-provider queries identified by provider, exact indicators or search filters, purpose, and query limit, presented together for analyst approval.
_Avoid_: Blanket provider access, unrestricted hunt approval.

**Internal telemetry**:
Observations from the analyst's environment, including DNS queries, proxy logs, endpoint events, and firewall connections, together with their available context.
_Avoid_: IOC when referring to an entire activity record.

**Case**:
The retained record of a hunt, including its hypothesis, seeds, candidates, evidence, query history, and analyst decisions.
_Avoid_: Report when referring to the whole investigation record.

**Candidate set**:
The candidates returned by a discovery step, including candidates that have not been selected for further investigation.
_Avoid_: Verified infrastructure, expansion shortlist when referring to the whole returned set.

**Narrowing**:
The selection of a subset of retained candidates for further investigation using additional evidence and the campaign time window.
_Avoid_: Deletion, rejection when a candidate is only left outside the selected subset.

**Expansion**:
Further evidence gathering or pivots from a selected candidate, distinct from retaining or locally examining existing results.
_Avoid_: Saving candidates as a synonym for investigating them further.

**Hunt status**:
A snapshot of recorded investigation progress, including active work, retained candidates, findings, query usage, and source gaps.
_Avoid_: Completion percentage when the amount of remaining investigation is unknown.

**Source gap**:
Missing coverage caused by unavailable, rate-limited, or inaccessible source data, distinct from a successful query that returns no matches.
_Avoid_: No match, benign result when the source was not successfully queried.

**Hunt hypothesis**:
A proposition about a campaign's relationship to candidate infrastructure that can be assessed against source observations.
_Avoid_: Attribution when the proposition has not been supported.

**Playbook**:
A reusable investigation strategy describing useful observations, narrowing criteria, expansion rationale, and alternative explanations for an infrastructure relationship.
_Avoid_: Mandatory sequence when the available evidence calls for a different strategy.

**Hunt completion**:
The point at which no new candidates meet the expansion criteria and no remaining planned investigation is waiting on unavailable sources.
_Avoid_: Exhaustive proof that no additional infrastructure exists.
