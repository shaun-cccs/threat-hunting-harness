# Use existing observations only

The threat-hunting harness must use existing observations from internal datasets and intelligence providers, without contacting suspected infrastructure or requesting a fresh provider scan or fetch on its behalf. This preserves the user's explicit collection boundary, at the cost of relying on the coverage and freshness of existing sources. Adding active collection would require revisiting this architectural boundary and the source-operation contracts that enforce it.
