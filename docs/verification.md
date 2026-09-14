# Verification record

This branch contains the core gateway, Shodan contract, retention/narrowing, review, lifecycle, and exports for issues #1–#6 and #12. The reviewed fixes for recovery and accounting are included. Branch-specific offline checks are recorded in its commit message.

The earlier bounded live Shodan checks authenticated account metadata (HTTP 200) and retrieved one existing host report for `1.1.1.1`, `history=false`: 16 observations, one API request, zero searches/retries, and unknown credits. Those checks do not establish historical/search entitlements. Splitting this branch made no new live provider calls. Credentials and raw case artifacts remain ignored.

Provider, client, and evaluation validation records arrive with the corresponding later branches; no native client or benchmark acceptance is claimed here.
