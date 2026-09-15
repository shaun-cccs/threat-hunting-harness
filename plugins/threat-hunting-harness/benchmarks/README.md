# Offline benchmark corpus

This corpus uses documented historical infrastructure subsets with **synthetic** Shodan observations. It tests a reproducible enrichment/coordinated workflow comparison. It does not assert that Shodan returned the constructed relationships, that the cited hosts remain malicious, or that fingerprints/observation times in the fixture were found in the source reports.

| Case | Selected investigation window | Source and publication | Seed / withheld count |
| --- | --- | --- | --- |
| `turla-armenia-2020` | 2019-01-01 to 2020-03-11 | ESET, [Tracking Turla: New backdoor delivered via Armenian watering holes](https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/), 2020-03-12 | 1 / 2 |
| `lunarweb-2020-2023` | 2020-05-20 to 2023-12-31 | ESET, [To the Moon and back(doors): Lunar landing in diplomatic missions](https://www.welivesecurity.com/en/eset-research/moon-backdoors-lunar-landing-diplomatic-missions/), 2024-05-15 | 1 / 2 |
| `lazarus-simplextea-2023` | 2023-03-01 to 2023-03-31 | ESET, [Linux malware strengthens links between Lazarus and the 3CX supply-chain attack](https://www.welivesecurity.com/2023/04/20/linux-malware-strengthens-links-lazarus-3cx-supply-chain-attack/), 2023-04-20 | 1 / 1 |

Indicator sources are pinned to ESET's public IOC repository commit [`812c573dc8c354210893775b2de97d1fbf29be1b`](https://github.com/eset/malware-ioc/tree/812c573dc8c354210893775b2de97d1fbf29be1b): the relevant sections in `turla/README.adoc` and `nukesped_lazarus/README.adoc`. Those exact source paths and sections are recorded in each manifest and truth file. The selected windows describe evaluation slices. They are not assertions that all report indicators were observed throughout those windows; the Lazarus BADCALL address has an unknown first-seen date in the cited table.

`campaigns/` holds seed-only public inputs. `truth/` is for the evaluator after investigation. `observations/` holds mocked provider responses behind the gateway. Keep `truth/` and the full response fixture out of native client workspaces and prompts. The evaluator code does not pass truth to either workflow.

The shared certificate fingerprints, their dates, weak shared-hosting controls and mock rate limit are synthetic fixture construction. The reports support only historical indicator membership. The observation `available_at` date is the public report date and is labeled as a proxy; historical Shodan availability is unknown. Both modes see the same fixture. The coordinator can discover only a subset of withheld report infrastructure, preserving the distinction between unavailable observations and evidence of absence.

Run with `hunt evaluate --benchmarks benchmarks --output <new-directory>`. See [evaluation.md](../docs/evaluation.md) for policies, metrics, temporal leakage, artifact retention and the absence of empirical numeric thresholds. Do not contact these historical indicators to validate the corpus.
