# Issue tracker

Implementation requirements live in GitHub issues for `shaun-cccs/threat-hunting-harness`.

Read an issue with its complete acceptance criteria before implementing or reviewing it:

```bash
gh issue view NUMBER --repo shaun-cccs/threat-hunting-harness --json number,title,body,url
```

List outstanding work with `gh issue list --repo shaun-cccs/threat-hunting-harness --state open`. Dependency links in each issue determine implementation order. Cite issue numbers in commits so reviews can recover the original requirements.

Implementation and review use read-only issue access. Publishing comments or changing issue state requires the user's instruction to do so.
