# Policies

| file | use it for |
|------|------------|
| [`default.yml`](default.yml) | What `sentinel init` writes. Blocks destructive and credential-reading actions, asks before risky ones, stays out of the way otherwise. |
| [`strict.yml`](strict.yml) | Unattended agents and unfamiliar code. Default is `confirm`; only known-harmless commands run freely; unknown hosts are denied. |

Copy one to `.sentinel/policy.yml` and edit. Validate with:

```bash
sentinel policy validate .sentinel/policy.yml
sentinel policy test
```

The language is documented in [docs/policy.md](../docs/policy.md).
