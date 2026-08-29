# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual strings used in this repo's issue tracker.

Since the tracker is local markdown (see `issue-tracker.md`), these aren't GitHub/GitLab labels — they're the literal values written into the `Status:` line near the top of each issue/spec file.

| Role in mattpocock/skills | `Status:` value in this repo | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding value from this table as the `Status:` line.

Edit the right-hand column to match whatever vocabulary you actually use.
