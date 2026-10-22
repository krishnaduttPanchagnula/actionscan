# Ranked Feature Backlog — actionscan

**Generated**: 2026-10-23
**Inputs**: `competitor-profiles/_feature-inventory.md` (156 capabilities × 14 competitors, mechanically extracted), `_summary.md`, `_prioritized-list.md`
**Purpose**: decide what a "full-blown open-source actionscan" should build next, highest impact first.

---

## How this is ranked

**Impact** (1–5) — how much the capability changes what a security engineer can do, or whether they can adopt actionscan at all:

| | Meaning |
|---|---|
| **5** | Without it, actionscan is unusable at scale, or our defensible wedge disappears |
| **4** | A serious capability gap a competitor already ships; adoption blocker in enterprise orgs |
| **3** | Real value, but the user can work around it today |
| **2** | Nice-to-have; improves polish or reach |
| **1** | Cosmetic, or belongs to a different product category |

**Effort** — S ≤ ½ day · M 1–3 days · L 1–2 weeks · XL > 2 weeks.

**Type** — 🛡 **defends the wedge** (keeps the org-wide × live-feed × reference-level position ours) · 🧰 **table stakes** (users expect it; a competitor has it) · 🌱 **new ground** (nobody popular has it; highest ceiling) · ➡️ **delegate** (another tool already does it better — recommend, do not build).

**Evidence** — how many of the 14 competitors ship it, and who. `solo` = exactly one competitor has it.

---

## Tier 0 — Blocking: we cannot be adopted without these

| # | Feature | Impact | Effort | Type | Evidence | Why now |
|---|---|---|---|---|---|---|
| 1 | **Ignore / allowlist config** — `actionscan.yml` with per-action and per-rule allow/deny, inline `# actionscan: ignore[rule] reason`, `--no-ignores` audit mode | **5** | M | 🧰 | zizmor, poutine, scharf, actionlint, Scorecard(planned) | Every competitor has one. Without it, the LOW "outdated" layer makes us noisy in exactly the large orgs that need us. This is the #1 adoption blocker. |
| 2 | **Finding fingerprints + baseline/delta mode** — stable hash per finding; `--baseline <file>` shows new/resolved; merge-base diff | **5** | M | 🌱 | solo: **scharf** (fingerprint multiset diff), osv-scanner (2-scan diff) | The #1 user complaint across the whole field ("show me what changed"). Nobody popular has it. It is also what makes CI gating usable — without it every run re-reports the same 200 findings. |
| 3 | **Transitive `uses:` dependency graph** — composite actions + reusable workflow calls, resolved at pinned SHAs | **5** | XL | 🌱 | solo: **scharf** | The acknowledged hole in the entire market. scharf proved it is doable and published the budgets (depth 12, 5k nodes, 8 MiB, 500 requests). Without it, a compromised action 3 hops away is invisible. |
| 4 | **Severity remapping + personas** — `rules.<id>.remap.severity`, `regular/pedantic/auditor` sensitivity profiles | 4 | S | 🧰 | solo: zizmor | zizmor's "high signal-to-noise by default" is their headline claim. Noise control is how we compete against their 41 audits without building them. |
| 5 | **Unreadable/degraded state in the exit contract** — already implemented, but extend to `--fail-on` semantics and per-feed status | 4 | S | 🛡 | solo-ish (zizmor has `--offline`) | Shipped in the CLI rewrite; listed because the *report* must show it, not just the exit code. Already 60% done. |

---

## Tier 1 — The differentiators: nobody popular has these

These are the reason to build actionscan rather than adopt zizmor.

| # | Feature | Impact | Effort | Type | Evidence | Why now |
|---|---|---|---|---|---|---|
| 6 | **Publish a public, versioned Actions threat feed** — stable JSON of compromised actions + affected ranges, no auth, no account | **5** | S | 🌱 | solo: nobody (StepSecurity's API answers `400 unsupported ecosystem: actions`) | We already compute the data. Publishing it turns actionscan from a tool into *infrastructure* — other tools consume it, and "who else uses actionscan's feed" is a moat a feature list cannot buy. Cheapest high-leverage item on this page. |
| 7 | **`$GITHUB_STEP_SUMMARY` + GitHub annotations** — a summary table in the job summary; `::error file=…` per finding | 4 | S | 🧰 | zizmor (`--format=github`), Harden-Runner | Cheapest path from "a report nobody opens" to "findings developers actually read". We already emit SARIF and have the location data. |
| 8 | **Cross-repo action-reference inventory** — "you use 214 distinct actions across 87 repos; this one is your biggest blast radius" | 4 | M | 🛡 | solo: **StepSecurity** ("Actions In Use", Enterprise) | This is our dashboard's blast-radius panel turned into a first-class query. It is StepSecurity's Enterprise feature and their API 400s on Actions — the exact thing they sell and we give away. |
| 9 | **Provenance / impostor-commit verification** — prove the pinned commit is still on the upstream default branch, not a force-pushed imposter | 4 | M | 🌱 | solo: scharf (`--verify-provenance`), zizmor (`impostor-commit`) | A tag can be moved to an attacker commit; SHA pinning does not help if the SHA is not on the upstream branch. This is the check that makes SHA pinning actually trustworthy. |
| 10 | **Incomplete-vs-clean semantics for every layer** — a scan that could not finish says "incomplete", never "clean" | 4 | S | 🛡 | solo: **scharf** (`complete-clean` / `complete-with-findings` / `incomplete`, `executionSuccessful=false`) | We do this for feeds and unreadable repos; it must extend to transitive traversal, budget exhaustion and per-repo failures. A security tool that says "clean" when it did not look is worse than useless. |

---

## Tier 2 — Parity: competitors have it, we should too

Ordered by how often users hit the gap.

| # | Feature | Impact | Effort | Type | Evidence | Note |
|---|---|---|---|---|---|---|
| 11 | **Unpinned container image detection** — `uses: docker://…`, `container:`, `services:` | 4 | M | 🧰 | solo: **zizmor** (`unpinned-images`); Checkov CKV_GHA_4; KICS | Same supply chain, same feeds (Trivy/Grype for images). Currently we *skip* docker:// refs, so a whole class of unpinned references is silently unreported. |
| 12 | **SHA vs tag version mismatch** — `# v4.2.2` comment disagrees with the pinned SHA | 3 | S | 🧰 | solo: **zizmor** (`ref-version-mismatch`) | Cheap, high signal: it catches a workflow whose comment lies about what it pins. |
| 13 | **Exact-tag-over-branch ref resolution** — when a tag and a branch share a name, the tag wins | 3 | S | 🧰 | solo: **pinny** (`ListMatchingRefs`) | A correctness detail of ref resolution that silently changes results. Cheap to get right. |
| 14 | **Repo-level posture score** | 3 | M | 🛡 | solo: **Scorecard** (0–10 + aggregate) | Adopting Scorecard's model lets us say "12 of 87 repos are in bad shape" without building their 48 probes. Recommendation, not reimplementation. |
| 15 | **OpenSSF Scorecard badge** in the HTML report | 2 | S | 🧰 | osv-scanner | Cheap credibility signal on a report you send to someone. |
| 16 | **Audit log / run history** — append-only record of every scan, policy evaluation and decision | 3 | M | 🛡 | solo: **StepSecurity** | Enterprise orgs ask for "who approved this exception and when". Pairs with #1's expiring exceptions. |
| 17 | **GitHub dependency snapshot output** — `--format github` dependency listing | 2 | S | 🧰 | solo: **Trivy** | Small; useful for diffing dependency graphs over time. |
| 18 | **in-toto attestation** of the scan result | 2 | M | 🛡 | solo: **Scorecard** | Lets a security team *prove* what was scanned. Long-tail but high-value for regulated buyers. |
| 19 | **SBOM output** (SPDX / CycloneDX) | 2 | M | 🧰 | osv-scanner, Trivy | Only if someone asks for a supply-chain SBOM of Actions. Parity, not strategy. |
| 20 | **Proxy support** — `HTTP_PROXY` / `HTTPS_PROXY` | 2 | S | 🧰 | solo: **Semgrep** | Enterprise networks egress through a proxy. Without it we are simply unusable there. |
| 21 | **Private-repo / GitHub Enterprise support** | 4 | M | 🛡 | (most tools: Y; Scorecard Y) | We already accept a token; we must confirm GHE base-URL support. Trivy's advisory says GHES is Enterprise-gated — that is our opportunity. |
| 22 | **Fork / archived-repo policy** | 2 | S | 🧰 | poutine, Scorecard | We skip forks today, silently. Make it configurable and say so. |

---

## Tier 3 — Adjacent: real value, but another tool does it better

Do these only after Tier 0 and 1, and prefer to *integrate* rather than reimplement.

| # | Feature | Impact | Effort | Type | Evidence | Recommendation |
|---|---|---|---|---|---|---|
| 23 | **Typosquat / unverified-creator detection** | 3 | M | ➡️ | zizmor (`typosquat-uses`, typomania), poutine (verified-creator allowlist) | Integrate zizmor as a recommended companion. Do not rebuild the typo database. |
| 24 | **Workflow expression / type linting** | 3 | M | ➡️ | solo: **actionlint** (full type system, 39 checks) | Recommend actionlint. It is a 4.3k★, MIT, purpose-built linter. |
| 25 | **Token permission least-privilege analysis** | 3 | M | ➡️ | zizmor, Scorecard, poutine | zizmor and Scorecard both do it. We should consume a permission finding in the report, not compute it. |
| 26 | **Secret / credential exposure detection** | 3 | M | ➡️ | zizmor, actionlint, Trivy, Checkov, Semgrep, KICS | ggshield territory. Recommend. |
| 27 | **Cache poisoning / artifact poisoning detection** | 3 | M | ➡️ | solo: **zizmor** (`cache-poisoning`, `artipacked`) | zizmor's rule set is deep here. Recommend. |
| 28 | **Multi-CI support (GitLab, Azure DevOps, Tekton)** | 2 | L | ➡️ | poutine, StepSecurity, Checkov | poutine already covers 4 CI systems. Do not chase. |
| 29 | **Container image vulnerability scanning** | 2 | L | ➡️ | Trivy, Grype, Checkov | Trivy owns this. We should only report *unpinned* image refs (#11). |
| 30 | **Repo-level posture scoring engine** | 2 | L | ➡️ | Scorecard | Adopt their output (#14), do not rebuild. |

---

## Tier 4 — Explicitly do not build

| Capability | Held by | Why not |
|---|---|---|
| Runtime runner protection (egress filtering, tamper detection) | Harden-Runner | A different layer entirely — runtime, not reference-time. An agent running on the runner is not something a scanner can do. |
| 41 static workflow audits | zizmor | A solved, well-funded category: 6.7k★, 47k monthly downloads, 94 releases, 1 maintainer with sponsor backing (Trail of Bits, Grafana Labs). Beating them means out-shipping one person on static analysis — a bad bet. Recommend them. |
| Web playground (WASM) | actionlint | Distribution gimmick for a try-before-install audience we do not have. |
| PDF report | KICS | Nobody opens a PDF in 2026. |
| Repo self-published GHSA | zizmor | Nice, but it is a consequence of having users, not a feature. |
| Posture badge in the README | Scorecard, osv-scanner | Cheap to add later (#15). |
| Shell linter integration (shellcheck, pyflakes) | actionlint | Their job. |
| Call-graph reachability FP filter | osv-scanner | Package-graph reasoning, not action-reference reasoning. |

---

## Sequencing

**Sprint 1 — unblock adoption (1–2 weeks)**
`#1` ignore config · `#4` severity remapping + personas · `#7` step summary + annotations · `#6` publish the threat feed

Rationale: #1 is the adoption blocker; #4 is 3 lines of config; #7 and #6 are each a day and produce visible evidence that the tool works.

**Sprint 2 — the wedge (3–4 weeks)**
`#2` fingerprints + baseline/delta · `#10` incomplete-vs-clean everywhere · `#16` audit log

Rationale: #2 is what makes CI gating survivable and is the #1 user ask. #10 is the trust property that makes the rest worth having.

**Sprint 3 — the moat (4–6 weeks)**
`#3` transitive dependency graph

Rationale: copy scharf's budgets and incompleteness semantics rather than inventing them. Everything else in this list can be copied by a well-funded competitor in a quarter; the transitive graph with honest budget accounting is the thing that takes longer.

**Sprint 4 — widen (parallel, low risk)**
`#11` container image pinning · `#12` SHA/tag mismatch · `#8` inventory query · `#5` report-side degraded state · `#14`#15` posture score + badge

---

## What we should not claim

Three things the competitive analysis says are **not** ours, and the README should say so plainly:

1. **We are not a workflow linter.** zizmor (41 audits) and actionlint (39 checks) do that. Recommending them is a differentiator, not a weakness to hide.
2. **We are not a runtime defence.** Harden-Runner watches the runner. We read the workflow.
3. **We are not a package scanner.** Trivy, Grype and osv-scanner own package and image vulnerabilities. We consume OSV for Actions advisories and add the reference layer nobody else has.

The one sentence that should carry the README: *"actionscan answers the question every other tool in this space cannot — which of my organisation's repositories reference this action, and is it compromised, vulnerable or unpinned?"*

---

## Ranking summary (all 30 ranked items)

| Rank | Feature | Impact | Effort | Type | Tier |
|---|---|---|---|---|---|
| 1 | Public Actions threat feed | 5 | S | 🌱 | 1 |
| 2 | Finding fingerprints + baseline/delta | 5 | M | 🌱 | 0 |
| 3 | Transitive `uses:` graph | 5 | XL | 🌱 | 0 |
| 4 | Ignore / allowlist config | 5 | M | 🧰 | 0 |
| 5 | Severity remapping + personas | 4 | S | 🧰 | 0 |
| 6 | Unreadable/degraded state in report | 4 | S | 🛡 | 0 |
| 7 | `$GITHUB_STEP_SUMMARY` + annotations | 4 | S | 🧰 | 1 |
| 8 | Cross-repo action-reference inventory | 4 | M | 🛡 | 1 |
| 9 | Provenance / impostor-commit verification | 4 | M | 🌱 | 1 |
| 10 | Incomplete-vs-clean semantics everywhere | 4 | S | 🛡 | 1 |
| 11 | Unpinned container image detection | 4 | M | 🧰 | 2 |
| 12 | Private repo / GitHub Enterprise | 4 | M | 🛡 | 2 |
| 13 | SHA vs tag version mismatch | 3 | S | 🧰 | 2 |
| 14 | Exact-tag-over-branch resolution | 3 | S | 🧰 | 2 |
| 15 | Repo-level posture score (adopt) | 3 | M | 🛡 | 2 |
| 16 | Audit log / run history | 3 | M | 🛡 | 2 |
| 17 | Typosquat detection | 3 | M | ➡️ | 3 |
| 18 | Token permission analysis | 3 | M | ➡️ | 3 |
| 19 | Workflow expression linting | 3 | M | ➡️ | 3 |
| 20 | Secret detection | 3 | M | ➡️ | 3 |
| 21 | Cache poisoning detection | 3 | M | ➡️ | 3 |
| 22 | GitHub dependency snapshot | 2 | S | 🧰 | 2 |
| 23 | in-toto attestation | 2 | M | 🛡 | 2 |
| 24 | SBOM output | 2 | M | 🧰 | 2 |
| 25 | OpenSSF Scorecard badge | 2 | S | 🧰 | 2 |
| 26 | Proxy support | 2 | S | 🧰 | 2 |
| 27 | Fork / archived-repo policy | 2 | S | 🧰 | 2 |
| 28 | Multi-CI support | 2 | L | ➡️ | 3 |
| 29 | Container image vulnerability scanning | 2 | L | ➡️ | 3 |
| 30 | Posture scoring engine | 2 | L | ➡️ | 3 |

*Rank order is by impact, then by effort within an impact band. Tier 0 items are the ones that block adoption and are therefore pulled forward regardless of rank.*
