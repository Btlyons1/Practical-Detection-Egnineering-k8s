# Practical Detection Engineering: Kubernetes

Kubernetes audit log baselining and detection engineering, applied to a synthetic but realistic 31-day cluster dataset containing normal operations and four embedded attack scenarios modeled after the SCARLETEEL kill chain.

The [Detection Engineering Baseline](https://github.com/Btlyons1/Detection-Engineering-Baseline) series (Parts 1 through 3) established the statistical methodology: MAD, modified z-score, percentile-based thresholds, and false positive analysis using AWS CloudTrail. This repo takes that methodology and applies it to Kubernetes, extending it with behavioral profiling against a realistic multi-actor cluster dataset.

**Author:** [Brandon Lyons](https://github.com/Btlyons1)

**Blog series:** [Practical Detection Engineering for Kubernetes - Part 1](https://open.substack.com/pub/brandontlyons/p/practical-detection-engineering-for?r=19yefa&utm_campaign=post&utm_medium=web), [Practical Detection Engineering for Kubernetes - Part 2](https://open.substack.com/pub/brandontlyons/p/practical-detection-engineering-for-a55?r=19yefa&utm_campaign=post&utm_medium=web&showWelcomeOnShare=true).

---

## What Is in This Repo

```
detections/
  DET-2026-002/
    k8s_audit_baseline_notebook.ipynb   # Main analysis and detection notebook
    outputs/                            # Generated visualizations and baseline artifact

files/
  k8s_baseline_helpers.py              # All analysis and detection helper functions
  k8s_audit_events.db                  # Synthetic 31-day K8s audit log (SQLite)
  generate_synthetic_k8s_audit.py      # Script to regenerate the dataset
```

---

## The Dataset

The SQLite database contains 31 days of synthetic Kubernetes API server audit events (January 26 through February 25, 2026) across 10 actors: platform engineers, developers, data scientists, security accounts, service accounts, and system controllers.

Four attack scenarios are embedded in the eval window (February 7 onward) and labeled with `is_attack = 1`:

| Scenario | Actor | Dates | TTP |
|---|---|---|---|
| Anonymous API probing | system:anonymous | Feb 7 | Forbidden spray recon |
| RBAC escalation | data-scientist-carol | Feb 10, 12, 16 | ClusterRoleBinding creation |
| Secrets enumeration | notebook-sa | Feb 10 | Bulk secrets list |
| JupyterLab compromise | data-scientist-carol | Feb 10, 12, 16 | Categorical footprint expansion |

The attack scenarios are a synthetic reconstruction of the SCARLETEEL kill chain: a compromised Jupyter notebook, credential theft, and privilege escalation through RBAC modifications.

---

## The Notebook: DET-2026-002

The notebook walks through the full detection engineering workflow in eight sections:

| Section | What It Covers |
|---|---|
| 1. Intro and Hypothesis | Detection goals, field reference, measurable hypotheses |
| 2. Frequency Analysis | Actor concentration, verb/resource distributions, temporal patterns |
| 3. Data Distribution and Stats | Distribution shapes, overdispersion, method selection |
| 4. Data Grouping and Aggregation | Namespace hygiene, risky configs, overpermissioned service accounts |
| 5. Behavioral Baselining | Per-actor behavioral profiles, scope vs. volume as detection dimensions |
| 6. Detection Use Cases | Five detection rules with Python and SQL implementations, backtesting, FP analysis |
| 7. Hardening Recommendations | Concrete remediations tied to findings from Sections 4 and 6 |
| 8. Conclusion | Summary of methods, results, and next steps |

### Detection Rules Implemented

- **6a: Categorical Footprint Expansion** -- alert when a human user touches a namespace or resource type absent from their 30-day baseline. Catches all 13 labeled SCARLETEEL-phase attack events with zero false positives.
- **6b: Secrets Enumeration (Per-Hour Burst)** -- P95 threshold on hourly secrets access rate. Catches bulk enumeration attacks that spike a single actor-hour slot.
- **6c: Forbidden Reconnaissance Spray** -- sliding 10-minute window on 403 responses. Fires on the anonymous probing scenario exclusively.
- **6d: RBAC Escalation Attempts** -- any ClusterRoleBinding or RoleBinding mutation by a principal not on the platform-admin allowlist.
- **6e: Pod Exec Scope Anomalies** -- exec events outside an actor's baseline namespace scope (hunting query).

Each detection includes a Python implementation for analysis, a Presto/Trino-compatible SQL implementation for production use, a backtest against labeled data, and a false positive rate calculation against the clean eval window.

---

## Setup

**Requirements:** Python 3.10+

```bash
pip install -r requirements.txt
```

**Run the notebook:**

```bash
cd detections/DET-2026-002
jupyter notebook k8s_audit_baseline_notebook.ipynb
```

The notebook expects the SQLite database at `../../files/k8s_audit_events.db` and the helper module at `../../files/k8s_baseline_helpers.py`. Both paths are relative to the notebook location and resolve automatically.

**Regenerate the dataset:**

```bash
python files/generate_synthetic_k8s_audit.py
```

This writes a fresh `k8s_audit_events.db` to `files/`. The generator is configurable: attack injection dates, actor profiles, namespace layout, and risk posture markers are all adjustable at the top of the script.

---

## Key Design Decisions

**Why IQR instead of MAD for per-hour thresholds?**

At per-actor per-hour granularity, many hour buckets have fewer than 15 observations. MAD requires roughly 20 or more to be statistically stable. IQR degrades gracefully at low N: the fence widens, which is the correct failure mode (more conservative, not more aggressive). MAD is used in Parts 1 through 3 for daily CloudTrail counts where N is sufficient.

**Why is `baseline_df` built from `is_attack == 0` rather than a date cutoff?**

In the notebook context, using label-based filtering gives the cleanest baseline for illustration purposes. The SQL implementations use `timestamp < '2026-02-07'` throughout, which is the production-safe equivalent that does not require a labeled column.

**Why does Signal 2 (IQR rate anomaly) not fire on the SCARLETEEL attack?**

By design. The attacker generates 4 to 5 events per phase during Carol's normal business hours. Her baseline at those hours spans 1 to 12 events per hour, giving a Q3 + 1.5 x IQR fence of 15.8. The attack adds nothing statistically remarkable to the hourly count. Volume is the wrong signal for this TTP. Signal 1 (categorical expansion) catches all 13 attack events because scope is anomalous even when volume is not.

---

## Outputs

Running all notebook cells produces the following artifacts in `detections/DET-2026-002/outputs/`:

| File | Description |
|---|---|
| `actor_pareto.png` | Gini concentration curve and top-actor bar chart |
| `frequency_analysis.png` | Verb, resource, and response code distributions |
| `activity_heatmap.png` | Day-of-week x hour heatmap and hourly volume envelope |
| `event_volume_timeline.png` | 31-day daily event volume bar chart |
| `volume_distribution.png` | Daily volume distribution with normal and log-normal fits |
| `distribution_fitting.png` | Overdispersion analysis and method justification |
| `verb_resource_matrix.png` | Verb x resource heatmap and Pareto ranking |
| `user_namespace_matrix.png` | User x namespace access heatmap |
| `rare_resource_access.png` | Rare resource verb and actor breakdown |
| `actor_footprint.png` | Namespace breadth vs. resource diversity scatter |
| `namespace_activity.png` | Event volume by namespace with hygiene highlights |
| `notebook_sa_access_matrix.png` | notebook-sa cross-namespace access heatmap |
| `cross_namespace_access.png` | Namespace breadth and sensitive namespace hits by user |
| `carol_behavioral_profiles.png` | Carol's baseline vs. attack event behavioral profile |
| `behavioral_similarity_cohort.png` | Cohort-wide categorical expansion and rate anomaly signals |
| `DET-2026-002-baseline.json` | Serialized baseline artifact with thresholds and behavior profiles |

---

## Prior Work

- [Detection Engineering Baseline](https://github.com/Btlyons1/Detection-Engineering-Baseline) -- Parts 1 through 3, covering MAD, modified z-score, and percentile-based thresholds applied to AWS CloudTrail. The methodology built there is what this series puts into practice on Kubernetes.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

**Author:** Brandon Lyons
