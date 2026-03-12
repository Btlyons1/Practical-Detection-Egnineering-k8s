"""
Kubernetes Audit Log Baseline Helpers

Extends the core baseline_helpers.py with K8s-specific analysis functions
including cosine similarity for behavioral profiling.

Reuses patterns from: github.com/Btlyons1/Detection-Engineering-Baseline

Author: Brandon Lyons
"""

import itertools
import pandas as pd
import numpy as np
from scipy import stats
from scipy.spatial.distance import cosine
from typing import Optional, Union, Tuple, Dict, List, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import Counter
import json


# =============================================================================
# K8S DOMAIN CONSTANTS
# =============================================================================

K8S_SYSTEM_NAMESPACES: List[str] = ['kube-system', 'kube-public', 'kube-node-lease']

K8S_HIGH_VALUE_RESOURCES: frozenset = frozenset({
    'secrets', 'serviceaccounts', 'clusterrolebindings',
    'rolebindings', 'clusterroles', 'roles', 'nodes',
})

K8S_READ_VERBS:  frozenset = frozenset({'get', 'list', 'watch'})
K8S_WRITE_VERBS: frozenset = frozenset({'create', 'update', 'patch'})

# Minimum observations required for a stable per-hour IQR fence.
# Hours below MIN_N_FALLBACK are suppressed entirely.
IQR_MIN_N_PER_HOUR: int = 15
IQR_MIN_N_FALLBACK:  int = 5


# =============================================================================
# CORE STATISTICAL FUNCTIONS (from baseline_helpers.py)
# =============================================================================

def calculate_median(data: Union[pd.Series, np.ndarray]) -> float:
    """Calculate median - preferred over mean for security data."""
    return float(np.median(data))


def calculate_mad(data: Union[pd.Series, np.ndarray]) -> float:
    """
    Calculate Median Absolute Deviation (MAD).
    
    MAD is a robust measure of dispersion that is not affected by outliers,
    making it ideal for security telemetry with long-tail distributions.
    """
    median = np.median(data)
    return float(np.median(np.abs(data - median)))


def calculate_modified_zscore(data: Union[pd.Series, np.ndarray]) -> np.ndarray:
    """
    Calculate Modified Z-Score using MAD.
    
    The constant 0.6745 makes MAD consistent with standard deviation
    for normally distributed data, allowing us to use familiar sigma
    thresholds even on non-normal (e.g., Pareto) distributions.
    """
    data = np.asarray(data)
    median = np.median(data)
    mad = calculate_mad(data)
    
    if mad == 0:
        return np.zeros_like(data, dtype=float)
    
    return 0.6745 * (data - median) / mad


def detect_outliers_mad(
    data: Union[pd.Series, np.ndarray],
    threshold: float = 3.5
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Detect outliers using Modified Z-Score method.
    
    Parameters
    ----------
    data : array-like
        Numeric data to analyze
    threshold : float
        Modified z-score threshold for outlier detection (default: 3.5)
        Commonly used thresholds:
        - 2.5: More sensitive, catches borderline anomalies
        - 3.5: Standard, good balance (recommended)
        - 5.0: Conservative, only extreme outliers
        
    Returns
    -------
    tuple
        (outlier_mask, modified_z_scores)
    """
    modified_z = calculate_modified_zscore(data)
    outlier_mask = np.abs(modified_z) > threshold
    return outlier_mask, modified_z


def calculate_percentiles(
    data: Union[pd.Series, np.ndarray],
    percentiles: List[int] = [5, 25, 50, 75, 90, 95, 99]
) -> Dict[str, float]:
    """Calculate percentile values for threshold setting."""
    return {f"p{p}": float(np.percentile(data, p)) for p in percentiles}


def calculate_robust_statistics(series: Union[pd.Series, np.ndarray]) -> Dict[str, Any]:
    """
    Return a robust statistics dict for a numeric series.

    Uses median + MAD instead of mean + std as primary measures to resist
    outlier inflation — the same pattern used in the reference baseline
    (DET-2026-001). Mean and std are included for reference only.

    Keys: count, median, mad, mean, std, min, max, p5, p25, p75, p90, p95, p99
    """
    data = pd.Series(series).dropna()
    median_val = float(np.median(data))
    mad_val = float(np.median(np.abs(data - median_val)))
    pcts = calculate_percentiles(data)
    return {
        "count":  int(len(data)),
        "median": median_val,
        "mad":    mad_val,
        "mean":   float(data.mean()),
        "std":    float(data.std()),
        "min":    float(data.min()),
        "max":    float(data.max()),
        **pcts,
    }


def gini_coefficient(series: Union[pd.Series, np.ndarray]) -> float:
    """
    Calculate the Gini coefficient for a frequency distribution.

    Measures how concentrated activity is across actors, verbs, namespaces, etc.
    0 = perfectly uniform (every actor generates equal events).
    1 = one actor generates all events.

    Useful in Section 2 frequency analysis to quantify long-tail behavior before
    deciding whether a global threshold is meaningful.
    """
    s = np.sort(np.abs(pd.Series(series).dropna().values))
    n = len(s)
    if n == 0 or s.sum() == 0:
        return 0.0
    return float((2 * np.sum(np.arange(1, n + 1) * s) / (n * s.sum())) - (n + 1) / n)


def build_frequency_table(
    series: pd.Series,
    label: str = "value",
) -> pd.DataFrame:
    """
    Build a frequency table with share and cumulative percentage columns.

    Returns a DataFrame with columns: <label>, count, share_pct, cumulative_pct.
    Sorted descending by count. Mirrors the FrequencyAnalyzer output from the
    reference baseline (DET-2026-001).

    Parameters
    ----------
    series : pd.Series
        Raw column values (e.g. df['user_username'], df['verb']).
    label : str
        Name for the value column in the output table.
    """
    counts = series.value_counts()
    total = counts.sum()
    cum = counts.cumsum() / total * 100
    return pd.DataFrame({
        label:          counts.index,
        "count":        counts.values,
        "share_pct":    (counts.values / total * 100).round(2),
        "cumulative_pct": cum.values.round(2),
    }).reset_index(drop=True)


def get_rare_events(
    series: pd.Series,
    threshold: int = 50,
) -> pd.DataFrame:
    """
    Return values whose total count is below ``threshold``.

    Low-frequency events are high-signal in security telemetry: they are either
    infrequent by design (RBAC mutations, pod exec) or anomalous behavior that
    doesn't blend into the noisy majority.

    Parameters
    ----------
    series : pd.Series
        Raw column to scan (e.g. df['verb'], df['object_ref_resource']).
    threshold : int
        Events with count < threshold are returned.
    """
    counts = series.value_counts()
    rare = counts[counts < threshold]
    return pd.DataFrame({
        "value": rare.index,
        "count": rare.values,
    }).reset_index(drop=True)


def suggest_threshold_from_stats(
    stats: Dict[str, Any],
    sensitivity: str = "medium",
) -> Dict[str, Any]:
    """
    Suggest a detection threshold from a ``calculate_robust_statistics`` result.

    Three sensitivity levels — each balances recall vs. false-positive rate:

    - ``high``   : median + 2 * MAD  (catches more, more FPs)
    - ``medium`` : P95               (standard operational threshold)
    - ``low``    : P99               (fire only on extreme outliers)

    Returns a dict with keys: threshold, method, sensitivity, stats_used.
    """
    if sensitivity == "high":
        threshold = stats["median"] + 2 * stats["mad"]
        method = "median + 2×MAD"
    elif sensitivity == "low":
        threshold = stats["p99"]
        method = "P99"
    else:  # medium
        threshold = stats["p95"]
        method = "P95"

    return {
        "threshold":   round(threshold, 2),
        "method":      method,
        "sensitivity": sensitivity,
        "stats_used":  {k: stats[k] for k in ("median", "mad", "p95", "p99")},
    }


def calculate_iqr_bounds(data: Union[pd.Series, np.ndarray]) -> Tuple[float, float, float]:
    """
    Calculate Interquartile Range (IQR) bounds.
    
    Returns
    -------
    tuple
        (lower_bound, upper_bound, iqr)
    """
    q1 = np.percentile(data, 25)
    q3 = np.percentile(data, 75)
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr
    return float(lower_bound), float(upper_bound), float(iqr)


# =============================================================================
# COSINE SIMILARITY FOR BEHAVIORAL ANALYSIS
# =============================================================================

@dataclass
class BehaviorVector:
    """
    Represents a user/SA's behavioral profile as a vector.
    
    Each dimension represents the proportion of activity in a category.
    """
    entity: str
    period: str  # "baseline" or date string
    namespace_vector: Dict[str, float] = field(default_factory=dict)
    verb_vector: Dict[str, float] = field(default_factory=dict)
    resource_vector: Dict[str, float] = field(default_factory=dict)
    hour_vector: Dict[int, float] = field(default_factory=dict)
    total_events: int = 0
    
    def to_array(self, dimension: str, all_keys: List[str]) -> np.ndarray:
        """Convert a dimension to a numpy array with consistent ordering."""
        vector_dict = getattr(self, f"{dimension}_vector")
        return np.array([vector_dict.get(k, 0.0) for k in all_keys])


class BehaviorProfiler:
    """
    Build and compare behavioral profiles using cosine similarity.
    
    Use Case: Detect when a user's current activity pattern deviates
    significantly from their historical baseline.
    
    Example
    -------
    >>> profiler = BehaviorProfiler()
    >>> baseline = profiler.build_baseline_profile(df, "data-scientist-carol", days=14)
    >>> current = profiler.build_current_profile(df, "data-scientist-carol", date="2024-01-15")
    >>> similarity = profiler.compare_profiles(baseline, current)
    >>> if similarity < 0.7:
    ...     print("Anomalous behavior detected!")
    """
    
    def __init__(self):
        self.all_namespaces = set()
        self.all_verbs = set()
        self.all_resources = set()
    
    def _normalize_vector(self, counter: Counter) -> Dict[str, float]:
        """Normalize counts to proportions (sum to 1)."""
        total = sum(counter.values())
        if total == 0:
            return {}
        return {k: v / total for k, v in counter.items()}
    
    def _extract_hour(self, timestamp: str) -> int:
        """Extract hour from ISO timestamp string."""
        if isinstance(timestamp, str):
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
        return timestamp.hour
    
    def build_profile(
        self,
        df: pd.DataFrame,
        entity: str,
        period_label: str = "baseline"
    ) -> BehaviorVector:
        """
        Build a behavioral profile for an entity from audit events.
        
        Parameters
        ----------
        df : pd.DataFrame
            Audit events filtered to the relevant time period
        entity : str
            Username or service account name
        period_label : str
            Label for this profile (e.g., "baseline" or "2024-01-15")
            
        Returns
        -------
        BehaviorVector
            Normalized behavioral profile
        """
        entity_events = df[df["user_username"] == entity]
        
        if len(entity_events) == 0:
            return BehaviorVector(entity=entity, period=period_label)
        
        # Count occurrences in each dimension
        namespace_counts = Counter(entity_events["object_ref_namespace"].dropna())
        verb_counts = Counter(entity_events["verb"])
        resource_counts = Counter(entity_events["object_ref_resource"].dropna())
        hour_counts = Counter(entity_events["timestamp"].apply(self._extract_hour))
        
        # Track all seen values for consistent vector lengths
        self.all_namespaces.update(namespace_counts.keys())
        self.all_verbs.update(verb_counts.keys())
        self.all_resources.update(resource_counts.keys())
        
        return BehaviorVector(
            entity=entity,
            period=period_label,
            namespace_vector=self._normalize_vector(namespace_counts),
            verb_vector=self._normalize_vector(verb_counts),
            resource_vector=self._normalize_vector(resource_counts),
            hour_vector=self._normalize_vector(hour_counts),
            total_events=len(entity_events),
        )
    
    def calculate_cosine_similarity(
        self,
        profile_a: BehaviorVector,
        profile_b: BehaviorVector,
        dimension: str = "namespace"
    ) -> float:
        """
        Calculate cosine similarity between two profiles for a specific dimension.
        
        Parameters
        ----------
        profile_a, profile_b : BehaviorVector
            Profiles to compare
        dimension : str
            Which dimension to compare: "namespace", "verb", "resource", or "hour"
            
        Returns
        -------
        float
            Cosine similarity (0 = completely different, 1 = identical)
        """
        if dimension == "hour":
            all_keys = list(range(24))
        else:
            all_keys = sorted(getattr(self, f"all_{dimension}s" if dimension != "namespace" 
                                      else "all_namespaces"))
        
        vec_a = profile_a.to_array(dimension, all_keys)
        vec_b = profile_b.to_array(dimension, all_keys)
        
        # Handle zero vectors
        if np.all(vec_a == 0) or np.all(vec_b == 0):
            return 0.0
        
        # scipy.cosine returns distance, we want similarity
        return 1 - cosine(vec_a, vec_b)
    
    def calculate_composite_similarity(
        self,
        profile_a: BehaviorVector,
        profile_b: BehaviorVector,
        weights: Dict[str, float] = None
    ) -> Dict[str, float]:
        """
        Calculate similarity across all dimensions with optional weighting.
        
        Parameters
        ----------
        profile_a, profile_b : BehaviorVector
            Profiles to compare
        weights : dict, optional
            Weights for each dimension (default: equal weights)
            
        Returns
        -------
        dict
            Similarity scores per dimension and weighted composite
        """
        if weights is None:
            weights = {
                "namespace": 0.35,  # Where they're working - most important
                "resource": 0.30,   # What they're touching
                "verb": 0.20,       # What operations
                "hour": 0.15,       # When (time of day)
            }
        
        scores = {}
        for dimension in ["namespace", "verb", "resource", "hour"]:
            scores[f"{dimension}_similarity"] = self.calculate_cosine_similarity(
                profile_a, profile_b, dimension
            )
        
        # Weighted composite
        scores["composite_similarity"] = sum(
            scores[f"{dim}_similarity"] * weight 
            for dim, weight in weights.items()
        )
        
        return scores
    
    def detect_behavioral_anomaly(
        self,
        baseline_profile: BehaviorVector,
        current_profile: BehaviorVector,
        threshold: float = 0.7
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect if current behavior is anomalous compared to baseline.
        
        Parameters
        ----------
        baseline_profile : BehaviorVector
            Historical baseline profile
        current_profile : BehaviorVector
            Current period profile
        threshold : float
            Similarity threshold below which behavior is flagged (default: 0.7)
            
        Returns
        -------
        tuple
            (is_anomalous, details_dict)
        """
        scores = self.calculate_composite_similarity(baseline_profile, current_profile)
        
        is_anomalous = scores["composite_similarity"] < threshold
        
        # Find which dimensions contributed most to the anomaly
        anomalous_dimensions = []
        for dim in ["namespace", "verb", "resource", "hour"]:
            if scores[f"{dim}_similarity"] < threshold:
                anomalous_dimensions.append(dim)
        
        # What's new in current that wasn't in baseline?
        new_namespaces = set(current_profile.namespace_vector.keys()) - \
                         set(baseline_profile.namespace_vector.keys())
        new_resources = set(current_profile.resource_vector.keys()) - \
                        set(baseline_profile.resource_vector.keys())
        
        return is_anomalous, {
            "entity": current_profile.entity,
            "baseline_period": baseline_profile.period,
            "current_period": current_profile.period,
            "composite_similarity": scores["composite_similarity"],
            "dimension_scores": scores,
            "anomalous_dimensions": anomalous_dimensions,
            "new_namespaces": list(new_namespaces),
            "new_resources": list(new_resources),
            "baseline_events": baseline_profile.total_events,
            "current_events": current_profile.total_events,
        }


# =============================================================================
# K8S-SPECIFIC ANALYSIS FUNCTIONS
# =============================================================================

def analyze_cross_namespace_access(
    df: pd.DataFrame,
    entity: str
) -> Dict[str, Any]:
    """
    Analyze an entity's cross-namespace access patterns.
    
    Useful for detecting lateral movement or overly broad permissions.
    """
    entity_events = df[df["user_username"] == entity]
    
    namespaces_accessed = entity_events["object_ref_namespace"].dropna().unique()
    
    # Group by namespace and count
    ns_counts = entity_events.groupby("object_ref_namespace").size().to_dict()
    
    # Identify sensitive access
    sensitive_namespaces = ["kube-system", "kube-public", "default"]
    sensitive_access = {ns: ns_counts.get(ns, 0) for ns in sensitive_namespaces 
                       if ns in ns_counts}
    
    return {
        "entity": entity,
        "total_namespaces": len(namespaces_accessed),
        "namespaces": list(namespaces_accessed),
        "namespace_event_counts": ns_counts,
        "sensitive_namespace_access": sensitive_access,
        "cross_namespace_ratio": len(namespaces_accessed) / max(len(entity_events), 1),
    }


def analyze_secrets_access_patterns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze secrets access patterns across the cluster.
    
    Returns a DataFrame with per-entity secrets access metrics.
    """
    secrets_events = df[df["object_ref_resource"] == "secrets"]
    
    if len(secrets_events) == 0:
        return pd.DataFrame()
    
    analysis = secrets_events.groupby("user_username").agg({
        "audit_id": "count",
        "object_ref_namespace": lambda x: x.nunique(),
        "object_ref_name": lambda x: x.nunique(),
        "verb": lambda x: list(x.unique()),
        "response_status_code": lambda x: (x == 403).sum(),
    }).rename(columns={
        "audit_id": "total_secrets_access",
        "object_ref_namespace": "unique_namespaces",
        "object_ref_name": "unique_secrets",
        "verb": "verbs_used",
        "response_status_code": "forbidden_count",
    })
    
    return analysis.sort_values("total_secrets_access", ascending=False)


def analyze_exec_patterns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze pod exec usage patterns.
    
    Exec is a high-risk operation - good for detecting potential breaches.
    """
    exec_events = df[df["object_ref_subresource"] == "exec"]
    
    if len(exec_events) == 0:
        return pd.DataFrame()
    
    analysis = exec_events.groupby("user_username").agg({
        "audit_id": "count",
        "object_ref_namespace": lambda x: list(x.unique()),
        "object_ref_name": lambda x: x.nunique(),
        "timestamp": ["min", "max"],
    })
    
    analysis.columns = ["exec_count", "namespaces", "unique_pods", 
                       "first_exec", "last_exec"]
    
    return analysis.sort_values("exec_count", ascending=False)


def detect_forbidden_spray(
    df: pd.DataFrame,
    threshold_count: int = 10,
    time_window_minutes: int = 5
) -> List[Dict[str, Any]]:
    """
    Detect reconnaissance via rapid 403 responses.
    
    Pattern: Many forbidden responses in a short time window indicates
    an entity probing for accessible resources.
    """
    forbidden_events = df[df["response_status_code"] == 403].copy()
    
    if len(forbidden_events) == 0:
        return []
    
    forbidden_events["timestamp_dt"] = pd.to_datetime(forbidden_events["timestamp"])
    forbidden_events = forbidden_events.sort_values("timestamp_dt")
    
    alerts = []
    
    for entity in forbidden_events["user_username"].unique():
        entity_forbidden = forbidden_events[forbidden_events["user_username"] == entity]
        
        # Sliding window analysis
        for i, row in entity_forbidden.iterrows():
            window_start = row["timestamp_dt"]
            window_end = window_start + pd.Timedelta(minutes=time_window_minutes)
            
            window_events = entity_forbidden[
                (entity_forbidden["timestamp_dt"] >= window_start) &
                (entity_forbidden["timestamp_dt"] <= window_end)
            ]
            
            if len(window_events) >= threshold_count:
                alerts.append({
                    "entity": entity,
                    "window_start": str(window_start),
                    "forbidden_count": len(window_events),
                    "resources_probed": list(window_events["object_ref_resource"].unique()),
                    "namespaces_probed": list(window_events["object_ref_namespace"].dropna().unique()),
                })
                break  # One alert per entity
    
    return alerts


def identify_risky_configurations(df: pd.DataFrame) -> Dict[str, List[Dict]]:
    """
    Identify events indicating risky cluster configurations.
    
    Returns categorized findings for security review.
    """
    findings = {
        "workloads_in_default": [],
        "overpermissioned_access": [],
        "anonymous_access_attempts": [],
        "rbac_modifications": [],
    }
    
    # Workloads in default namespace
    default_ns_creates = df[
        (df["object_ref_namespace"] == "default") &
        (df["verb"] == "create") &
        (df["object_ref_resource"].isin(["pods", "deployments", "daemonsets"]))
    ]
    for _, row in default_ns_creates.iterrows():
        findings["workloads_in_default"].append({
            "timestamp": row["timestamp"],
            "user": row["user_username"],
            "resource": row["object_ref_resource"],
            "name": row["object_ref_name"],
        })
    
    # Anonymous access attempts
    anon_events = df[df["user_username"] == "system:anonymous"]
    for _, row in anon_events.iterrows():
        findings["anonymous_access_attempts"].append({
            "timestamp": row["timestamp"],
            "resource": row["object_ref_resource"],
            "namespace": row["object_ref_namespace"],
            "result": row["authorization_decision"],
        })
    
    # RBAC modifications
    rbac_mods = df[
        (df["object_ref_resource"].isin(["roles", "rolebindings", 
                                          "clusterroles", "clusterrolebindings"])) &
        (df["verb"].isin(["create", "update", "patch", "delete"]))
    ]
    for _, row in rbac_mods.iterrows():
        findings["rbac_modifications"].append({
            "timestamp": row["timestamp"],
            "user": row["user_username"],
            "verb": row["verb"],
            "resource": row["object_ref_resource"],
            "name": row["object_ref_name"],
        })
    
    return findings


# =============================================================================
# BASELINE DOCUMENTATION (matches existing pattern)
# =============================================================================

@dataclass
class K8sDetectionBaseline:
    """
    Structured baseline documentation for K8s detection rules.
    
    Matches the DetectionBaseline pattern from baseline_helpers.py
    """
    detection_id: str
    detection_name: str
    hypothesis: str
    data_source: str
    baseline_period_start: str
    baseline_period_end: str
    
    # Statistical baselines
    event_volume_baseline: Dict[str, float] = field(default_factory=dict)
    per_entity_baselines: Dict[str, Dict] = field(default_factory=dict)
    behavior_profiles: Dict[str, Dict] = field(default_factory=dict)
    
    # Thresholds
    percentile_thresholds: Dict[str, float] = field(default_factory=dict)
    mad_thresholds: Dict[str, float] = field(default_factory=dict)
    cosine_similarity_threshold: float = 0.7
    
    # Findings
    risk_findings: Dict[str, List] = field(default_factory=dict)
    
    # Metadata
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    @classmethod
    def from_json(cls, path: str) -> "K8sDetectionBaseline":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def load_from_sqlite(db_path: str, query: str = None) -> pd.DataFrame:
    """Load K8s audit events from SQLite (pattern works for DuckDB/Snowflake/etc)."""
    import sqlite3
    
    conn = sqlite3.connect(db_path)
    
    if query is None:
        query = "SELECT * FROM k8s_audit_events ORDER BY timestamp"
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Parse JSON columns back to lists
    if "user_groups" in df.columns:
        df["user_groups"] = df["user_groups"].apply(
            lambda x: json.loads(x) if isinstance(x, str) else x
        )
    if "source_ips" in df.columns:
        df["source_ips"] = df["source_ips"].apply(
            lambda x: json.loads(x) if isinstance(x, str) else x
        )
    
    return df


def quick_baseline_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """Generate a quick summary of the audit log dataset."""
    return {
        "total_events": len(df),
        "date_range": {
            "start": df["timestamp"].min(),
            "end": df["timestamp"].max(),
        },
        "unique_users": df["user_username"].nunique(),
        "unique_namespaces": df["object_ref_namespace"].nunique(),
        "unique_resources": df["object_ref_resource"].nunique(),
        "verb_distribution": df["verb"].value_counts().to_dict(),
        "response_code_distribution": df["response_status_code"].value_counts().to_dict(),
        "attack_events": df["is_attack"].sum() if "is_attack" in df.columns else "N/A",
        "risky_config_events": df["is_risky_config"].sum() if "is_risky_config" in df.columns else "N/A",
    }

# =============================================================================
# FREQUENCY & CONCENTRATION ANALYSIS
# =============================================================================

def shorten_actor_name(username: str) -> str:
    """
    Return a compact display label for a K8s principal.

    system:serviceaccount:ns:name → sa:name
    system:kube-*                 → kube-*
    system:node:*                 → node:*
    """
    if username.startswith('system:serviceaccount:'):
        return 'sa:' + username.replace('system:serviceaccount:', '').split(':')[-1]
    if username.startswith('system:kube-'):
        return username.replace('system:kube-', 'kube-')
    if username.startswith('system:node:'):
        return username.replace('system:node:', 'node:')
    return username


def analyze_actor_concentration(
    df: pd.DataFrame,
    user_col: str = 'user_username',
    head_pct: float = 0.80,
) -> Dict[str, Any]:
    """
    Compute activity concentration metrics for all actors in df.

    Returns a dict with keys:
      gini         - Gini coefficient (0 = uniform, 1 = one actor dominates)
      freq_table   - DataFrame with events, share_%, cumulative_%
      head_actors  - actors that together account for head_pct of activity
      tail_actors  - remaining actors
      n_80         - number of actors to reach 80% of events
      n_95         - number of actors to reach 95% of events
      n_actors     - total unique actors
      actor_counts - raw Series (actor → event count, sorted descending)
    """
    counts     = df.groupby(user_col).size().sort_values(ascending=False)
    total      = counts.sum()
    cumulative = counts.cumsum() / total

    freq_table = pd.DataFrame({
        'events':       counts.values,
        'share_%':      (counts.values / total * 100).round(2),
        'cumulative_%': (cumulative.values * 100).round(2),
    }, index=counts.index).rename_axis(user_col)

    g            = gini_coefficient(counts)
    head_cutoff  = int((cumulative.values >= head_pct).argmax()) + 1
    n_95_cutoff  = int((cumulative.values >= 0.95).argmax()) + 1

    return {
        'gini':         g,
        'freq_table':   freq_table,
        'head_actors':  counts.index[:head_cutoff].tolist(),
        'tail_actors':  counts.index[head_cutoff:].tolist(),
        'n_80':         head_cutoff,
        'n_95':         n_95_cutoff,
        'n_actors':     len(counts),
        'actor_counts': counts,
    }


# =============================================================================
# PER-ACTOR BASELINE STATISTICS
# =============================================================================

def build_per_actor_baseline(
    df: pd.DataFrame,
    user_col: str = 'user_username',
    date_col: str = 'date',
    exclude_system: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Aggregate per-actor per-day event volume and compute robust statistics.

    Parameters
    ----------
    exclude_system : bool
        If True (default), exclude system: principals.

    Returns
    -------
    (baselines_df, user_daily_df)
      baselines_df  — one row per actor: days_active, total_events,
                      median_daily, mad_daily, p95_daily, max_daily
      user_daily_df — raw (actor, date, daily_count) DataFrame
    """
    mask       = ~df[user_col].str.startswith('system:') if exclude_system else pd.Series([True] * len(df))
    user_daily = (
        df[mask]
        .groupby([user_col, date_col])
        .size()
        .reset_index(name='daily_count')
    )

    def _stats(group: pd.DataFrame) -> pd.Series:
        s = calculate_robust_statistics(group['daily_count'])
        return pd.Series({
            'days_active':  s['count'],
            'total_events': int(group['daily_count'].sum()),
            'median_daily': round(s['median'], 1),
            'mad_daily':    round(s['mad'], 1),
            'p95_daily':    round(s['p95'], 1),
            'max_daily':    int(s['max']),
        })

    baselines = (
        user_daily.groupby(user_col)
        .apply(_stats)
        .reset_index()
    )
    return baselines, user_daily


# =============================================================================
# DISTRIBUTION SHAPE ANALYSIS
# =============================================================================

def analyze_volume_distribution(series: Union[pd.Series, np.ndarray]) -> Dict[str, Any]:
    """
    Fit Normal and Log-normal distributions to a volume series and run normality tests.

    Returns a dict with keys:
      stats_table  - DataFrame suitable for display
      mu, sigma    - normal fit parameters
      ln_shape, ln_loc, ln_scale - log-normal fit parameters
      shapiro_stat, shapiro_p    - Shapiro-Wilk test
      ks_stat, ks_p              - KS test vs standard normal
      pcts         - dict {50: val, 75: val, 90: val, 95: val, 99: val}
      x_range      - linspace array for plotting fits
      kde          - scipy gaussian_kde object
      data         - cleaned numpy array
      is_normal    - bool (shapiro_p > 0.05)
    """
    data                        = pd.Series(series).dropna().values
    mu, sigma                   = stats.norm.fit(data)
    ln_shape, ln_loc, ln_scale  = stats.lognorm.fit(data, floc=0)
    kde                         = stats.gaussian_kde(data, bw_method='silverman')
    shapiro_stat, shapiro_p     = stats.shapiro(data)
    ks_stat, ks_p               = stats.kstest((data - mu) / sigma, 'norm')
    pcts                        = {p: float(np.percentile(data, p)) for p in [50, 75, 90, 95, 99]}
    x_range                     = np.linspace(data.min() * 0.80, data.max() * 1.15, 300)

    normal_verdict = (
        '(normal)' if shapiro_p > 0.05
        else '(rejects normality — prefer P95/MAD over mean±std)'
    )
    stats_table = pd.DataFrame([
        ('Days in window',    len(data)),
        ('Mean events/day',   f'{mu:,.0f}'),
        ('Std dev',           f'{sigma:,.0f}'),
        ('Median',            f'{np.median(data):,.0f}'),
        ('MAD',               f'{np.median(np.abs(data - np.median(data))):,.0f}'),
        ('P95',               f'{pcts[95]:,.0f}'),
        ('P99',               f'{pcts[99]:,.0f}'),
        ('Shapiro-Wilk p',    f'{shapiro_p:.4f}  {normal_verdict}'),
    ], columns=['Stat', 'Value']).set_index('Stat')

    return {
        'stats_table':  stats_table,
        'mu': mu,       'sigma': sigma,
        'ln_shape': ln_shape, 'ln_loc': ln_loc, 'ln_scale': ln_scale,
        'shapiro_stat': shapiro_stat, 'shapiro_p': shapiro_p,
        'ks_stat': ks_stat, 'ks_p': ks_p,
        'pcts':     pcts,
        'x_range':  x_range,
        'kde':      kde,
        'data':     data,
        'is_normal': bool(shapiro_p > 0.05),
    }


def build_actor_hour_grid(
    df: pd.DataFrame,
    user_col: str = 'user_username',
) -> pd.DataFrame:
    """
    Build a complete (actor × date × hour) grid including zero-count slots.

    Used to characterize overdispersion and zero-inflation in per-actor hourly
    activity. Returns a DataFrame with columns: user_col, date, hour, count.
    """
    mask   = ~df[user_col].str.startswith('system:')
    actors = df[mask][user_col].unique()
    dates  = pd.date_range(df['timestamp'].min().date(), df['timestamp'].max().date(), freq='D')

    grid = pd.DataFrame(
        [(a, d.date(), h) for a, d, h in itertools.product(actors, dates, range(24))],
        columns=[user_col, 'date', 'hour'],
    )
    actual = (
        df[mask]
        .groupby([user_col, 'date', 'hour'])
        .size()
        .reset_index(name='count')
    )
    full_grid = grid.merge(actual, on=[user_col, 'date', 'hour'], how='left').fillna(0)
    full_grid['count'] = full_grid['count'].astype(int)
    return full_grid


def analyze_hourly_overdispersion(full_grid: pd.DataFrame) -> Dict[str, Any]:
    """
    Compute overdispersion and zero-inflation statistics from a full actor-hour grid.

    Returns dict with:
      pct_zero   - % of actor-hour slots with zero events
      mean_nz    - mean of non-zero slots
      var_nz     - variance of non-zero slots
      disp_ratio - var / mean  (Poisson expects 1.0; >1 = overdispersed)
      nonzero    - numpy array of non-zero counts
      all_counts - full numpy array
    """
    all_counts = full_grid['count'].values
    nonzero    = all_counts[all_counts > 0]
    pct_zero   = float((all_counts == 0).mean() * 100)
    mean_nz    = float(nonzero.mean())
    var_nz     = float(nonzero.var())
    disp_ratio = var_nz / mean_nz if mean_nz > 0 else 0.0
    return {
        'pct_zero':   pct_zero,
        'mean_nz':    mean_nz,
        'var_nz':     var_nz,
        'disp_ratio': disp_ratio,
        'nonzero':    nonzero,
        'all_counts': all_counts,
    }


def compute_temporal_patterns(
    df: pd.DataFrame,
    day_col:  str = 'day_of_week',
    hour_col: str = 'hour',
    date_col: str = 'date',
) -> Dict[str, Any]:
    """
    Compute day-of-week/hour heatmap data and hourly volume envelope statistics.

    Returns dict with:
      heatmap_data   - pivot DataFrame (day_of_week × hour)
      hourly_stats   - DataFrame with mean/std per hour
      low_hour_mean  - mean events/hr for hours 00-05 UTC
      biz_hour_mean  - mean events/hr for hours 13-22 UTC
    """
    day_order    = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_data = df.groupby([day_col, hour_col]).size().unstack(fill_value=0)
    heatmap_data = heatmap_data.reindex([d for d in day_order if d in heatmap_data.index])

    hourly_by_date = df.groupby([date_col, hour_col]).size().reset_index(name='count')
    hourly_stats   = hourly_by_date.groupby(hour_col)['count'].agg(['mean', 'std']).fillna(0)

    low_mean = float(hourly_stats.loc[hourly_stats.index <= 5, 'mean'].mean())
    biz_mean = float(
        hourly_stats.loc[(hourly_stats.index >= 13) & (hourly_stats.index <= 22), 'mean'].mean()
    )
    return {
        'heatmap_data':  heatmap_data,
        'hourly_stats':  hourly_stats,
        'low_hour_mean': low_mean,
        'biz_hour_mean': biz_mean,
    }


# =============================================================================
# DETECTION HELPERS
# =============================================================================

def get_top_profile_key(vec: dict) -> str:
    """Return the key with the highest value in a BehaviorVector dimension dict."""
    return max(vec, key=vec.get) if vec else 'none'


def detect_categorical_expansion(
    eval_df: pd.DataFrame,
    base_ns:  set,
    base_res: set,
    user: str,
    user_col: str = 'user_username',
    ns_col:   str = 'object_ref_namespace',
    res_col:  str = 'object_ref_resource',
) -> pd.DataFrame:
    """
    Return eval events for ``user`` that touch namespaces or resource types
    outside their established baseline footprint.

    Adds boolean columns ns_new, res_new, cat_alert to the returned slice.
    """
    user_eval = eval_df[eval_df[user_col] == user].copy()
    user_eval['ns_new']    = user_eval[ns_col].apply(
        lambda x: bool(pd.notna(x) and x not in base_ns))
    user_eval['res_new']   = user_eval[res_col].apply(
        lambda x: bool(pd.notna(x) and x not in base_res))
    user_eval['cat_alert'] = user_eval['ns_new'] | user_eval['res_new']
    return user_eval[user_eval['cat_alert']]


def compute_iqr_thresholds(
    base_daily: pd.DataFrame,
    hour_col:       str = 'hour',
    count_col:      str = 'count',
    min_n_per_hour: int = IQR_MIN_N_PER_HOUR,
    min_n_fallback:  int = IQR_MIN_N_FALLBACK,
) -> Tuple[Dict[int, float], Dict[int, str]]:
    """
    Compute per-hour IQR upper-fence thresholds from baseline per-(date, hour) data.

    Three tiers per hour bucket:
      n >= min_n_per_hour           → per-hour IQR (Q3 + 1.5×IQR)
      min_n_fallback <= n < min_n   → global IQR fallback (conservative)
      n < min_n_fallback            → suppressed (threshold = inf)

    Returns (thresholds, methods) dicts keyed by hour 0-23.
    """
    all_counts = base_daily[count_col].values
    _, global_upper, _ = (
        calculate_iqr_bounds(all_counts)
        if len(all_counts) >= min_n_fallback
        else (0, float('inf'), 0)
    )
    thresholds: Dict[int, float] = {}
    methods:    Dict[int, str]   = {}

    for h in range(24):
        h_data = base_daily[base_daily[hour_col] == h][count_col].values
        if len(h_data) >= min_n_per_hour:
            _, upper, _ = calculate_iqr_bounds(h_data)
            thresholds[h] = upper
            methods[h]    = f'per-hour IQR (n={len(h_data)})'
        elif len(h_data) >= min_n_fallback:
            thresholds[h] = global_upper
            methods[h]    = f'global fallback (n={len(h_data)} < {min_n_per_hour})'
        else:
            thresholds[h] = float('inf')
            methods[h]    = f'suppressed (n={len(h_data)} < {min_n_fallback})'

    return thresholds, methods


def run_cohort_footprint_detection(
    baseline_df: pd.DataFrame,
    eval_df:     pd.DataFrame,
    users:       List[str],
    user_col:    str = 'user_username',
    ns_col:      str = 'object_ref_namespace',
    res_col:     str = 'object_ref_resource',
    date_col:    str = 'date',
    hour_col:    str = 'hour',
    min_n_per_hour: int = IQR_MIN_N_PER_HOUR,
    min_n_fallback:  int = IQR_MIN_N_FALLBACK,
) -> pd.DataFrame:
    """
    Run Signal 1 (categorical footprint expansion) and Signal 2 (per-hour IQR
    rate anomaly) for every user in ``users``.

    Returns a summary DataFrame with one row per user:
      user, display, new_ns, new_res, cat_alert, hr_spikes, hr_alert, any_alert
    """
    results = []
    for user in users:
        user_base = baseline_df[baseline_df[user_col] == user]
        user_eval = eval_df[eval_df[user_col] == user]
        if len(user_base) == 0:
            continue

        base_ns  = set(user_base[ns_col].dropna())
        base_res = set(user_base[res_col].dropna())

        # Signal 1
        ns_new    = int(user_eval[ns_col].apply(
            lambda x: bool(pd.notna(x) and x not in base_ns)).sum())
        res_new   = int(user_eval[res_col].apply(
            lambda x: bool(pd.notna(x) and x not in base_res)).sum())
        cat_alert = ns_new > 0 or res_new > 0

        # Signal 2
        base_daily  = user_base.groupby([date_col, hour_col]).size().reset_index(name='count')
        eval_hourly = user_eval.groupby([date_col, hour_col]).size().reset_index(name='count')
        thresholds, _ = compute_iqr_thresholds(
            base_daily, hour_col='hour', count_col='count',
            min_n_per_hour=min_n_per_hour, min_n_fallback=min_n_fallback,
        )
        hr_spikes = sum(
            1 for h in eval_hourly[hour_col].unique()
            if (eval_hourly[eval_hourly[hour_col] == h]['count'].values
                > thresholds.get(h, float('inf'))).any()
        )

        display_name = user.split('-')[-1] if '-' in user else user
        results.append({
            'user':      user,
            'display':   display_name,
            'new_ns':    ns_new,
            'new_res':   res_new,
            'cat_alert': cat_alert,
            'hr_spikes': hr_spikes,
            'hr_alert':  hr_spikes > 0,
            'any_alert': cat_alert or hr_spikes > 0,
        })

    return pd.DataFrame(results).sort_values('new_ns', ascending=False)


def build_secrets_burst_detection(
    baseline_df:  pd.DataFrame,
    eval_df:      pd.DataFrame,
    resource_col: str = 'object_ref_resource',
    user_col:     str = 'user_username',
    date_col:     str = 'date',
    hour_col:     str = 'hour',
) -> Dict[str, Any]:
    """
    Build per-hour P95 secrets access detection.

    Returns dict with:
      baseline_stats - per-actor hourly secrets stats from baseline
      p95_threshold  - P95 hourly count threshold
      eval_data      - per-(date, hour, user) eval secrets counts
      alerts         - eval_data rows exceeding p95_threshold
    """
    base_secrets = (
        baseline_df[baseline_df[resource_col] == 'secrets']
        .groupby([date_col, hour_col, user_col])
        .size().reset_index(name='hourly_count')
    )

    if len(base_secrets) == 0:
        empty = pd.DataFrame()
        return {
            'baseline_stats': empty, 'p95_threshold': float('inf'),
            'eval_data': empty,      'alerts': empty,
        }

    baseline_stats = (
        base_secrets.groupby(user_col)['hourly_count']
        .agg(['mean', 'max', 'std', 'count'])
        .round(2)
        .rename(columns={
            'mean':  'avg/hr',
            'max':   'max/hr',
            'std':   'std/hr',
            'count': 'obs (hr slots)',
        })
    )
    p95 = float(np.percentile(base_secrets['hourly_count'].values, 95))

    eval_secrets = (
        eval_df[eval_df[resource_col] == 'secrets']
        .groupby([date_col, hour_col, user_col])
        .size().reset_index(name='hourly_count')
    )
    alerts = (
        eval_secrets[eval_secrets['hourly_count'] > p95]
        if len(eval_secrets) > 0
        else pd.DataFrame()
    )

    return {
        'baseline_stats': baseline_stats,
        'p95_threshold':  p95,
        'eval_data':      eval_secrets,
        'alerts':         alerts,
    }


# =============================================================================
# VISUALIZATION HELPERS
# =============================================================================

def plot_profile_comparison(
    axes,
    baseline_profile,
    compare_profile,
    baseline_label: str = 'Baseline',
    compare_label:  str = 'Comparison',
    baseline_color: str = '#2c7da0',
    compare_color:  str = '#8B5CF6',
    bar_width: float = 0.35,
) -> None:
    """
    Fill a 2×2 axes grid with paired bar charts comparing two BehaviorVector profiles.

    Panels: namespace distribution, verb distribution, resource distribution, hourly activity.
    Designed to work with the output of BehaviorProfiler.build_profile().

    Parameters
    ----------
    axes        : 2×2 matplotlib axes array (from plt.subplots(2, 2))
    baseline_profile / compare_profile : BehaviorVector objects
    """
    import numpy as _np

    def _comparison_bar(ax, b_vec, c_vec, title, rotate=False):
        keys   = sorted(set(list(b_vec.keys()) + list(c_vec.keys())))
        b_vals = [b_vec.get(k, 0) for k in keys]
        c_vals = [c_vec.get(k, 0) for k in keys]
        x = _np.arange(len(keys))
        ax.bar(x - bar_width / 2, b_vals, bar_width,
               label=baseline_label, color=baseline_color, alpha=0.85, edgecolor='none')
        ax.bar(x + bar_width / 2, c_vals, bar_width,
               label=compare_label,  color=compare_color,  alpha=0.85, edgecolor='none')
        ax.set_xticks(x)
        ax.set_xticklabels(keys,
                           rotation=45 if rotate else 0,
                           ha='right' if rotate else 'center',
                           fontsize=8)
        ax.set_title(title)
        ax.set_ylabel('Proportion')
        ax.legend(fontsize=8)

    _comparison_bar(axes[0, 0], baseline_profile.namespace_vector,
                    compare_profile.namespace_vector, 'Namespace Distribution', rotate=True)
    _comparison_bar(axes[0, 1], baseline_profile.verb_vector,
                    compare_profile.verb_vector, 'Verb Distribution')
    _comparison_bar(axes[1, 0], baseline_profile.resource_vector,
                    compare_profile.resource_vector, 'Resource Type Distribution', rotate=True)

    hours      = list(range(24))
    baseline_h = [baseline_profile.hour_vector.get(h, 0) for h in hours]
    compare_h  = [compare_profile.hour_vector.get(h, 0) for h in hours]
    axes[1, 1].bar([h - 0.2 for h in hours], baseline_h, 0.4,
                   label=baseline_label, color=baseline_color, alpha=0.85, edgecolor='none')
    axes[1, 1].bar([h + 0.2 for h in hours], compare_h,  0.4,
                   label=compare_label,  color=compare_color,  alpha=0.85, edgecolor='none')
    axes[1, 1].set_title('Activity by Hour (UTC)')
    axes[1, 1].set_xlabel('Hour')
    axes[1, 1].set_ylabel('Proportion')
    axes[1, 1].legend(fontsize=8)
