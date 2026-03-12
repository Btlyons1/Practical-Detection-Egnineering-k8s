#!/usr/bin/env python3
"""
Synthetic Kubernetes Audit Log Generator

Generates realistic K8s audit logs with:
- Normal cluster activity (controllers, CI/CD, monitoring)
- Human user interactions (platform engineers, developers, data scientists)
- Multi-tenancy patterns (team namespaces, shared resources, sandbox sprawl)
- Configurable attack scenario injections
- Risk posture markers (root pods, hostPath, overpermissioned SAs)

Follows the Detection Engineering Baseline methodology.
Output: DuckDB database matching the CloudTrail baseline pattern.

Author: Brandon Lyons
Repository: github.com/Btlyons1/Detection-Engineering-Baseline
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
import sqlite3


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class ClusterConfig:
    """Configuration for synthetic cluster topology."""
    
    # Time range for generated events
    start_date: datetime = field(default_factory=lambda: datetime(2026, 1, 26))
    end_date: datetime = field(default_factory=lambda: datetime(2026, 2, 25))
    
    # Volume settings
    events_per_day_base: int = 800
    events_per_day_variance: float = 0.3
    
    # Namespace topology
    namespaces: Dict[str, Dict] = field(default_factory=lambda: {
        # System namespaces
        "kube-system": {"type": "system", "risk_level": "low"},
        "kube-public": {"type": "system", "risk_level": "low"},
        "kube-node-lease": {"type": "system", "risk_level": "low"},
        
        # Infrastructure
        "monitoring": {"type": "infrastructure", "risk_level": "low"},
        "ingress-nginx": {"type": "infrastructure", "risk_level": "medium"},
        "cert-manager": {"type": "infrastructure", "risk_level": "low"},
        
        # Team namespaces - proper isolation
        "team-alpha-prod": {"type": "team", "team": "alpha", "env": "prod", "risk_level": "low"},
        "team-alpha-dev": {"type": "team", "team": "alpha", "env": "dev", "risk_level": "low"},
        "team-beta-prod": {"type": "team", "team": "beta", "env": "prod", "risk_level": "low"},
        "team-beta-dev": {"type": "team", "team": "beta", "env": "dev", "risk_level": "low"},
        
        # Data science - shared, higher risk
        "jupyter-notebooks": {"type": "datascience", "risk_level": "high"},
        "ml-pipelines": {"type": "datascience", "risk_level": "medium"},
        
        # Problematic namespaces
        "default": {"type": "problematic", "risk_level": "high"},  # Should be empty
        "sandbox": {"type": "problematic", "risk_level": "high"},  # Junk drawer
    })
    
    # Attack scenarios to inject
    inject_attacks: Dict[str, bool] = field(default_factory=lambda: {
        "jupyter_compromise": True,
        "anonymous_probing": True,
        "rbac_escalation": True,
        "secrets_enumeration": True,
        "cryptominer_daemonset": False,  # Optional - very noisy
    })


# =============================================================================
# ACTORS: Users, Service Accounts, System Components
# =============================================================================

@dataclass
class Actor:
    """Represents an entity that generates audit events."""
    name: str
    actor_type: str  # human, service_account, system
    groups: List[str]
    typical_namespaces: List[str]
    typical_verbs: List[str]
    typical_resources: List[str]
    activity_hours: Tuple[int, int]  # (start_hour, end_hour) in UTC
    activity_weight: float  # Relative activity level
    is_risky: bool = False
    risk_reason: Optional[str] = None


# Human users
HUMAN_USERS = [
    Actor(
        name="platform-eng-alice",
        actor_type="human",
        groups=["system:authenticated", "platform-engineering"],
        typical_namespaces=["kube-system", "monitoring", "ingress-nginx", "team-alpha-prod", 
                           "team-alpha-dev", "team-beta-prod", "team-beta-dev"],
        typical_verbs=["get", "list", "watch", "create", "update", "patch", "delete"],
        typical_resources=["pods", "deployments", "services", "configmaps", "secrets", 
                          "nodes", "namespaces", "pods/log", "pods/exec"],
        activity_hours=(14, 23),  # 9 AM - 6 PM EST (UTC-5)
        activity_weight=1.5,
    ),
    Actor(
        name="platform-eng-bob",
        actor_type="human",
        groups=["system:authenticated", "platform-engineering"],
        typical_namespaces=["kube-system", "monitoring", "cert-manager"],
        typical_verbs=["get", "list", "watch", "create", "update"],
        typical_resources=["pods", "deployments", "services", "certificates", "issuers"],
        activity_hours=(13, 22),  # 8 AM - 5 PM EST
        activity_weight=1.0,
    ),
    Actor(
        name="dev-carlos",
        actor_type="human",
        groups=["system:authenticated", "team-alpha-developers"],
        typical_namespaces=["team-alpha-dev", "team-alpha-prod"],
        typical_verbs=["get", "list", "watch", "create", "update", "delete"],
        typical_resources=["pods", "deployments", "services", "configmaps", "pods/log", 
                          "pods/exec", "pods/portforward"],
        activity_hours=(14, 23),
        activity_weight=1.2,
    ),
    Actor(
        name="dev-diana",
        actor_type="human",
        groups=["system:authenticated", "team-beta-developers"],
        typical_namespaces=["team-beta-dev", "team-beta-prod"],
        typical_verbs=["get", "list", "watch", "create", "update"],
        typical_resources=["pods", "deployments", "services", "configmaps", "pods/log"],
        activity_hours=(15, 24),  # 10 AM - 7 PM EST
        activity_weight=0.9,
    ),
    # Data scientists - heavy notebook users
    Actor(
        name="data-scientist-carol",
        actor_type="human",
        groups=["system:authenticated", "data-science-team"],
        typical_namespaces=["jupyter-notebooks", "ml-pipelines"],
        typical_verbs=["get", "list", "watch", "create", "delete"],
        typical_resources=["pods", "pods/exec", "pods/log", "secrets", "configmaps", 
                          "persistentvolumeclaims"],
        activity_hours=(14, 22),
        activity_weight=1.8,  # High exec activity
    ),
    Actor(
        name="data-scientist-dan",
        actor_type="human",
        groups=["system:authenticated", "data-science-team"],
        typical_namespaces=["jupyter-notebooks", "ml-pipelines"],
        typical_verbs=["get", "list", "watch", "create", "delete"],
        typical_resources=["pods", "pods/exec", "pods/log", "secrets", "configmaps"],
        activity_hours=(16, 1),  # 11 AM - 8 PM EST
        activity_weight=1.5,
    ),
    Actor(
        name="security-eve",
        actor_type="human",
        groups=["system:authenticated", "security-team"],
        typical_namespaces=["kube-system", "monitoring", "team-alpha-prod", "team-beta-prod",
                           "jupyter-notebooks", "default", "sandbox"],
        typical_verbs=["get", "list", "watch"],  # Read-only audit activity
        typical_resources=["pods", "secrets", "configmaps", "serviceaccounts", 
                          "roles", "rolebindings", "clusterroles", "clusterrolebindings",
                          "networkpolicies", "podsecuritypolicies"],
        activity_hours=(14, 20),
        activity_weight=0.6,
    ),
]

# Service accounts
SERVICE_ACCOUNTS = [
    # CI/CD
    Actor(
        name="system:serviceaccount:team-alpha-dev:deploy-bot",
        actor_type="service_account",
        groups=["system:serviceaccounts", "system:serviceaccounts:team-alpha-dev"],
        typical_namespaces=["team-alpha-dev", "team-alpha-prod"],
        typical_verbs=["get", "list", "create", "update", "patch", "delete"],
        typical_resources=["deployments", "services", "configmaps", "secrets", "pods"],
        activity_hours=(0, 24),  # Anytime - CI/CD
        activity_weight=2.0,
    ),
    Actor(
        name="system:serviceaccount:team-beta-dev:deploy-bot",
        actor_type="service_account",
        groups=["system:serviceaccounts", "system:serviceaccounts:team-beta-dev"],
        typical_namespaces=["team-beta-dev", "team-beta-prod"],
        typical_verbs=["get", "list", "create", "update", "patch"],
        typical_resources=["deployments", "services", "configmaps"],
        activity_hours=(0, 24),
        activity_weight=1.5,
    ),
    # Monitoring
    Actor(
        name="system:serviceaccount:monitoring:prometheus",
        actor_type="service_account",
        groups=["system:serviceaccounts", "system:serviceaccounts:monitoring"],
        typical_namespaces=["monitoring", "kube-system", "team-alpha-prod", "team-beta-prod"],
        typical_verbs=["get", "list", "watch"],
        typical_resources=["pods", "services", "endpoints", "nodes", "nodes/metrics"],
        activity_hours=(0, 24),
        activity_weight=3.0,  # High volume watches
    ),
    # Overpermissioned SA - risk marker
    Actor(
        name="system:serviceaccount:jupyter-notebooks:notebook-sa",
        actor_type="service_account",
        groups=["system:serviceaccounts", "system:serviceaccounts:jupyter-notebooks"],
        typical_namespaces=["jupyter-notebooks", "ml-pipelines", "team-alpha-dev"],  # Too broad
        typical_verbs=["get", "list", "watch", "create", "delete"],
        typical_resources=["pods", "secrets", "configmaps", "persistentvolumeclaims", 
                          "pods/exec", "pods/log"],
        activity_hours=(0, 24),
        activity_weight=1.0,
        is_risky=True,
        risk_reason="SA has access outside its namespace",
    ),
]

# System components
SYSTEM_COMPONENTS = [
    Actor(
        name="system:kube-controller-manager",
        actor_type="system",
        groups=["system:masters"],
        typical_namespaces=["kube-system", "default", "team-alpha-prod", "team-beta-prod"],
        typical_verbs=["get", "list", "watch", "update", "patch", "create", "delete"],
        typical_resources=["endpoints", "pods", "replicasets", "deployments", "services",
                          "serviceaccounts", "secrets", "events", "nodes"],
        activity_hours=(0, 24),
        activity_weight=5.0,
    ),
    Actor(
        name="system:kube-scheduler",
        actor_type="system",
        groups=["system:masters"],
        typical_namespaces=["kube-system"],
        typical_verbs=["get", "list", "watch", "update", "patch"],
        typical_resources=["pods", "nodes", "persistentvolumes", "persistentvolumeclaims"],
        activity_hours=(0, 24),
        activity_weight=2.0,
    ),
    Actor(
        name="system:node:node-1",
        actor_type="system",
        groups=["system:nodes"],
        typical_namespaces=["kube-system"],
        typical_verbs=["get", "create", "update", "patch"],
        typical_resources=["nodes", "nodes/status", "pods", "pods/status", 
                          "configmaps", "secrets", "serviceaccounts/token"],
        activity_hours=(0, 24),
        activity_weight=2.5,
    ),
]


# =============================================================================
# AUDIT EVENT GENERATION
# =============================================================================

@dataclass
class AuditEvent:
    """Kubernetes audit event structure."""
    # Core fields
    audit_id: str
    timestamp: str
    
    # Request info
    verb: str
    request_uri: str
    
    # User info
    user_username: str
    user_groups: List[str]
    
    # Source
    source_ips: List[str]
    user_agent: str
    
    # Object reference
    object_ref_resource: Optional[str]
    object_ref_namespace: Optional[str]
    object_ref_name: Optional[str]
    object_ref_api_group: Optional[str]
    object_ref_api_version: Optional[str]
    object_ref_subresource: Optional[str]
    
    # Response
    response_status_code: int
    response_status_reason: Optional[str]
    
    # Stage
    stage: str
    
    # Annotations
    authorization_decision: str
    authorization_reason: Optional[str]
    
    # Metadata for analysis
    is_attack: bool = False
    attack_scenario: Optional[str] = None
    is_risky_config: bool = False
    risk_marker: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class AuditEventGenerator:
    """Generates synthetic K8s audit events."""
    
    def __init__(self, config: ClusterConfig):
        self.config = config
        self.all_actors = HUMAN_USERS + SERVICE_ACCOUNTS + SYSTEM_COMPONENTS
        
        # Resource name pools
        self.pod_names = [
            "web-frontend-abc123", "api-server-def456", "worker-ghi789",
            "nginx-ingress-xyz", "prometheus-0", "grafana-abc",
            "carol-notebook-0", "dan-notebook-0", "shared-gpu-notebook",
            "training-job-123", "inference-server-456",
            "legacy-api-789", "test-pod-dan", "experiment-2024-03",
        ]
        self.deployment_names = [
            "web-frontend", "api-server", "worker", "nginx-ingress",
            "prometheus", "grafana", "redis", "postgres",
        ]
        self.secret_names = [
            "db-credentials", "api-keys", "tls-cert", "registry-creds",
            "aws-credentials", "model-secrets", "jupyter-token",
        ]
        self.configmap_names = [
            "app-config", "nginx-config", "prometheus-config", 
            "feature-flags", "env-vars",
        ]
        self.service_account_names = [
            "default", "deploy-bot", "prometheus", "notebook-sa",
            "admin-sa", "readonly-sa",
        ]
        
        # Source IP pools
        self.internal_ips = ["10.0.1.50", "10.0.1.51", "10.0.1.52", "10.0.2.100"]
        self.vpn_ips = ["192.168.100.10", "192.168.100.11", "192.168.100.12"]
        self.cicd_ips = ["10.0.50.10", "10.0.50.11"]
        
    def _generate_request_uri(self, verb: str, resource: str, namespace: Optional[str], 
                              name: Optional[str], subresource: Optional[str] = None) -> str:
        """Build the request URI from components."""
        # Determine API path
        core_resources = ["pods", "services", "secrets", "configmaps", "serviceaccounts",
                         "nodes", "namespaces", "endpoints", "events", "persistentvolumeclaims"]
        
        if resource in core_resources or resource.startswith("pods/"):
            api_prefix = "/api/v1"
        else:
            api_prefix = "/apis/apps/v1"
        
        # Build path
        if namespace:
            path = f"{api_prefix}/namespaces/{namespace}/{resource.split('/')[0]}"
        else:
            path = f"{api_prefix}/{resource.split('/')[0]}"
        
        if name:
            path += f"/{name}"
            
        if subresource or "/" in resource:
            sub = subresource or resource.split("/")[1]
            path += f"/{sub}"
            
        return path
    
    def _get_user_agent(self, actor: Actor) -> str:
        """Generate appropriate user agent for actor type."""
        if actor.actor_type == "human":
            kubectl_versions = ["v1.28.0", "v1.27.3", "v1.26.5"]
            return f"kubectl/{random.choice(kubectl_versions)} (linux/amd64)"
        elif actor.actor_type == "service_account":
            return "kubernetes-client/go/v0.28.0"
        else:
            return "kube-controller-manager/v1.28.0"
    
    def _get_source_ip(self, actor: Actor) -> List[str]:
        """Get appropriate source IP for actor."""
        if actor.actor_type == "human":
            return [random.choice(self.vpn_ips)]
        elif actor.actor_type == "service_account":
            return [random.choice(self.internal_ips + self.cicd_ips)]
        else:
            return [random.choice(self.internal_ips)]
    
    def _get_resource_name(self, resource: str, namespace: str) -> str:
        """Get a realistic resource name."""
        base_resource = resource.split("/")[0]
        
        if base_resource == "pods":
            return random.choice(self.pod_names)
        elif base_resource == "deployments":
            return random.choice(self.deployment_names)
        elif base_resource == "secrets":
            return random.choice(self.secret_names)
        elif base_resource == "configmaps":
            return random.choice(self.configmap_names)
        elif base_resource == "serviceaccounts":
            return random.choice(self.service_account_names)
        elif base_resource == "nodes":
            return f"node-{random.randint(1, 5)}"
        else:
            return f"{base_resource}-{uuid.uuid4().hex[:8]}"
    
    def _is_within_activity_hours(self, timestamp: datetime, actor: Actor) -> bool:
        """Check if timestamp falls within actor's typical activity hours."""
        hour = timestamp.hour
        start, end = actor.activity_hours
        
        if start <= end:
            return start <= hour < end
        else:  # Wraps around midnight
            return hour >= start or hour < end
    
    def generate_normal_event(self, timestamp: datetime) -> AuditEvent:
        """Generate a single normal audit event."""
        # Weight actor selection by activity_weight
        weights = [a.activity_weight for a in self.all_actors]
        actor = random.choices(self.all_actors, weights=weights)[0]
        
        # Select verb and resource
        verb = random.choice(actor.typical_verbs)
        resource = random.choice(actor.typical_resources)
        namespace = random.choice(actor.typical_namespaces) if actor.typical_namespaces else None
        
        # Subresource handling
        subresource = None
        if "/" in resource:
            subresource = resource.split("/")[1]
            resource = resource.split("/")[0]
        
        # Get resource name for non-list/watch operations
        name = None
        if verb not in ["list", "watch"]:
            name = self._get_resource_name(resource, namespace)
        
        # Build the event
        return AuditEvent(
            audit_id=str(uuid.uuid4()),
            timestamp=timestamp.isoformat() + "Z",
            verb=verb,
            request_uri=self._generate_request_uri(verb, resource, namespace, name, subresource),
            user_username=actor.name,
            user_groups=actor.groups,
            source_ips=self._get_source_ip(actor),
            user_agent=self._get_user_agent(actor),
            object_ref_resource=resource,
            object_ref_namespace=namespace,
            object_ref_name=name,
            object_ref_api_group="" if resource in ["pods", "secrets", "configmaps", 
                                                     "services", "serviceaccounts"] else "apps",
            object_ref_api_version="v1",
            object_ref_subresource=subresource,
            response_status_code=200,
            response_status_reason="OK",
            stage="ResponseComplete",
            authorization_decision="allow",
            authorization_reason="RBAC: allowed",
            is_attack=False,
            is_risky_config=actor.is_risky,
            risk_marker=actor.risk_reason,
        )
    
    def generate_events_for_day(self, date: datetime) -> List[AuditEvent]:
        """Generate all events for a single day."""
        events = []
        
        # Calculate event count with variance
        base_count = self.config.events_per_day_base
        variance = int(base_count * self.config.events_per_day_variance)
        event_count = random.randint(base_count - variance, base_count + variance)
        
        # Weekends have less activity
        if date.weekday() >= 5:
            event_count = int(event_count * 0.3)
        
        # Generate timestamps distributed throughout the day
        # More activity during business hours
        for _ in range(event_count):
            # Bias toward business hours (weighted random)
            if random.random() < 0.7:  # 70% during business hours
                hour = random.randint(13, 22)  # ~8 AM - 5 PM EST in UTC
            else:
                hour = random.randint(0, 23)
            
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            timestamp = date.replace(hour=hour, minute=minute, second=second)
            events.append(self.generate_normal_event(timestamp))
        
        return events


# =============================================================================
# ATTACK SCENARIO INJECTION
# =============================================================================

class AttackInjector:
    """Injects realistic attack patterns into audit logs."""
    
    def __init__(self, config: ClusterConfig):
        self.config = config
        self.attack_source_ip = "10.0.99.99"  # Compromised internal
        self.anonymous_source_ips = ["203.0.113.50", "198.51.100.25"]  # External
    
    def inject_jupyter_compromise(self, events: List[AuditEvent],
                                   attack_date: datetime) -> List[AuditEvent]:
        """
        Multi-day Jupyter notebook compromise scenario (business hours).

        Attack path:
          - Attacker exploits the exposed Jupyter port (or a malicious notebook dependency)
            to gain code execution inside carol-notebook-0 (pod IP 10.0.99.99).
          - From inside the pod they find Carol's kubeconfig and issue API calls using
            the Python kubernetes client. Source IP is the pod IP, not Carol's workstation.
          - Operates slowly across multiple days to stay within normal volume bounds.
          - Later phases pivot to the mounted notebook-sa token (same pod, same IP,
            but kubernetes-client/go user-agent reflects a different tool).

        Phase 1  (attack_date,     14:30 UTC) - Namespace discovery
          Attacker maps what namespaces Carol's credentials can reach from inside the pod.
          Volume is indistinguishable from Carol's normal afternoon activity.

        Phase 2  (attack_date + 2, 15:15 UTC) - Credential harvesting
          Targeted secret reads in newly discovered namespaces. One SA token
          creation attempt to establish a persistent foothold.

        Phase 3  (attack_date + 4, 14:00 UTC) - RBAC enumeration and escalation
          Attacker maps cluster-wide RBAC to find privilege paths, then creates
          an in-namespace role binding to escalate within jupyter-notebooks.
        """
        attack_events = []

        carol = "data-scientist-carol"
        carol_groups = ["system:authenticated", "data-science-team"]
        carol_ip = ["10.0.99.99"]   # pod-internal IP: attacker operating from inside carol-notebook-0
        carol_ua = "python-kubernetes/28.1.0"  # Python K8s client used from within the Jupyter pod

        def _evt(ts, verb, resource, namespace, name, api_group, subresource,
                 status_code, status_reason, authz_decision, authz_reason):
            return AuditEvent(
                audit_id=str(uuid.uuid4()),
                timestamp=ts.isoformat() + "Z",
                verb=verb,
                request_uri=self._build_uri(verb, resource, namespace, name, subresource),
                user_username=carol,
                user_groups=carol_groups,
                source_ips=carol_ip,
                user_agent=carol_ua,
                object_ref_resource=resource,
                object_ref_namespace=namespace,
                object_ref_name=name,
                object_ref_api_group=api_group,
                object_ref_api_version="v1",
                object_ref_subresource=subresource,
                response_status_code=status_code,
                response_status_reason=status_reason,
                stage="ResponseComplete",
                authorization_decision=authz_decision,
                authorization_reason=authz_reason,
                is_attack=True,
                attack_scenario="jupyter_compromise",
            )

        # ------------------------------------------------------------------
        # Phase 1 – Namespace Discovery  (attack_date, 14:30 UTC)
        # Attacker enumerates pods across namespaces they shouldn't touch.
        # Carol normally only visits jupyter-notebooks and ml-pipelines.
        # ------------------------------------------------------------------
        p1 = attack_date.replace(hour=14, minute=30, second=0, microsecond=0)

        # list pods in out-of-scope team namespaces and kube-system
        for i, ns in enumerate(["team-alpha-prod", "team-beta-prod", "kube-system"]):
            attack_events.append(_evt(
                ts=p1 + timedelta(minutes=i * 3),
                verb="list", resource="pods", namespace=ns, name=None,
                api_group="", subresource=None,
                status_code=200, status_reason="OK",
                authz_decision="allow", authz_reason="RBAC: allowed",
            ))

        # cluster-scoped namespace list — first time Carol's token is used
        # to enumerate namespaces (new resource type for her profile)
        attack_events.append(_evt(
            ts=p1 + timedelta(minutes=10),
            verb="list", resource="namespaces", namespace=None, name=None,
            api_group="", subresource=None,
            status_code=200, status_reason="OK",
            authz_decision="allow", authz_reason="RBAC: allowed",
        ))

        # ------------------------------------------------------------------
        # Phase 2 – Credential Harvesting  (attack_date + 2, 15:15 UTC)
        # Attacker returns two days later, now targeting secrets in the
        # namespaces confirmed reachable during Phase 1.
        # ------------------------------------------------------------------
        p2 = (attack_date + timedelta(days=2)).replace(
            hour=15, minute=15, second=0, microsecond=0
        )

        # bulk list secrets in team-alpha-prod (new namespace for Carol)
        attack_events.append(_evt(
            ts=p2,
            verb="list", resource="secrets", namespace="team-alpha-prod", name=None,
            api_group="", subresource=None,
            status_code=200, status_reason="OK",
            authz_decision="allow", authz_reason="RBAC: allowed",
        ))

        # targeted gets — db creds succeed, cross-tenant api-keys forbidden
        for i, (ns, secret, code, reason, dec, authz) in enumerate([
            ("team-alpha-prod", "db-credentials",  200, "OK",        "allow", "RBAC: allowed"),
            ("team-alpha-prod", "aws-credentials",  200, "OK",        "allow", "RBAC: allowed"),
            ("team-beta-prod",  "api-keys",          403, "Forbidden", "deny",  "RBAC: access denied"),
        ]):
            attack_events.append(_evt(
                ts=p2 + timedelta(minutes=2 + i * 2),
                verb="get", resource="secrets", namespace=ns, name=secret,
                api_group="", subresource=None,
                status_code=code, status_reason=reason,
                authz_decision=dec, authz_reason=authz,
            ))

        # SA token creation to mint a long-lived credential (persistence)
        attack_events.append(_evt(
            ts=p2 + timedelta(minutes=10),
            verb="create", resource="serviceaccounts", namespace="jupyter-notebooks",
            name="notebook-sa", api_group="", subresource="token",
            status_code=201, status_reason="Created",
            authz_decision="allow", authz_reason="RBAC: allowed",
        ))

        # ------------------------------------------------------------------
        # Phase 3 – RBAC Enumeration & Escalation  (attack_date + 4, 14:00 UTC)
        # Attacker maps cluster-wide RBAC to find privilege paths, then
        # creates a rolebinding to escalate within the jupyter-notebooks ns.
        # ------------------------------------------------------------------
        p3 = (attack_date + timedelta(days=6)).replace(
            hour=14, minute=0, second=0, microsecond=0
        )

        # cluster-scoped RBAC reads — new resource type for Carol
        for i, resource in enumerate(["clusterroles", "clusterrolebindings"]):
            attack_events.append(_evt(
                ts=p3 + timedelta(minutes=i * 2),
                verb="list", resource=resource, namespace=None, name=None,
                api_group="rbac.authorization.k8s.io", subresource=None,
                status_code=200, status_reason="OK",
                authz_decision="allow", authz_reason="RBAC: allowed",
            ))

        # namespace-scoped RBAC reads
        attack_events.append(_evt(
            ts=p3 + timedelta(minutes=5),
            verb="list", resource="roles", namespace="jupyter-notebooks", name=None,
            api_group="rbac.authorization.k8s.io", subresource=None,
            status_code=200, status_reason="OK",
            authz_decision="allow", authz_reason="RBAC: allowed",
        ))

        # escalation: create a rolebinding (succeeds — misconfigured RBAC)
        attack_events.append(_evt(
            ts=p3 + timedelta(minutes=8),
            verb="create", resource="rolebindings", namespace="jupyter-notebooks",
            name="escalated-binding", api_group="rbac.authorization.k8s.io",
            subresource=None,
            status_code=201, status_reason="Created",
            authz_decision="allow", authz_reason="RBAC: allowed",
        ))

        events.extend(attack_events)
        return events

    def _build_uri(self, verb: str, resource: str, namespace, name, subresource) -> str:
        """Minimal URI builder for attack events."""
        rbac_resources = {
            "clusterroles", "clusterrolebindings", "roles", "rolebindings",
        }
        if resource in rbac_resources:
            api_prefix = "/apis/rbac.authorization.k8s.io/v1"
        elif resource in {"namespaces", "selfsubjectaccessreviews"}:
            api_prefix = "/api/v1"
        else:
            api_prefix = "/api/v1"

        if namespace:
            path = f"{api_prefix}/namespaces/{namespace}/{resource}"
        else:
            path = f"{api_prefix}/{resource}"

        if name:
            path += f"/{name}"
        if subresource:
            path += f"/{subresource}"
        return path
    
    def inject_anonymous_probing(self, events: List[AuditEvent],
                                  attack_date: datetime) -> List[AuditEvent]:
        """
        Simulate external attacker probing for anonymous access.
        
        Pattern: Rapid-fire requests from external IP testing various endpoints.
        """
        attack_events = []
        base_time = attack_date.replace(hour=2, minute=30)
        
        probe_paths = [
            "/api/v1/pods",
            "/api/v1/namespaces",
            "/api/v1/secrets",
            "/api/v1/nodes",
            "/apis/apps/v1/deployments",
            "/healthz",
            "/version",
            "/api/v1/namespaces/kube-system/secrets",
        ]
        
        for i, path in enumerate(probe_paths):
            attack_events.append(AuditEvent(
                audit_id=str(uuid.uuid4()),
                timestamp=(base_time + timedelta(seconds=i*3)).isoformat() + "Z",
                verb="get" if "secrets" in path else "list",
                request_uri=path,
                user_username="system:anonymous",
                user_groups=["system:unauthenticated"],
                source_ips=[random.choice(self.anonymous_source_ips)],
                user_agent="curl/7.68.0",
                object_ref_resource=path.split("/")[-1] if "/" in path else None,
                object_ref_namespace="kube-system" if "kube-system" in path else None,
                object_ref_name=None,
                object_ref_api_group="",
                object_ref_api_version="v1",
                object_ref_subresource=None,
                response_status_code=403,
                response_status_reason="Forbidden",
                stage="ResponseComplete",
                authorization_decision="deny",
                authorization_reason="RBAC: access denied",
                is_attack=True,
                attack_scenario="anonymous_probing",
            ))
        
        events.extend(attack_events)
        return events
    
    def inject_rbac_escalation(self, events: List[AuditEvent],
                                attack_date: datetime) -> List[AuditEvent]:
        """
        Simulate privilege escalation via RBAC manipulation.
        
        Pattern: Compromised service account attempts to create cluster-admin binding.
        """
        attack_events = []
        base_time = attack_date.replace(hour=4, minute=45)
        
        # Attacker using compromised notebook SA
        compromised_sa = "system:serviceaccount:jupyter-notebooks:notebook-sa"
        
        # Step 1: Check current permissions
        attack_events.append(AuditEvent(
            audit_id=str(uuid.uuid4()),
            timestamp=base_time.isoformat() + "Z",
            verb="create",
            request_uri="/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            user_username=compromised_sa,
            user_groups=["system:serviceaccounts", "system:serviceaccounts:jupyter-notebooks"],
            source_ips=[self.attack_source_ip],
            user_agent="kubernetes-client/go/v0.28.0",
            object_ref_resource="selfsubjectaccessreviews",
            object_ref_namespace=None,
            object_ref_name=None,
            object_ref_api_group="authorization.k8s.io",
            object_ref_api_version="v1",
            object_ref_subresource=None,
            response_status_code=201,
            response_status_reason="Created",
            stage="ResponseComplete",
            authorization_decision="allow",
            authorization_reason="RBAC: allowed",
            is_attack=True,
            attack_scenario="rbac_escalation",
        ))
        
        # Step 2: Attempt to create cluster-admin binding
        attack_events.append(AuditEvent(
            audit_id=str(uuid.uuid4()),
            timestamp=(base_time + timedelta(minutes=1)).isoformat() + "Z",
            verb="create",
            request_uri="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            user_username=compromised_sa,
            user_groups=["system:serviceaccounts", "system:serviceaccounts:jupyter-notebooks"],
            source_ips=[self.attack_source_ip],
            user_agent="kubernetes-client/go/v0.28.0",
            object_ref_resource="clusterrolebindings",
            object_ref_namespace=None,
            object_ref_name="backdoor-admin-binding",
            object_ref_api_group="rbac.authorization.k8s.io",
            object_ref_api_version="v1",
            object_ref_subresource=None,
            response_status_code=403,
            response_status_reason="Forbidden",
            stage="ResponseComplete",
            authorization_decision="deny",
            authorization_reason="RBAC: access denied",
            is_attack=True,
            attack_scenario="rbac_escalation",
        ))
        
        # Step 3: Try namespace-scoped escalation instead
        attack_events.append(AuditEvent(
            audit_id=str(uuid.uuid4()),
            timestamp=(base_time + timedelta(minutes=2)).isoformat() + "Z",
            verb="create",
            request_uri="/apis/rbac.authorization.k8s.io/v1/namespaces/jupyter-notebooks/rolebindings",
            user_username=compromised_sa,
            user_groups=["system:serviceaccounts", "system:serviceaccounts:jupyter-notebooks"],
            source_ips=[self.attack_source_ip],
            user_agent="kubernetes-client/go/v0.28.0",
            object_ref_resource="rolebindings",
            object_ref_namespace="jupyter-notebooks",
            object_ref_name="escalated-binding",
            object_ref_api_group="rbac.authorization.k8s.io",
            object_ref_api_version="v1",
            object_ref_subresource=None,
            response_status_code=201,  # This one succeeds - bad RBAC config
            response_status_reason="Created",
            stage="ResponseComplete",
            authorization_decision="allow",
            authorization_reason="RBAC: allowed",
            is_attack=True,
            attack_scenario="rbac_escalation",
        ))
        
        events.extend(attack_events)
        return events
    
    def inject_secrets_enumeration(self, events: List[AuditEvent],
                                    attack_date: datetime) -> List[AuditEvent]:
        """
        Simulate broad secrets enumeration across namespaces.
        
        Pattern: Attacker lists secrets in all accessible namespaces.
        """
        attack_events = []
        base_time = attack_date.replace(hour=5, minute=10)
        
        # Using the overpermissioned notebook SA
        attacker_sa = "system:serviceaccount:jupyter-notebooks:notebook-sa"
        
        all_namespaces = list(self.config.namespaces.keys())
        
        for i, ns in enumerate(all_namespaces):
            # List secrets in namespace
            response_code = 200 if ns in ["jupyter-notebooks", "ml-pipelines", 
                                          "team-alpha-dev", "default"] else 403
            
            attack_events.append(AuditEvent(
                audit_id=str(uuid.uuid4()),
                timestamp=(base_time + timedelta(seconds=i*5)).isoformat() + "Z",
                verb="list",
                request_uri=f"/api/v1/namespaces/{ns}/secrets",
                user_username=attacker_sa,
                user_groups=["system:serviceaccounts", "system:serviceaccounts:jupyter-notebooks"],
                source_ips=[self.attack_source_ip],
                user_agent="kubernetes-client/go/v0.28.0",
                object_ref_resource="secrets",
                object_ref_namespace=ns,
                object_ref_name=None,
                object_ref_api_group="",
                object_ref_api_version="v1",
                object_ref_subresource=None,
                response_status_code=response_code,
                response_status_reason="OK" if response_code == 200 else "Forbidden",
                stage="ResponseComplete",
                authorization_decision="allow" if response_code == 200 else "deny",
                authorization_reason="RBAC: allowed" if response_code == 200 else "RBAC: access denied",
                is_attack=True,
                attack_scenario="secrets_enumeration",
            ))
        
        events.extend(attack_events)
        return events


# =============================================================================
# RISK MARKER INJECTION
# =============================================================================

class RiskMarkerInjector:
    """Injects events that indicate risky configurations."""
    
    def inject_risky_pod_creations(self, events: List[AuditEvent],
                                    date_range: Tuple[datetime, datetime]) -> List[AuditEvent]:
        """
        Add pod creation events with risky security contexts.
        These represent existing misconfigurations in the cluster.
        """
        risk_events = []
        start_date, end_date = date_range
        
        risky_pods = [
            {
                "name": "legacy-api-789",
                "namespace": "default",  # Risk: workload in default
                "risk_marker": "workload_in_default_namespace",
                "creator": "dev-carlos",
            },
            {
                "name": "log-collector-ds",
                "namespace": "monitoring",
                "risk_marker": "hostPath_volume_mount",
                "creator": "platform-eng-alice",
            },
            {
                "name": "debug-pod-root",
                "namespace": "sandbox",
                "risk_marker": "container_running_as_root",
                "creator": "dev-diana",
            },
            {
                "name": "network-tools",
                "namespace": "sandbox",
                "risk_marker": "hostNetwork_enabled",
                "creator": "platform-eng-bob",
            },
            {
                "name": "shared-gpu-notebook",
                "namespace": "jupyter-notebooks",
                "risk_marker": "privileged_container",
                "creator": "data-scientist-carol",
            },
        ]
        
        for pod_config in risky_pods:
            # Random time in the date range
            random_day = start_date + timedelta(
                days=random.randint(0, (end_date - start_date).days)
            )
            timestamp = random_day.replace(
                hour=random.randint(14, 20),
                minute=random.randint(0, 59)
            )
            
            risk_events.append(AuditEvent(
                audit_id=str(uuid.uuid4()),
                timestamp=timestamp.isoformat() + "Z",
                verb="create",
                request_uri=f"/api/v1/namespaces/{pod_config['namespace']}/pods",
                user_username=pod_config["creator"],
                user_groups=["system:authenticated"],
                source_ips=["192.168.100.10"],
                user_agent="kubectl/v1.28.0 (linux/amd64)",
                object_ref_resource="pods",
                object_ref_namespace=pod_config["namespace"],
                object_ref_name=pod_config["name"],
                object_ref_api_group="",
                object_ref_api_version="v1",
                object_ref_subresource=None,
                response_status_code=201,
                response_status_reason="Created",
                stage="ResponseComplete",
                authorization_decision="allow",
                authorization_reason="RBAC: allowed",
                is_attack=False,
                is_risky_config=True,
                risk_marker=pod_config["risk_marker"],
            ))
        
        events.extend(risk_events)
        return events


# =============================================================================
# DATABASE OUTPUT
# =============================================================================

def save_to_sqlite(events: List[AuditEvent], db_path: str):
    """Save events to SQLite database (portable pattern for DuckDB/Snowflake/etc)."""
    
    # Convert events to records
    records = [e.to_dict() for e in events]
    
    # Connect and create table
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Drop and recreate to ensure a clean slate on every run
    cursor.execute("DROP TABLE IF EXISTS k8s_audit_events")
    cursor.execute("""
        CREATE TABLE k8s_audit_events (
            audit_id TEXT PRIMARY KEY,
            timestamp TEXT,
            verb TEXT,
            request_uri TEXT,
            user_username TEXT,
            user_groups TEXT,
            source_ips TEXT,
            user_agent TEXT,
            object_ref_resource TEXT,
            object_ref_namespace TEXT,
            object_ref_name TEXT,
            object_ref_api_group TEXT,
            object_ref_api_version TEXT,
            object_ref_subresource TEXT,
            response_status_code INTEGER,
            response_status_reason TEXT,
            stage TEXT,
            authorization_decision TEXT,
            authorization_reason TEXT,
            is_attack INTEGER,
            attack_scenario TEXT,
            is_risky_config INTEGER,
            risk_marker TEXT
        )
    """)
    
    # Insert records
    for record in records:
        cursor.execute("""
            INSERT INTO k8s_audit_events VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, [
            record["audit_id"],
            record["timestamp"],
            record["verb"],
            record["request_uri"],
            record["user_username"],
            json.dumps(record["user_groups"]),  # Store lists as JSON
            json.dumps(record["source_ips"]),
            record["user_agent"],
            record["object_ref_resource"],
            record["object_ref_namespace"],
            record["object_ref_name"],
            record["object_ref_api_group"],
            record["object_ref_api_version"],
            record["object_ref_subresource"],
            record["response_status_code"],
            record["response_status_reason"],
            record["stage"],
            record["authorization_decision"],
            record["authorization_reason"],
            1 if record["is_attack"] else 0,
            record["attack_scenario"],
            1 if record["is_risky_config"] else 0,
            record["risk_marker"],
        ])
    
    conn.commit()
    conn.close()
    print(f"Saved {len(records)} events to {db_path}")


# =============================================================================
# MAIN GENERATION FUNCTION
# =============================================================================

def generate_synthetic_audit_logs(
    output_path: str = "files/k8s_audit_events.db",
    days: int = 30,
    inject_attacks: bool = True,
) -> str:
    """
    Generate synthetic K8s audit logs.
    
    Parameters
    ----------
    output_path : str
        Path for output SQLite file (pattern works for DuckDB, etc.)
    days : int
        Number of days of data to generate
    inject_attacks : bool
        Whether to inject attack scenarios
        
    Returns
    -------
    str
        Path to generated database
    """
    config = ClusterConfig(
        start_date=datetime(2026, 1, 26),
        end_date=datetime(2026, 2, 25),
    )
    
    generator = AuditEventGenerator(config)
    attack_injector = AttackInjector(config)
    risk_injector = RiskMarkerInjector()
    
    all_events = []
    
    # Generate normal events for each day
    current_date = config.start_date
    while current_date <= config.end_date:
        day_events = generator.generate_events_for_day(current_date)
        all_events.extend(day_events)
        current_date += timedelta(days=1)
    
    print(f"Generated {len(all_events)} normal events")
    
    # Inject attacks at specific dates
    if inject_attacks:
        attack_date = config.start_date + timedelta(days=days // 2)  # Middle of range
        
        if config.inject_attacks.get("jupyter_compromise"):
            all_events = attack_injector.inject_jupyter_compromise(all_events, attack_date)
            print("Injected jupyter_compromise scenario")
            
        if config.inject_attacks.get("anonymous_probing"):
            probe_date = attack_date - timedelta(days=3)
            all_events = attack_injector.inject_anonymous_probing(all_events, probe_date)
            print("Injected anonymous_probing scenario")
            
        if config.inject_attacks.get("rbac_escalation"):
            all_events = attack_injector.inject_rbac_escalation(all_events, attack_date)
            print("Injected rbac_escalation scenario")
            
        if config.inject_attacks.get("secrets_enumeration"):
            enum_date = attack_date + timedelta(hours=2)
            all_events = attack_injector.inject_secrets_enumeration(all_events, enum_date)
            print("Injected secrets_enumeration scenario")
    
    # Inject risky configuration markers
    all_events = risk_injector.inject_risky_pod_creations(
        all_events, 
        (config.start_date, config.end_date)
    )
    print("Injected risky configuration markers")
    
    # Sort by timestamp
    all_events.sort(key=lambda e: e.timestamp)
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Save to SQLite
    save_to_sqlite(all_events, output_path)
    
    # Print summary
    attack_count = sum(1 for e in all_events if e.is_attack)
    risky_count = sum(1 for e in all_events if e.is_risky_config)
    
    print(f"\n=== Generation Summary ===")
    print(f"Total events: {len(all_events)}")
    print(f"Date range: {config.start_date.date()} to {config.end_date.date()}")
    print(f"Attack events: {attack_count}")
    print(f"Risky config events: {risky_count}")
    print(f"Output: {output_path}")
    
    return output_path


if __name__ == "__main__":
    generate_synthetic_audit_logs()
