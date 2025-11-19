# Kubernetes RBAC & Network Policies: Comprehensive Security Guide

## Table of Contents
1. [Introduction](#introduction)
2. [RBAC Architecture](#rbac-architecture)
3. [RBAC Implementation](#rbac-implementation)
4. [Network Policies Architecture](#network-policies-architecture)
5. [Network Policies Implementation](#network-policies-implementation)
6. [End-to-End Security Implementation](#end-to-end-security-implementation)
7. [Best Practices & Auditing](#best-practices--auditing)

## Introduction

RBAC (Role-Based Access Control) and Network Policies are fundamental security primitives in Kubernetes that implement the principle of least privilege for both access control and network traffic.

## RBAC Architecture

### RBAC Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    RBAC SECURITY MODEL                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │    SUBJECTS     │    │     ROLES       │    │  RESOURCES  │  │
│  │                 │    │                 │    │             │  │
│  │ • Users         │    │ • Permissions   │    │ • Pods      │  │
│  │ • Groups        │────│ • Verbs         │────│ • Services  │  │
│  │ • Service       │    │ • API Groups    │    │ • Secrets   │  │
│  │   Accounts      │    │ • Resources     │    │ • ConfigMaps│  │
│  │                 │    │ • Resource Names│    │ • etc.      │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    BINDINGS                                 ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       ││
│  │  │   ROLE       │  │ CLUSTER ROLE │  │ CLUSTER ROLE │       ││
│  │  │   BINDING    │  │   BINDING    │  │   BINDING    │       ││
│  │  │              │  │              │  │              │       ││
│  │  │ • Namespaced │  │ • Cluster-   │  │ • Cluster-   │       ││
│  │  │ • Links      │  │   wide       │  │   wide       │       ││
│  │  │   Role to    │  │ • Links      │  │ • Links      │       ││
│  │  │   Subjects   │  │   ClusterRole│  │   ClusterRole│       ││
│  │  │              │  │   to Subjects│  │   to Subjects│       ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘       ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 SECURITY CONTROLS                           ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       ││
│  │  │  PRINCIPLE   │  │   REGULAR    │  │   AUTOMATED  │       ││
│  │  │ OF LEAST     │  │    AUDITS    │  │   COMPLIANCE │       ││
│  │  │ PRIVILEGE    │  │              │  │   CHECKS     │       ││
│  │  │              │  │ • Role       │  │              │       ││
│  │  │ • Minimal    │  │   Reviews    │  │ • Continuous │       ││
│  │  │   Permissions│  │ • Access     │  │   Monitoring │       ││
│  │  │ • Just-      │  │   Logs       │  │ • Policy as  │       ││
│  │  │   Enough-    │  │ • Compliance │  │   Code       │       ││
│  │  │   Access     │  │   Checks     │  │ • Alerts     │       ││
│  │  │ • Time-      │  │              │  │              │       ││
│  │  │   Limited    │  │              │  │              │       ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘       ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### RBAC Component Relationships

```
Subjects (Who) → Bindings (Links) → Roles (What) → Resources (Where)

• Users/Groups/ServiceAccounts → RoleBindings/ClusterRoleBindings → 
  Roles/ClusterRoles → API Resources + Verbs
```

## RBAC Implementation

### 1. Cluster Role Management

```yaml
# cluster-roles-secure.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
  labels:
    rbac.authorization.k8s.io/aggregate-to-view: "true"
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: namespace-reader
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: limited-deployer
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments/scale"]
  verbs: ["get", "update"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: network-policy-manager
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

### 2. Namespaced Roles

```yaml
# namespaced-roles.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: deployment-manager
rules:
- apiGroups: ["apps", "extensions"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: pod-log-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: kube-system
  name: metrics-reader
rules:
- apiGroups: [""]
  resources: ["pods", "nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods", "nodes"]
  verbs: ["get", "list", "watch"]
```

### 3. Role Bindings with Least Privilege

```yaml
# role-bindings-least-privilege.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: development
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deployment-manager
subjects:
- kind: User
  name: alice@company.com
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: support-reader
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-log-reader
subjects:
- kind: Group
  name: support-team
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: cluster-admin@company.com
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: cluster-admins
  apiGroup: rbac.authorization.k8s.io
```

### 4. Service Account RBAC

```yaml
# service-account-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitoring-agent
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-reader
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: monitoring-agent-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: monitoring-reader
subjects:
- kind: ServiceAccount
  name: monitoring-agent
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: monitoring
  name: config-updater
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "update", "patch"]
  resourceNames: ["monitoring-config"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: monitoring
  name: monitoring-config-updater
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: config-updater
subjects:
- kind: ServiceAccount
  name: monitoring-agent
  namespace: monitoring
```

### 5. Advanced RBAC Patterns

```yaml
# advanced-rbac-patterns.yaml
# 1. Resource-specific permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: specific-deployment-manager
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  resourceNames: ["frontend", "backend", "database"]
  verbs: ["get", "update", "patch"]
---
# 2. Cross-namespace access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cross-namespace-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cross-namespace-auditor
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cross-namespace-reader
subjects:
- kind: User
  name: auditor@company.com
  apiGroup: rbac.authorization.k8s.io
---
# 3. Fine-grained secret access
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: secret-reader-specific
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["database-credentials", "api-keys"]
  verbs: ["get", "list"]
---
# 4. Pod exec restrictions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: pod-executor
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
  resourceNames: ["debug-pod-*"]
```

## Network Policies Architecture

### Network Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                 NETWORK POLICY SECURITY MODEL                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   INGRESS       │    │    EGRESS       │    │   ISOLATION │  │
│  │   RULES         │    │    RULES        │    │   STRATEGY  │  │
│  │                 │    │                 │    │             │  │
│  │ • From:         │    │ • To:           │    │ • Default   │  │
│  │   - PodSelector │    │   - PodSelector │    │   Deny All  │  │
│  │   - Namespace   │    │   - Namespace   │    │ • Namespace │  │
│  │     Selector    │    │     Selector    │    │   Isolation │  │
│  │   - IPBlock     │    │   - IPBlock     │    │ • Application│  │
│  │ • Ports:        │    │ • Ports:        │    │   Tier      │  │
│  │   - Protocol    │    │   - Protocol    │    │   Isolation │  │
│  │   - Port        │    │   - Port        │    │             │  │
│  │   - EndPort     │    │   - EndPort     │    │             │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 TRAFFIC FLOW CONTROL                        ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       ││
│  │  │   EAST-WEST  │  │  NORTH-SOUTH │  │   MICRO-     │       ││
│  │  │   TRAFFIC    │  │   TRAFFIC    │  │   SEGMENTATION│      ││
│  │  │              │  │              │  │              │       ││
│  │  │ • Pod-to-Pod │  │ • External   │  │ • Application│       ││
│  │  │ • Service    │  │   to Service │  │   Tiers      │       ││
│  │  │   Discovery  │  │ • Load       │  │ • Database   │       ││
│  │  │ • Namespace  │  │   Balancers  │  │   Access     │       ││
│  │  │   Isolation  │  │ • Ingress    │  │ • API        │       ││
│  │  │              │  │   Controllers│  │   Security   │       ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘       ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 SECURITY ZONES                              ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       ││
│  │  │   WEB TIER   │  │  APP TIER    │  │  DATA TIER   │       ││
│  │  │              │  │              │  │              │       ││
│  │  │ • Ingress    │  │ • Internal   │  │ • Database   │       ││
│  │  │   from       │  │   Services   │  │   Only       │       ││
│  │  │   Internet   │  │ • Web Tier   │  │ • App Tier   │       ││
│  │  │ • Port 80/443│  │   Access     │  │   Access     │       ││
│  │  │ • App Tier   │  │ • Data Tier  │  │ • Specific   │       ││
│  │  │   Access     │  │   Access     │  │   Ports      │       ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘       ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Network Policies Implementation

### 1. Default Deny All Policies

```yaml
# default-deny-all.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all-egress
  namespace: development
spec:
  podSelector: {}
  policyTypes:
  - Egress
---
# Allow DNS egress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

### 2. Namespace Isolation

```yaml
# namespace-isolation.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}  # Allow within namespace
  egress:
  - to:
    - podSelector: {}  # Allow within namespace
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
---
# Allow specific cross-namespace communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 9100
```

### 3. Application Tier Segmentation

```yaml
# application-tier-segmentation.yaml
# Web Tier Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-tier-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: app
    ports:
    - protocol: TCP
      port: 8080
---
# Application Tier Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-tier-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: web
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: database
    ports:
    - protocol: TCP
      port: 5432
---
# Database Tier Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-tier-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: app
    ports:
    - protocol: TCP
      port: 5432
  egress: []  # No egress allowed from database
```

### 4. Label-Based Microsegmentation

```yaml
# label-based-microsegmentation.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-backend-communication
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
          version: v1
    ports:
    - protocol: TCP
      port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-database-communication
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
          type: postgresql
    ports:
    - protocol: TCP
      port: 5432
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cache-access
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
          role: cache
    ports:
    - protocol: TCP
      port: 6379
```

### 5. Advanced Network Policies

```yaml
# advanced-network-policies.yaml
# 1. IP Block restrictions
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-office-ips
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: internal-api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 192.168.1.0/24
    - ipBlock:
        cidr: 10.0.0.0/8
    ports:
    - protocol: TCP
      port: 8443
---
# 2. Port range policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-port-range
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: game-server
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: UDP
      port: 7777
      endPort: 7780
---
# 3. Combined namespace and pod selector
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: specific-service-access
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: critical-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
      podSelector:
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 9090
```

## End-to-End Security Implementation

### 1. Complete RBAC + Network Policy Setup

```yaml
# complete-security-setup.yaml
---
# Namespace setup with labels
apiVersion: v1
kind: Namespace
metadata:
  name: web-app
  labels:
    name: web-app
    environment: production
    security-tier: frontend
---
apiVersion: v1
kind: Namespace
metadata:
  name: api-backend
  labels:
    name: api-backend
    environment: production
    security-tier: backend
---
apiVersion: v1
kind: Namespace
metadata:
  name: database
  labels:
    name: database
    environment: production
    security-tier: data
---
# RBAC for development team
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: web-app
  name: web-developer
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: web-app
  name: web-developers-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: web-developer
subjects:
- kind: Group
  name: web-developers
  apiGroup: rbac.authorization.k8s.io
---
# Network Policies for microsegmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: web-app
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-to-api
  namespace: web-app
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: api-backend
      podSelector:
        matchLabels:
          app: api-service
    ports:
    - protocol: TCP
      port: 8080
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-to-db
  namespace: api-backend
spec:
  podSelector:
    matchLabels:
      app: api-service
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
      podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432
```

### 2. Automated Security Compliance

```yaml
# security-compliance-checker.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: rbac-audit
  namespace: security
spec:
  schedule: "0 6 * * *"  # Daily at 6 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: rbac-auditor
            image: bitnami/kubectl:latest
            command:
            - /bin/bash
            - -c
            - |
              # Check for overly permissive roles
              kubectl get clusterroles,roles --all-namespaces -o json | \
              jq -r '.items[] | select(.rules[]?.verbs[]? | contains("*")) | .metadata.name'
              
              # Check for wildcard resources
              kubectl get clusterroles,roles --all-namespaces -o json | \
              jq -r '.items[] | select(.rules[]?.resources[]? | contains("*")) | .metadata.name'
              
              # Check network policies coverage
              kubectl get namespaces -o json | \
              jq -r '.items[].metadata.name' | \
              while read ns; do
                policies=$(kubectl get networkpolicies -n $ns -o name | wc -l)
                echo "Namespace $ns has $policies network policies"
              done
          restartPolicy: OnFailure
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-policy-validator
  namespace: security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: network-policy-validator
  template:
    metadata:
      labels:
        app: network-policy-validator
    spec:
      containers:
      - name: validator
        image: nginx:1.25
        command:
        - /bin/bash
        - -c
        - |
          # Simple network connectivity tests
          while true; do
            # Test DNS resolution
            nslookup kubernetes.default.svc.cluster.local
            
            # Test cross-namespace connectivity (should fail if policies work)
            curl -s -m 5 http://web-app-service.web-app.svc.cluster.local:80 || echo "Web app unreachable (expected)"
            
            sleep 60
          done
```

### 3. Security Monitoring and Alerting

```yaml
# security-monitoring.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rbac-rules
  namespace: monitoring
data:
  rbac-alerts.yml: |
    groups:
    - name: rbac.alerts
      rules:
      - alert: OverlyPermissiveRole
        expr: count(kube_role_info{role_name=~".*"}) by (role_name) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Role with wildcard permissions detected"
          description: "Role {{ $labels.role_name }} has wildcard permissions"
      
      - alert: MissingNetworkPolicy
        expr: count(kube_namespace_status_phase{phase="Active"}) - count(kube_networkpolicy_info) > 0
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "Namespaces missing network policies"
          description: "{{ $value }} namespaces don't have network policies"
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 9100
```

## Best Practices & Auditing

### 1. RBAC Best Practices Checklist

```yaml
# rbac-best-practices.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-best-practices
  namespace: kube-system
data:
  checklist.md: |
    # RBAC Security Checklist
    
    ## Principle of Least Privilege
    ✅ Use specific verbs instead of wildcards
    ✅ Limit resources to specific names
    ✅ Use namespaced roles when possible
    ✅ Avoid cluster-admin binding
    
    ## Regular Audits
    ✅ Review ClusterRoleBindings monthly
    ✅ Audit ServiceAccount permissions
    ✅ Check for privilege escalation
    ✅ Monitor anomalous access patterns
    
    ## Secure Patterns
    ✅ Use groups instead of individual users
    ✅ Implement time-bound tokens
    ✅ Regular rotation of credentials
    ✅ Automated compliance checking
    
    ## Monitoring
    ✅ Enable audit logging
    ✅ Monitor failed auth attempts
    ✅ Alert on privilege changes
    ✅ Track sensitive resource access
```

### 2. Network Policy Best Practices

```yaml
# network-policy-best-practices.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: network-policy-best-practices
  namespace: kube-system
data:
  checklist.md: |
    # Network Policy Security Checklist
    
    ## Default Policies
    ✅ Implement default-deny-all policies
    ✅ Allow DNS resolution explicitly
    ✅ Restrict cross-namespace traffic
    ✅ Use namespace labels for segmentation
    
    ## Application Security
    ✅ Segment by application tiers
    ✅ Use pod labels for microsegmentation
    ✅ Restrict egress to necessary destinations
    ✅ Implement ingress controls
    
    ## Monitoring & Testing
    ✅ Test network policies regularly
    ✅ Monitor policy violations
    ✅ Use canary deployments for policy changes
    ✅ Document allowed traffic flows
    
    ## Advanced Security
    ✅ Use IP blocks for external services
    ✅ Implement port ranges when needed
    ✅ Combine namespace and pod selectors
    ✅ Regular policy reviews and updates
```

### 3. Automated Security Scans

```bash
#!/bin/bash
# security-audit-script.sh

echo "=== Kubernetes RBAC & Network Policy Audit ==="

# RBAC Audit
echo "1. Auditing RBAC configurations..."
echo "=== ClusterRoles with wildcard verbs ==="
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? | contains("*")) | .metadata.name'

echo "=== Roles with wildcard verbs ==="
kubectl get roles --all-namespaces -o json | jq -r '.items[] | select(.rules[]?.verbs[]? | contains("*")) | "\(.metadata.namespace)/\(.metadata.name)"'

echo "=== ServiceAccounts with cluster-admin ==="
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'

# Network Policy Audit
echo "2. Auditing Network Policies..."
echo "=== Namespaces without network policies ==="
kubectl get namespaces -o json | jq -r '.items[].metadata.name' | while read ns; do
    count=$(kubectl get networkpolicies -n $ns -o name 2>/dev/null | wc -l)
    if [ "$count" -eq "0" ]; then
        echo "WARNING: Namespace $ns has no network policies"
    fi
done

echo "=== Overly permissive network policies ==="
kubectl get networkpolicies --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.ingress[].from[]? | .ipBlock?.cidr == "0.0.0.0/0") | "\(.metadata.namespace)/\(.metadata.name)"'

# Security Context Audit
echo "3. Auditing Pod Security..."
echo "=== Pods running as root ==="
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].securityContext?.runAsNonRoot != true) | "\(.metadata.namespace)/\(.metadata.name)"'

echo "=== Audit Complete ==="
```

### 4. Continuous Compliance with OPA/Gatekeeper

```yaml
# gatekeeper-constraints.yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequirednetworkpolicies
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredNetworkPolicies
      validation:
        openAPIV3Schema:
          type: object
          properties:
            policies:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequirednetworkpolicies
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Namespace"
          input.review.object.metadata.name != "kube-system"
          count(network_policies) == 0
          msg := sprintf("Namespace %v must have network policies", [input.review.object.metadata.name])
        }
        
        network_policies[p] {
          p := data.inventory.cluster.v1.NetworkPolicy[name]
          p.metadata.namespace == input.review.object.metadata.name
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredNetworkPolicies
metadata:
  name: require-network-policies
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Namespace"]
  parameters:
    policies: ["default-deny-all"]
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srbacwildcards
spec:
  crd:
    spec:
      names:
        kind: K8sRBACWildcards
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srbacwildcards
        
        violation[{"msg": msg}] {
          input.review.object.kind == "ClusterRole"
          wildcard_verbs(input.review.object.rules)
          msg := sprintf("ClusterRole %v uses wildcard verbs", [input.review.object.metadata.name])
        }
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Role"
          wildcard_verbs(input.review.object.rules)
          msg := sprintf("Role %v in namespace %v uses wildcard verbs", [input.review.object.metadata.name, input.review.object.metadata.namespace])
        }
        
        wildcard_verbs(rules) {
          rules[_].verbs[_] == "*"
        }
```

This comprehensive guide provides a solid foundation for implementing RBAC and Network Policies with security best practices. Remember to regularly audit and update your configurations to maintain a strong security posture.