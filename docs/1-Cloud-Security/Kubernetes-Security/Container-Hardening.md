# Container Hardening: Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Container Security Architecture](#container-security-architecture)
3. [Minimal Images](#minimal-images)
4. [Non-Root Containers](#non-root-containers)
5. [Read-Only Filesystems](#read-only-filesystems)
6. [Resource Limits](#resource-limits)
7. [Image Scanning](#image-scanning)
8. [Secrets Management](#secrets-management)
9. [End-to-End Implementation](#end-to-end-implementation)
10. [Best Practices](#best-practices)

## Introduction

Container hardening is critical for securing Kubernetes workloads. This guide covers comprehensive practices for building secure containers and managing secrets properly.

## Container Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CONTAINER SECURITY LAYERS                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                         CONTAINER                           ││
│  │  ┌───────────────────────────────────────────────────────┐  ││
│  │  │                    POD SECURITY                       │  ││
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  ││
│  │  │  │   CONTAINER  │  │   SECURITY   │  │   RUNTIME    │ │  ││
│  │  │  │              │  │   CONTEXT    │  │   SECURITY   │ │  ││
│  │  │  │ • Minimal    │  │              │  │              │ │  ││
│  │  │  │   Base Image │  │ • Non-root   │  │ • Seccomp    │ │  ││
│  │  │  │ • Updated    │  │ • Read-only  │  │   Profiles   │ │  ││
│  │  │  │   Packages   │  │   FS         │  │ • AppArmor   │ │  ││
│  │  │  │ • Scanned    │  │ • Capabilities│  │ • SELinux    │ │  ││
│  │  │  │   for Vulns  │  │   Dropped    │  │   Policies   │ │  ││
│  │  │  │ • Signed     │  │ • Privilege  │  │ • gVisor     │ │  ││
│  │  │  │   Images     │  │   Escalation │  │ • Kata       │ │  ││
│  │  │  │              │  │   Prevention │  │   Containers │ │  ││
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘ │  ││
│  │  └───────────────────────────────────────────────────────┘  ││
│  │                                                             ││
│  │  ┌───────────────────────────────────────────────────────┐  ││
│  │  │                 RESOURCE MANAGEMENT                   │  ││
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  ││
│  │  │  │   CPU/MEM    │  │   NETWORK    │  │   STORAGE    │ │  ││
│  │  │  │   LIMITS     │  │   POLICIES   │  │   SECURITY   │ │  ││
│  │  │  │              │  │              │  │              │ │  ││
│  │  │  │ • CPU        │  │ • Egress     │  │ • Read-only  │ │  ││
│  │  │  │   Requests   │  │   Filtering  │  │   Root FS    │ │  ││
│  │  │  │ • Memory     │  │ • Ingress    │  │ • Volume     │ │  ││
│  │  │  │   Limits     │  │   Controls   │  │   Mounts     │ │  ││
│  │  │  │ • HugePages  │  │ • TLS        │  │ • Encryption │ │  ││
│  │  │  │   Control    │  │   Encryption │  │   at Rest    │ │  ││
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘ │  ││
│  │  └───────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     SECRETS MANAGEMENT                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   VAULT      │  │  SEALED      │  │   NATIVE     │          │
│  │              │  │  SECRETS     │  │   SECRETS    │          │
│  │ • Dynamic    │  │ • Encrypted  │  │ • Base64     │          │
│  │   Secrets    │  │   in Git     │  │   Encoded    │          │
│  │ • Encryption │  │ • Public Key │  │ • etcd       │          │
│  │ • Access     │  │   Crypto     │  │   Storage    │          │
│  │   Control    │  │ • Cluster    │  │ • RBAC       │          │
│  │ • Audit      │  │   Specific   │  │   Protected  │          │
│  │   Logging    │  │   Keys       │  │ • Limited    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Minimal Images

### 1. Multi-Stage Dockerfiles

```dockerfile
# Multi-stage build for Go application
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final minimal image
FROM alpine:3.18

RUN apk --no-cache add ca-certificates && \
    addgroup -S app && adduser -S app -G app

USER app
WORKDIR /home/app

COPY --from=builder /app/main .
COPY --chown=app:app templates/ ./templates/

EXPOSE 8080
CMD ["./main"]
```

### 2. Distroless Images

```dockerfile
# Using Google Distroless base image
FROM golang:1.21 AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /app/server .
USER nonroot:nonroot

EXPOSE 8080
CMD ["/server"]
```

### 3. Scratch Images

```dockerfile
# Ultra-minimal scratch image
FROM golang:1.21 AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM scratch
COPY --from=builder /app/app /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
CMD ["/app"]
```

## Non-Root Containers

### 1. User Management in Dockerfiles

```dockerfile
FROM node:18-alpine

# Create app user and group
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# Create app directory with proper permissions
WORKDIR /app
COPY package*.json ./
RUN chown -R appuser:appgroup /app

# Install dependencies as root
RUN npm ci --only=production

# Switch to non-root user
USER appuser

COPY --chown=appuser:appgroup . .

EXPOSE 3000
CMD ["node", "server.js"]
```

### 2. Kubernetes Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:1.0.0
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        ports:
        - containerPort: 8080
```

### 3. Pod Security Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-apps
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: policy/v1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
```

## Read-Only Filesystems

### 1. Dockerfile Configuration

```dockerfile
FROM nginx:1.25-alpine

# Remove default nginx config and create read-only structure
RUN rm -rf /etc/nginx/conf.d/default.conf && \
    mkdir -p /var/cache/nginx /var/run && \
    chown -R nginx:nginx /var/cache/nginx /var/run

# Copy custom configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/

# Switch to nginx user
USER nginx

# Create necessary directories with correct permissions
RUN mkdir -p /tmp/nginx

EXPOSE 8080
```

### 2. Kubernetes Implementation

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: read-only-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: read-only-app
  template:
    metadata:
      labels:
        app: read-only-app
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: tmp
          mountPath: /tmp
          readOnly: false
        - name: logs
          mountPath: /var/log
          readOnly: false
        - name: config
          mountPath: /etc/config
          readOnly: true
        env:
        - name: TEMP_DIR
          value: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
      - name: config
        configMap:
          name: app-config
```

### 3. Advanced Read-Only Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: advanced-readonly
spec:
  replicas: 2
  selector:
    matchLabels:
      app: advanced-readonly
  template:
    metadata:
      labels:
        app: advanced-readonly
    spec:
      containers:
      - name: app
        image: nginx:1.25-alpine
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 101  # nginx user in official image
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
          readOnly: true
        - name: nginx-conf-d
          mountPath: /etc/nginx/conf.d
          readOnly: true
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: tmp
        emptyDir:
          medium: Memory
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
      - name: nginx-config
        configMap:
          name: nginx-config
      - name: nginx-conf-d
        configMap:
          name: nginx-conf-d
```

## Resource Limits

### 1. CPU and Memory Limits

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: resource-limited-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: resource-limited-app
  template:
    metadata:
      labels:
        app: resource-limited-app
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
            ephemeral-storage: "1Gi"
          limits:
            memory: "128Mi"
            cpu: "500m"
            ephemeral-storage: "2Gi"
        env:
        - name: GOMEMLIMIT
          value: "100MiB"
        - name: GOMAXPROCS
          value: "1"
```

### 2. Quality of Service Classes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guaranteed-qos
spec:
  replicas: 2
  selector:
    matchLabels:
      app: guaranteed-qos
  template:
    metadata:
      labels:
        app: guaranteed-qos
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            memory: "128Mi"
            cpu: "500m"
          limits:
            memory: "128Mi"  # Same as requests for Guaranteed QoS
            cpu: "500m"      # Same as requests for Guaranteed QoS
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: burstable-qos
spec:
  replicas: 2
  selector:
    matchLabels:
      app: burstable-qos
  template:
    metadata:
      labels:
        app: burstable-qos
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"  # Higher than requests for Burstable QoS
            cpu: "500m"      # Higher than requests for Burstable QoS
```

### 3. Limit Ranges

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: namespace-limits
  namespace: production
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "2"
      memory: "2Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
  - type: Pod
    max:
      cpu: "4"
      memory: "4Gi"
```

## Image Scanning

### 1. Trivy Integration

```yaml
# trivy-scan-job.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: trivy-scan
  namespace: security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trivy
            image: aquasec/trivy:0.45
            command:
            - trivy
            - image
            - --format
            - table
            - --exit-code
            - "1"
            - --severity
            - HIGH,CRITICAL
            - --ignore-unfixed
            - my-registry.com/myapp:latest
            resources:
              requests:
                memory: "1Gi"
                cpu: "500m"
              limits:
                memory: "2Gi"
                cpu: "1"
          restartPolicy: Never
```

### 2. Admission Controller with Image Scanning

```yaml
# image-scanner-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-scanner
webhooks:
- name: image-scanner.secure-company.com
  clientConfig:
    service:
      namespace: security
      name: image-scanner-webhook
      path: /validate
    caBundle: ${CA_BUNDLE}
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Fail
  sideEffects: None
  admissionReviewVersions: ["v1", "v1beta1"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: image-scanner-webhook
  namespace: security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: image-scanner-webhook
  template:
    metadata:
      labels:
        app: image-scanner-webhook
    spec:
      containers:
      - name: webhook
        image: my-registry.com/image-scanner:1.0.0
        ports:
        - containerPort: 8443
        env:
        - name: TRIVY_SERVER
          value: "http://trivy-server.security.svc.cluster.local:8080"
        - name: ALLOWED_REGISTRIES
          value: "my-registry.com,docker.io/library"
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
```

### 3. Image Policy Configuration

```yaml
# image-policy-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: image-policy-config
  namespace: security
data:
  policy.yaml: |
    apiVersion: image-policy.k8s.io/v1
    kind: ImagePolicy
    rules:
    - name: allowed-registries
      pattern: "^my-registry\\.com/.*"
      action: allow
    - name: blocked-tags
      pattern: ".*:(latest|edge|unstable)$"
      action: deny
      message: "Using mutable tags is not allowed"
    - name: require-digest
      pattern: "^.*@sha256:[a-f0-9]{64}$"
      action: allow
      message: "Images must be referenced by digest"
    - name: block-high-vulnerabilities
      maxSeverity: "MEDIUM"
      maxCVSS: 6.9
```

## Secrets Management

### 1. Kubernetes Native Secrets (Basic)

```yaml
# native-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-database-secret
  namespace: production
type: Opaque
data:
  # Base64 encoded values
  username: YWRtaW4=
  password: c2VjdXJlLXBhc3N3b3JkLTEyMw==
  database-url: cG9zdGdyZXNxbDovL3VzZXI6cGFzc0BkYi5leGFtcGxlLmNvbTo1NDMyL2FwcA==
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-secrets
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app-with-secrets
  template:
    metadata:
      labels:
        app: app-with-secrets
    spec:
      containers:
      - name: app
        image: myapp:1.0.0
        env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: app-database-secret
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-database-secret
              key: password
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: app-database-secret
              key: database-url
        volumeMounts:
        - name: secret-volume
          mountPath: /etc/secrets
          readOnly: true
      volumes:
      - name: secret-volume
        secret:
          secretName: app-database-secret
          defaultMode: 0400
```

### 2. Sealed Secrets

```yaml
# sealed-secret-installation.yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-database-secret
  namespace: production
spec:
  encryptedData:
    username: AgBy1a9rF8d8...
    password: BgCr8s9aF7e2...
    database-url: CxYt3k8aF5e1...
  template:
    metadata:
      name: app-database-secret
      namespace: production
    type: Opaque
---
# Command to create sealed secret
# kubeseal --format yaml --cert my-cert.pem < secret.yaml > sealed-secret.yaml
```

### 3. HashiCorp Vault Integration

```yaml
# vault-agent-sidecar.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-vault
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app-with-vault
  template:
    metadata:
      labels:
        app: app-with-vault
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "app-role"
        vault.hashicorp.com/agent-inject-secret-database.conf: "database/creds/app-role"
        vault.hashicorp.com/agent-inject-template-database.conf: |
          {{- with secret "database/creds/app-role" -}}
          export DB_USERNAME="{{ .Data.username }}"
          export DB_PASSWORD="{{ .Data.password }}"
          {{- end }}
    spec:
      serviceAccountName: vault-auth
      containers:
      - name: app
        image: myapp:1.0.0
        env:
        - name: DB_CREDENTIALS_FILE
          value: /vault/secrets/database.conf
        command: ["/bin/sh"]
        args: ["-c", "source /vault/secrets/database.conf && ./app"]
        volumeMounts:
        - name: vault-secrets
          mountPath: /vault/secrets
          readOnly: true
      - name: vault-agent
        image: vault:1.15.0
        args:
        - agent
        - -config=/vault/config/config.hcl
        volumeMounts:
        - name: vault-config
          mountPath: /vault/config
        - name: vault-secrets
          mountPath: /vault/secrets
      volumes:
      - name: vault-config
        configMap:
          name: vault-agent-config
      - name: vault-secrets
        emptyDir: {}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-agent-config
  namespace: production
data:
  config.hcl: |
    exit_after_auth = false
    pid_file = "/home/vault/pidfile"
    
    auto_auth {
      method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = {
          role = "app-role"
        }
      }
      
      sink "file" {
        config = {
          path = "/home/vault/.vault-token"
        }
      }
    }
    
    template {
      destination = "/vault/secrets/database.conf"
      contents = "{{- with secret \"database/creds/app-role\" -}}export DB_USERNAME=\"{{ .Data.username }}\" export DB_PASSWORD=\"{{ .Data.password }}\"{{- end }}"
    }
```

### 4. External Secrets Operator

```yaml
# external-secrets-setup.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        tokenSecretRef:
          name: "vault-token"
          key: "token"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-secrets
  namespace: production
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: app-database-secret
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: database/creds/app-role
      property: username
  - secretKey: password
    remoteRef:
      key: database/creds/app-role
      property: password
```

## End-to-End Implementation

### 1. Complete Secure Deployment

```yaml
# complete-secure-deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-app-sa
  namespace: secure-production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: secure-production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "secure-app-role"
    spec:
      serviceAccountName: secure-app-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: my-registry.com/secure-app@sha256:a1b2c3d4e5f6...
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
            ephemeral-storage: "1Gi"
          limits:
            memory: "256Mi"
            cpu: "500m"
            ephemeral-storage: "2Gi"
        env:
        - name: DB_HOST
          value: "postgresql.secure-production.svc.cluster.local"
        - name: DB_CREDENTIALS_FILE
          value: "/vault/secrets/database.conf"
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: vault-secrets
          mountPath: /vault/secrets
          readOnly: true
        - name: config
          mountPath: /etc/config
          readOnly: true
      volumes:
      - name: tmp
        emptyDir:
          medium: Memory
          sizeLimit: 100Mi
      - name: vault-secrets
        emptyDir:
          medium: Memory
      - name: config
        configMap:
          name: app-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: secure-production
data:
  app.conf: |
    log_level = "info"
    timeout = "30s"
    max_connections = 100
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-app-policy
  namespace: secure-production
spec:
  podSelector:
    matchLabels:
      app: secure-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: secure-production
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

### 2. Security Automation Pipeline

```yaml
# security-pipeline.yaml
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: secure-image-pipeline
spec:
  workspaces:
  - name: source
  - name: dockerconfig
  params:
  - name: imageUrl
    type: string
  - name: imageTag
    type: string
  tasks:
  - name: source-to-image
    taskRef:
      name: buildah
    workspaces:
    - name: source
      workspace: source
    - name: dockerconfig
      workspace: dockerconfig
    params:
    - name: IMAGE
      value: "$(params.imageUrl):$(params.imageTag)"
  
  - name: vulnerability-scan
    taskRef:
      name: trivy-scan
    runAfter:
    - source-to-image
    params:
    - name: IMAGE
      value: "$(params.imageUrl):$(params.imageTag)"
  
  - name: sign-image
    taskRef:
      name: cosign-sign
    runAfter:
    - vulnerability-scan
    params:
    - name: IMAGE
      value: "$(params.imageUrl):$(params.imageTag)"
  
  - name: deploy-to-test
    taskRef:
      name: deploy
    runAfter:
    - sign-image
    params:
    - name: ENVIRONMENT
      value: "test"
    - name: IMAGE
      value: "$(params.imageUrl):$(params.imageTag)"
```

## Best Practices

### 1. Security Context Checklist

```yaml
# security-context-checklist.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-checklist
  namespace: kube-system
data:
  container-checklist: |
    ✅ Use minimal base images
    ✅ Run as non-root user
    ✅ Use read-only root filesystem
    ✅ Drop all capabilities
    ✅ Disable privilege escalation
    ✅ Set resource limits
    ✅ Use image digests, not tags
    ✅ Scan images for vulnerabilities
    ✅ Sign and verify images
    ✅ Use security contexts
    ✅ Implement network policies
    ✅ Use Pod Security Standards
  
  runtime-checklist: |
    ✅ Enable seccomp profiles
    ✅ Use AppArmor/SELinux
    ✅ Configure cgroups properly
    ✅ Monitor runtime behavior
    ✅ Use runtime sandboxes (gVisor/Kata)
    ✅ Implement OPA/Gatekeeper policies
    ✅ Enable audit logging
    ✅ Regular security updates
  
  secrets-checklist: |
    ✅ Never store secrets in plaintext
    ✅ Use external secrets management
    ✅ Rotate secrets regularly
    ✅ Limit secret access with RBAC
    ✅ Encrypt secrets at rest
    ✅ Audit secret access
    ✅ Use short-lived credentials
    ✅ Avoid secret leakage in logs
```

### 2. Continuous Security Monitoring

```yaml
# security-monitoring.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-monitor
  namespace: security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: security-monitor
  template:
    metadata:
      labels:
        app: security-monitor
    spec:
      serviceAccountName: security-monitor-sa
      containers:
      - name: monitor
        image: falcosecurity/falco:0.36.0
        securityContext:
          privileged: true
        args:
        - /usr/bin/falco
        - -c
        - /etc/falco/falco.yaml
        - -K
        - /var/run/secrets/kubernetes.io/serviceaccount/token
        - -k
        - https://$(KUBERNETES_SERVICE_HOST)
        - -pk
        volumeMounts:
        - name: falco-config
          mountPath: /etc/falco
        - name: falco-rules
          mountPath: /etc/falco/rules.d
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: os-release
          mountPath: /host/etc/os-release
          readOnly: true
      volumes:
      - name: falco-config
        configMap:
          name: falco-config
      - name: falco-rules
        configMap:
          name: falco-rules
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: os-release
        hostPath:
          path: /etc/os-release
```

### 3. Regular Security Audits

```bash
#!/bin/bash
# security-audit.sh

echo "=== Kubernetes Security Audit ==="

# Check cluster security
echo "1. Checking cluster security..."
kubectl get nodes
kubectl get pods -n kube-system

# Check RBAC configurations
echo "2. Checking RBAC..."
kubectl get clusterroles,clusterrolebindings
kubectl get roles,rolebindings --all-namespaces

# Check network policies
echo "3. Checking network policies..."
kubectl get networkpolicies --all-namespaces

# Check security contexts
echo "4. Checking security contexts..."
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + "/" + .metadata.name'

# Check image sources
echo "5. Checking container images..."
kubectl get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}" | \
  tr -s '[[:space:]]' '\n' | sort | uniq

# Check resource limits
echo "6. Checking resource limits..."
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].resources.limits==null) | .metadata.namespace + "/" + .metadata.name'

echo "=== Audit Complete ==="
```

This comprehensive container hardening guide provides a solid foundation for securing your Kubernetes workloads. Remember to implement these practices progressively and continuously monitor and update your security posture.