# Kubernetes Architecture: Security-Focused Tutorial

## Table of Contents
1. [Introduction](#introduction)
2. [Kubernetes Architecture Overview](#kubernetes-architecture-overview)
3. [Security-Focused Architecture Diagram](#security-focused-architecture-diagram)
4. [Core Components Deep Dive](#core-components-deep-dive)
5. [Kubernetes Hardening](#kubernetes-hardening)
6. [End-to-End Security Implementation](#end-to-end-security-implementation)
7. [Best Practices](#best-practices)

## Introduction

Kubernetes security follows a defense-in-depth approach, requiring security measures at multiple layers. This tutorial provides a comprehensive view of Kubernetes architecture from a security perspective and guides you through hardening your cluster.

## Kubernetes Architecture Overview

### Control Plane Components
- **API Server**: Gateway to Kubernetes, handles all REST operations
- **etcd**: Distributed key-value store holding cluster state
- **Controller Manager**: Regulates cluster state
- **Scheduler**: Assigns pods to nodes
- **Cloud Controller Manager**: Manages cloud provider-specific logic

### Node Components
- **Kubelet**: Primary node agent
- **Container Runtime**: Docker, containerd, or CRI-O
- **Kube Proxy**: Network proxy and load balancer
- **Network Plugins**: CNI implementations (Calico, Flannel, etc.)

## Security-Focused Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        KUBERNETES CLUSTER                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   LOAD BALANCER │    │   FIREWALL      │                     │
│  │                 │    │                 │                     │
│  │  • TLS Termination │ │  • Ingress Rules │                    │
│  │  • Rate Limiting  │ │  • Network Policies│                   │
│  └─────────────────┘    └─────────────────┘                     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                         CONTROL PLANE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐    │
│  │   API SERVER │  │  CONTROLLER  │  │      SCHEDULER      │    │
│  │              │  │   MANAGER    │  │                     │    │
│  │ • RBAC       │  │ • RBAC       │  │ • RBAC              │    │
│  │ • AuthN/AuthZ│  │ • Secure Port│  │ • Secure Port       │    │
│  │ • Audit Logs │  │ • TLS        │  │ • TLS               │    │
│  │ • Admission  │  └──────────────┘  └─────────────────────┘    │
│  │   Controls   │                                                │
│  │ • TLS        │            ┌──────────────┐                   │
│  └──────────────┘            │     ETCD     │                   │
│         │                    │              │                   │
│         └───────────────────►│ • Encryption │                   │
│                              │ • Auth       │                   │
│                              │ • Backup     │                   │
│                              │ • TLS        │                   │
│                              └──────────────┘                   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                           WORKER NODES                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                        WORKER NODE 1                        ││
│  │  ┌──────────────┐  ┌─────────────────┐  ┌─────────────────┐ ││
│  │  │   KUBELET    │  │  KUBE PROXY     │  │ NETWORK PLUGIN  │ ││
│  │  │              │  │                 │  │                 │ ││
│  │  │ • TLS        │  │ • Secure Config │  │ • Network       │ ││
│  │  │ • Auth       │  │ • RBAC          │  │   Policies      │ ││
│  │  │ • Read-only  │  │ • Secure Port   │  │ • Encryption    │ ││
│  │  │   Root FS    │  └─────────────────┘  └─────────────────┘ ││
│  │  └──────────────┘                                           ││
│  │                                                             ││
│  │  ┌───────────────────────────────────────────────────────┐  ││
│  │  │                   POD SECURITY                        │  ││
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  ││
│  │  │  │     POD      │  │   CONTAINER  │  │   CONTAINER  │ │  ││
│  │  │  │              │  │              │  │              │ │  ││
│  │  │  │ • Security   │  │ • Non-root   │  │ • Non-root   │ │  ││
│  │  │  │   Context    │  │ • Read-only  │  │ • Read-only  │ │  ││
│  │  │  │ • Network    │  │   FS         │  │   FS         │ │  ││
│  │  │  │   Policies   │  │ • AppArmor   │  │ • AppArmor   │ │  ││
│  │  │  │ • Pod        │  │ • Seccomp    │  │ • Seccomp    │ │  ││
│  │  │  │   Security   │  │ • Capabilities│ │ • Capabilities│ │  ││
│  │  │  │   Standards  │  │   Dropped    │  │   Dropped    │ │  ││
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘ │  ││
│  │  └───────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components Deep Dive

### 1. API Server Security

The API Server is the central management point and the most critical component to secure.

```yaml
# api-server-security-config.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    - --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
    - --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
    - --requestheader-allowed-names=front-proxy-client
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --requestheader-extra-headers-prefix=X-Remote-Extra-
    - --requestheader-group-headers=X-Remote-Group
    - --requestheader-username-headers=X-Remote-User
    - --secure-port=6443
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    - --audit-log-path=/var/log/kubernetes/audit/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    image: k8s.gcr.io/kube-apiserver:v1.28.2
    name: kube-apiserver
```

### 2. etcd Security

etcd contains all cluster data and must be rigorously secured.

```yaml
# etcd-security-config.yaml
apiVersion: v1
kind: Pod
metadata:
  name: etcd
  namespace: kube-system
spec:
  containers:
  - command:
    - etcd
    - --advertise-client-urls=https://127.0.0.1:2379
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --client-cert-auth=true
    - --data-dir=/var/lib/etcd
    - --initial-advertise-peer-urls=https://127.0.0.1:2380
    - --initial-cluster=controlplane=https://127.0.0.1:2380
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --listen-client-urls=https://127.0.0.1:2379
    - --listen-metrics-urls=http://127.0.0.1:2381
    - --listen-peer-urls=https://127.0.0.1:2380
    - --name=controlplane
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-client-cert-auth=true
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --snapshot-count=10000
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --auto-compaction-retention=1
    - --experimental-initial-corrupt-check=true
    - --experimental-corrupt-check-time=10m
    image: k8s.gcr.io/etcd:3.5.7-0
    name: etcd
```

### 3. Kubelet Security

Kubelet is the primary node agent and a common attack vector.

```yaml
# kubelet-config-security.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
cgroupDriver: systemd
clusterDNS:
- 10.96.0.10
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 0s
evictionPressureTransitionPeriod: 0s
fileCheckFrequency: 0s
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 0s
imageMinimumGCAge: 0s
kind: KubeletConfiguration
logging: {}
nodeStatusReportFrequency: 0s
nodeStatusUpdateFrequency: 0s
rotateCertificates: true
runtimeRequestTimeout: 0s
shutdownGracePeriod: 0s
shutdownGracePeriodCriticalPods: 0s
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 0s
syncFrequency: 0s
volumeStatsAggPeriod: 0s
protectKernelDefaults: true
makeIPTablesUtilChains: true
eventRecordQPS: 0
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
serverTLSBootstrap: true
readOnlyPort: 0
```

### 4. Network Plugin Security

Network plugins control pod networking and must be properly configured.

```yaml
# calico-network-policy.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  selector: all()
  types:
  - Ingress
  - Egress
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny-all
spec:
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system"}
  types:
  - Ingress
  - Egress
```

## Kubernetes Hardening

### 1. RBAC (Role-Based Access Control)

RBAC is fundamental to Kubernetes security, controlling who can access what.

```yaml
# rbac-secure-config.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-pods-global
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-reader
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
---
# Principle of Least Privilege Example
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: deployment-manager
rules:
- apiGroups: ["apps", "extensions"]
  resources: ["deployments"]
  resourceNames: ["myapp-deployment"]
  verbs: ["get", "update", "patch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

### 2. Admission Controls

Admission controllers intercept requests to the API Server before object persistence.

```yaml
# admission-webhook-example.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: "pod-security-policy.example.com"
webhooks:
- name: "pod-security-policy.example.com"
  clientConfig:
    service:
      namespace: "kube-system"
      name: "pod-security-webhook"
      path: /validate
    caBundle: "Ci0tLS0tQk...<ca-bundle>...tLS0K"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Fail
  sideEffects: None
  admissionReviewVersions: ["v1", "v1beta1"]
```

### 3. etcd Encryption

Enable encryption at rest for etcd data.

```yaml
# etcd-encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-encoded-secret>
    - identity: {}
```

Apply encryption configuration:
```bash
# Create encryption key
head -c 32 /dev/urandom | base64

# Update API server with encryption config
kubectl create secret generic encryption-config \
  --from-file=encryption-config.yaml=/path/to/encryption-config.yaml \
  -n kube-system
```

### 4. Pod Security Standards

Implement Pod Security Standards to enforce security baselines.

```yaml
# pod-security-standards.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: restricted-namespace
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
    - 'persistentVolumeClaim'
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
  readOnlyRootFilesystem: true
```

## End-to-End Security Implementation

### Step 1: Cluster Setup with Security Hardening

```bash
#!/bin/bash
# secure-cluster-setup.sh

# Initialize cluster with security features
kubeadm init \
  --control-plane-endpoint "k8s-cluster.example.com:6443" \
  --upload-certs \
  --pod-network-cidr=192.168.0.0/16 \
  --service-cidr=10.96.0.0/12 \
  --kubernetes-version v1.28.2 \
  --feature-gates=RotateKubeletServerCertificate=true \
  --apiserver-cert-extra-sans=k8s-cluster.example.com

# Configure kubectl
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Install network plugin with security features
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml

# Enable Pod Security Standards
kubectl label --overwrite ns kube-system \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged
```

### Step 2: Implement Network Policies

```yaml
# comprehensive-network-policies.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 10.96.0.0/12
    ports:
    - protocol: TCP
      port: 443
```

### Step 3: Configure Security Contexts

```yaml
# security-context-examples.yaml
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
        runAsGroup: 3000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: nginx:1.21
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /var/log/nginx
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
```

### Step 4: Implement Monitoring and Auditing

```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["kube-system"]
  verbs: ["get", "list", "watch"]
  
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
  
- level: Request
  resources:
  - group: ""
    resources: ["pods"]
  
- level: Metadata
  omitStages:
  - RequestReceived
```

### Step 5: Service Account Security

```yaml
# service-account-security.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: restricted-sa
  namespace: default
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader-restricted
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: restricted-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader-restricted
  apiGroup: rbac.authorization.k8s.io
```

## Best Practices

### 1. Regular Security Assessments

```bash
#!/bin/bash
# security-assessment.sh

# Check for vulnerabilities
kubectl get pods --all-namespaces -o json | kube-score score -

# Run security scans
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Check network policies
kubectl get networkpolicies --all-namespaces

# Verify RBAC configurations
kubectl auth can-i --list --as=system:serviceaccount:default:restricted-sa

# Check for privileged pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace + "/" + .metadata.name'
```

### 2. Continuous Security Monitoring

```yaml
# falco-security-rules.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-rules
  namespace: falco
data:
  local_rules.yaml: |
    - rule: Terminal shell in container
      desc: A shell was used as the entrypoint/exec point into a container
      condition: >
        container and proc.name in (bash, sh, zsh, ksh) and
        not proc.args contains "terraform" and
        not proc.args contains "ansible" and
        not proc.args contains "jenkins"
      output: >
        Shell run in container (user=%user.name container_id=%container.id container_name=%container.name
        shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
      priority: NOTICE
      tags: [container, shell]
```

### 3. Incident Response Plan

```yaml
# incident-response-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: incident-responder
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["get", "list", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "create", "patch", "delete"]
```

## Conclusion

This comprehensive tutorial covered Kubernetes architecture from a security perspective, including detailed configurations for hardening each component. Remember that security is an ongoing process that requires:

1. **Regular updates** of Kubernetes components and dependencies
2. **Continuous monitoring** and auditing
3. **Periodic security assessments**
4. **Adherence to principle of least privilege**
5. **Defense in depth** approach across all layers

Implement these security measures progressively, starting with the most critical components like API Server, etcd, and RBAC configurations, then moving to network policies and pod security standards.