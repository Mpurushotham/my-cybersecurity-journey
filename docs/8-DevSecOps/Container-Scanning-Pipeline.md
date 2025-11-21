# Container Scanning in CI/CD Pipeline: Comprehensive Guide

## 1. Complete Container Security Scanning Pipeline

```mermaid
flowchart TD
    subgraph ContainerSecurityPipeline[Container Security Scanning Pipeline]
        subgraph ImageCreation[Image Creation Phase]
            IC1[Base Image Selection<br/>Distroless/Alpine/Scratch] --> IC2[Multi-stage Build<br/>Minimal Final Image]
            IC2 --> IC3[Dockerfile Security<br/>Non-root, No SUID, Read-only]
            IC3 --> IC4[Build-time Scanning<br/>Dependency Analysis]
            IC4 --> IC5[Image Optimization<br/>Layer Minimization]
        end

        subgraph PreBuildScan[Pre-Build Scanning]
            PBS1[Dependency Scanning<br/>SCA - Software Composition] --> PBS2[License Compliance<br/>Open Source License Check]
            PBS2 --> PBS3[Base Image Vulnerabilities<br/>CVE Database Check]
            PBS3 --> PBS4[Build Context Analysis<br/>Secrets Detection]
            PBS4 --> PBS5{Pre-Build Security Pass?}
            PBS5 -->|Yes| PBS6[Proceed to Build]
            PBS5 -->|No| PBS7[Fail Fast<br/>Early Security Block]
        end

        subgraph BuildTimeScan[Build-time Security]
            BTS1[Container Build<br/>With Security Flags] --> BTS2[Runtime Dependency Scan<br/>Dynamic Analysis]
            BTS2 --> BTS3[Image Layer Analysis<br/>Each Layer Security Check]
            BTS3 --> BTS4[SBOM Generation<br/>Software Bill of Materials]
            BTS4 --> BTS5[Vulnerability Scan<br/>Multi-scanner Approach]
            BTS5 --> BTS6{Critical/High Vulnerabilities?}
            BTS6 -->|No| BTS7[Proceed to Signing]
            BTS6 -->|Yes| BTS8[Security Gate Failed]
        end

        subgraph PostBuildSecurity[Post-Build Security]
            PBS1[Image Signing<br/>Cosign/Notary] --> PBS2[Push to Registry<br/>With Security Metadata]
            PBS2 --> PBS3[Registry Scanning<br/>Continuous Monitoring]
            PBS3 --> PBS4[Policy Evaluation<br/>Admission Control Rules]
            PBS4 --> PBS5[Deployment Readiness Check<br/>Security Compliance]
            PBS5 --> PBS6{Deployment Approved?}
            PBS6 -->|Yes| PBS7[Deploy to Environment]
            PBS6 -->|No| PBS8[Quarantine Image]
        end

        subgraph RuntimeSecurity[Runtime Protection]
            RS1[Admission Controller<br/>Image Policy Webhook] --> RS2[Runtime Scanning<br/>Falco/eBPF Monitoring]
            RS2 --> RS3[Behavioral Analysis<br/>Anomaly Detection]
            RS3 --> RS4[Compliance Monitoring<br/>CIS Benchmarks]
            RS4 --> RS5[Incident Response<br/>Auto-remediation]
        end
    end

    ImageCreation --> PreBuildScan
    PreBuildScan --> BuildTimeScan
    BuildTimeScan --> PostBuildSecurity
    PostBuildSecurity --> RuntimeSecurity
```

## 2. Multi-Stage Container Scanning Workflow

```mermaid
flowchart TD
    subgraph MultiStageScanning[Multi-Stage Container Scanning Workflow]
        subgraph Stage1[Stage 1: Base Image Security]
            S1A[Base Image Selection<br/>CVE Scanning] --> S1B[Minimal Base Image<br/>Distroless/Scratch Preferred]
            S1B --> S1C[Image Digest Pinning<br/>No Latest Tags]
            S1C --> S1D[Base Image Update Policy<br/>Automated Patching]
            S1D --> S1E{Base Image Secure?}
            S1E -->|Yes| S1F[Proceed to Build]
            S1E -->|No| S1G[Reject Base Image]
        end

        subgraph Stage2[Stage 2: Build-time Security]
            S2A[Dockerfile Security Scan<br/>Linter & Best Practices] --> S2B[Dependency Installation Scan<br/>SCA During Build]
            S2B --> S2C[Secrets Detection<br/>Prevent Secret Leakage]
            S2C --> S2D[SBOM Generation<br/>Software Composition]
            S2D --> S2E[Image Layer Security<br/>Individual Layer Analysis]
            S2E --> S2F{Vulnerability Threshold?}
            S2F -->|Below Threshold| S2G[Continue Pipeline]
            S2F -->|Above Threshold| S2H[Fail Build]
        end

        subgraph Stage3[Stage 3: Post-Build Security]
            S3A[Comprehensive Vulnerability Scan<br/>Multiple Scanners] --> S3B[License Compliance Check<br/>Open Source Compliance]
            S3B --> S3C[Image Signing & Attestation<br/>Provenance]
            S3C --> S3D[Security Metadata Attachment<br/>VEX, SBOM]
            S3D --> S3E[Push to Secure Registry<br/>With Policies]
            S3E --> S3F{Registry Scan Pass?}
            S3F -->|Yes| S3G[Image Ready for Deployment]
            S3F -->|No| S3H[Quarantine in Registry]
        end

        subgraph Stage4[Stage 4: Runtime Security]
            S4A[Admission Control<br/>Validate Image Signatures] --> S4B[Runtime Behavior Monitoring<br/>Anomaly Detection]
            S4B --> S4C[Continuous Vulnerability Scan<br/>New CVE Detection]
            S4C --> S4D[Compliance Enforcement<br/>Pod Security Standards]
            S4D --> S4E[Incident Detection & Response<br/>Auto-remediation]
            S4E --> S4F{Security Incident?}
            S4F -->|No| S4G[Continue Monitoring]
            S4F -->|Yes| S4H[Trigger Response]
        end
    end

    Stage1 --> Stage2
    Stage2 --> Stage3
    Stage3 --> Stage4
```

## 3. Container Vulnerability Management Lifecycle

```mermaid
flowchart TD
    subgraph VulnManagement[Container Vulnerability Management Lifecycle]
        subgraph Discovery[Vulnerability Discovery]
            VD1[Image Scanning<br/>Trivy, Grype, Clair] --> VD2[Dependency Scanning<br/>SCA Tools]
            VD2 --> VD3[Runtime Scanning<br/>Falco, eBPF]
            VD3 --> VD4[Configuration Scanning<br/>CIS Benchmarks]
            VD4 --> VD5[Threat Intelligence Feeds<br/>CVE Databases]
        end

        subgraph Assessment[Risk Assessment]
            RA1[CVSS Scoring<br/>Critical/High/Medium/Low] --> RA2[Exploitability Analysis<br/>EPSS, KEV Catalog]
            RA2 --> RA3[Contextual Risk Assessment<br/>Environment, Data]
            RA3 --> RA4[Remediation Priority<br/>Business Impact]
            RA4 --> RA5[Exception Management<br/>Approved Waivers]
        end

        subgraph Remediation[Remediation Strategies]
            REM1[Base Image Update<br/>Automatic Patching] --> REM2[Dependency Patching<br/>Version Updates]
            REM2 --> REM3[Configuration Hardening<br/>Security Best Practices]
            REM3 --> REM4[Code Fixes<br/>Vulnerability Patches]
            REM4 --> REM5[Compensating Controls<br/>Network Policies, WAF]
        end

        subgraph Verification[Remediation Verification]
            RV1[Rescan After Fix<br/>Vulnerability Validation] --> RV2[Regression Testing<br/>No New Vulnerabilities]
            RV2 --> RV3[Security Approval<br/>Security Team Sign-off]
            RV3 --> RV4[Deployment Verification<br/>Production Testing]
            RV4 --> RV5[Continuous Monitoring<br/>Ongoing Scanning]
        end

        subgraph Reporting[Reporting & Compliance]
            REP1[Security Dashboards<br/>Real-time Visibility] --> REP2[Compliance Reporting<br/>SOC2, PCI DSS, HIPAA]
            REP2 --> REP3[Audit Trails<br/>Immutable Logs]
            REP3 --> REP4[Executive Reporting<br/>Risk Metrics]
            REP4 --> REP5[Automated Notifications<br/>Alerting]
        end
    end

    Discovery --> Assessment
    Assessment --> Remediation
    Remediation --> Verification
    Verification --> Reporting
```

## 4. Image Signing and Verification Pipeline

```mermaid
flowchart TD
    subgraph ImageSigningPipeline[Image Signing and Verification Pipeline]
        subgraph SigningProcess[Signing Process]
            SP1[Generate Key Pair<br/>Cosign, Notary] --> SP2[Sign Image Digest<br/>Cryptographic Signature]
            SP2 --> SP3[Attach SBOM<br/>Software Bill of Materials]
            SP3 --> SP4[Attach Provenance<br/>Build Provenance]
            SP4 --> SP5[Store Signature<br/>Registry, OCI]
            SP5 --> SP6[Verify Signature<br/>Integrity Check]
        end

        subgraph VerificationProcess[Verification Process]
            VP1[Admission Controller<br/>Signature Validation] --> VP2[Policy Check<br/>Allowed Registries, Signers]
            VP2 --> VP3[SBOM Verification<br/>Component Validation]
            VP3 --> VP4[Provenance Check<br/>Build Source Verification]
            VP4 --> VP5[Expiry Check<br/>Certificate Validity]
            VP5 --> VP6{All Checks Pass?}
            VP6 -->|Yes| VP7[Allow Deployment]
            VP6 -->|No| VP8[Block Deployment]
        end

        subgraph KeyManagement[Key Management]
            KM1[Key Generation<br/>Secure Key Storage] --> KM2[Key Rotation<br/>Regular Key Updates]
            KM2 --> KM3[Access Control<br/>RBAC for Signing]
            KM3 --> KM4[Audit Logging<br/>All Signing Operations]
            KM4 --> KM5[Disaster Recovery<br/>Key Backup Strategy]
            KM5 --> KM6[Revocation Management<br/>Compromised Keys]
        end

        subgraph PolicyEnforcement[Policy Enforcement]
            PE1[Signature Requirements<br/>Must Be Signed] --> PE2[Registry Policies<br/>Approved Registries Only]
            PE2 --> PE3[Signer Policies<br/>Approved Signers Only]
            PE3 --> PE4[Freshness Policies<br/>Recent Builds Only]
            PE4 --> PE5[Compliance Policies<br/>Regulatory Requirements]
            PE5 --> PE6[Exception Handling<br/>Approved Exceptions]
        end
    end

    SigningProcess --> VerificationProcess
    VerificationProcess --> KeyManagement
    KeyManagement --> PolicyEnforcement
```

## 5. Fail-Build Criteria and Security Gates

```mermaid
flowchart TD
    subgraph FailBuildCriteria[Fail-Build Criteria and Security Gates]
        subgraph CriticalFindings[Critical Findings - Immediate Fail]
            CF1[Critical CVEs<br/>CVSS Score 9.0-10.0] --> CF2[Exploitable Vulnerabilities<br/>Known Exploited Vulnerabilities]
            CF2 --> CF3[Secrets Exposure<br/>API Keys, Passwords]
            CF3 --> CF4[Malware Detection<br/>Malicious Code]
            CF4 --> CF5[Base Image Violations<br/>Unapproved Base Images]
            CF5 --> CF6[License Violations<br/>Prohibited Licenses]
        end

        subgraph HighFindings[High Findings - Conditional Fail]
            HF1[High CVEs<br/>CVSS Score 7.0-8.9] --> HF2[Outdated Dependencies<br/>Major Version Behind]
            HF2 --> HF3[Configuration Issues<br/>Security Misconfigurations]
            HF3 --> HF4[Unpinned Dependencies<br/>Floating Versions]
            HF4 --> HF5{Remediation Available?}
            HF5 -->|Yes| HF6[Fail Build<br/>Require Fix]
            HF5 -->|No| HF7[Security Exception<br/>With Approval]
        end

        subgraph MediumFindings[Medium Findings - Warning]
            MF1[Medium CVEs<br/>CVSS Score 4.0-6.9] --> MF2[Code Quality Issues<br/>Security Smells]
            MF2 --> MF3[Best Practice Violations<br/>Non-critical Issues]
            MF3 --> MF4[Documentation Gaps<br/>Security Documentation]
            MF4 --> MF5{Accumulated Issues?}
            MF5 -->|Below Threshold| MF6[Pass with Warnings]
            MF5 -->|Above Threshold| MF7[Fail Build<br/>Too Many Issues]
        end

        subgraph SecurityGates[Security Gates Configuration]
            SG1[CVSS Threshold<br/>Fail above 7.0] --> SG2[Vulnerability Count<br/>Max Allowed per Severity]
            SG2 --> SG3[License Policy<br/>Allowed License Types]
            SG3 --> SG4[Age Policy<br/>Max Image Age]
            SG4 --> SG5[Provenance Requirements<br/>Signed, Verified]
            SG5 --> SG6[Exception Process<br/>Approval Workflow]
        end
    end

    CriticalFindings --> HighFindings
    HighFindings --> MediumFindings
    MediumFindings --> SecurityGates
```

## Detailed Explanations and Recommendations

### 1. Base Image Scanning Best Practices

**Why Scan Base Images:**
- Base images often contain known vulnerabilities
- Inherited security issues propagate to all derived images
- Early detection prevents downstream security problems

**Implementation Recommendations:**

```yaml
# Example Trivy base image scanning in CI
- name: Scan base image
  run: |
    trivy image --severity CRITICAL,HIGH \
                --exit-code 1 \
                --ignore-unfixed \
    $BASE_IMAGE
    
    # Check for approved base images
    if ! grep -q "$BASE_IMAGE" approved_base_images.txt; then
      echo "ERROR: Base image not in approved list"
      exit 1
    fi
```

**Critical Controls:**
- Maintain approved base image list
- Use minimal base images (Distroless, Alpine)
- Pin base images to specific digests, not tags
- Regular base image updates

### 2. Build Failure Criteria

**Immediate Build Failure Conditions:**

```bash
#!/bin/bash
# Container scanning failure criteria

# Critical CVEs found
if [ "$CRITICAL_CVES" -gt 0 ]; then
  echo "FAIL: Critical vulnerabilities found"
  exit 1
fi

# Secrets detected in image
if [ "$SECRETS_FOUND" -gt 0 ]; then
  echo "FAIL: Secrets detected in container image"
  exit 1
fi

# Unapproved licenses
if [ "$FORBIDDEN_LICENSES" -gt 0 ]; then
  echo "FAIL: Prohibited licenses detected"
  exit 1
fi

# Image not signed
if [ "$SIGNED" != "true" ]; then
  echo "FAIL: Image must be signed before deployment"
  exit 1
fi
```

**Configuration Example for Jenkins:**

```groovy
pipeline {
    stages {
        stage('Container Security Scan') {
            steps {
                script {
                    def scanResult = sh(
                        script: 'trivy image --exit-code 1 --severity CRITICAL,HIGH ${IMAGE}',
                        returnStatus: true
                    )
                    
                    if (scanResult != 0) {
                        error "Container security scan failed with critical vulnerabilities"
                    }
                }
            }
        }
    }
}
```

### 3. Image Signing Enforcement

**Why Image Signing is Critical:**
- Ensures image integrity and authenticity
- Prevents deployment of tampered images
- Provides non-repudiation for deployments

**Implementation with Cosign:**

```bash
#!/bin/bash
# Image signing and verification process

# Sign the image
cosign sign --key cosign.key $IMAGE_TAG

# Generate SBOM
syft $IMAGE_TAG --output spdx-json > sbom.json

# Attach SBOM
cosign attach sbom --sbom sbom.json $IMAGE_TAG

# Verify before deployment
cosign verify --key cosign.pub $IMAGE_TAG
```

**Kubernetes Admission Control:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-signature-verification
webhooks:
- name: image-signature.kyverno.svc
  clientConfig:
    service:
      name: kyverno-svc
      namespace: kyverno
      path: /verify/images
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
```

### 4. Multi-Scanner Approach

**Why Use Multiple Scanners:**
- Different scanners have different vulnerability databases
- Reduces false negatives
- Provides comprehensive coverage

**Implementation Strategy:**

```yaml
# GitHub Actions example with multiple scanners
name: Container Security Scan
on: [push]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Build container
      run: docker build -t myapp:${{ github.sha }} .

    - name: Scan with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'

    - name: Scan with Grype
      run: |
        grype myapp:${{ github.sha }} --fail-on high
        echo "Grype scan completed"

    - name: Check for critical findings
      run: |
        if grep -q '"level": "error"' trivy-results.sarif; then
          echo "Critical vulnerabilities found"
          exit 1
        fi
```

### 5. Runtime Security Integration

**Continuous Runtime Monitoring:**

```yaml
# Falco runtime security rules
- rule: Unexpected privileged container
  desc: Detect privileged containers
  condition: container and container.privileged
  output: Privileged container started (user=%user.name command=%proc.cmdline %container.info)
  priority: WARNING
  tags: [container, privilege]

- rule: Shell spawned in container
  desc: A shell was spawned by a non-shell program in a container
  condition: >
    container and proc.name = bash and
    not proc.args contains "terraform" and
    not proc.args contains "ansible"
  output: Shell spawned in container (user=%user.name container_id=%container.id container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: NOTICE
```

### 6. Security Gates Configuration

**Configurable Security Policies:**

```yaml
# Security policy configuration
security_gates:
  vulnerabilities:
    critical: 0    # Zero tolerance for critical CVEs
    high: 5        # Maximum 5 high severity CVEs
    medium: 20     # Maximum 20 medium severity CVEs
    low: 50        # Maximum 50 low severity CVEs
  
  compliance:
    max_image_age_days: 30
    required_licenses: ["MIT", "Apache-2.0"]
    forbidden_licenses: ["GPL-3.0", "AGPL-3.0"]
  
  signing:
    required: true
    allowed_signers: ["team-security@company.com"]
  
  runtime:
    allow_privileged: false
    allow_root: false
    read_only_root_filesystem: true
```

### 7. Automated Remediation Workflow

**Self-Healing Pipeline:**

```mermaid
flowchart LR
    subgraph AutoRemediation[Automated Remediation Workflow]
        A1[Vulnerability Detected] --> A2{Auto-remediable?}
        A2 -->|Yes| A3[Automated Patch]
        A2 -->|No| A4[Security Team Alert]
        
        A3 --> A5[Rebuild Image]
        A5 --> A6[Rescan Image]
        A6 --> A7{Vulnerability Fixed?}
        A7 -->|Yes| A8[Deploy Fixed Image]
        A7 -->|No| A9[Escalate to Engineers]
        
        A4 --> A10[Manual Investigation]
        A10 --> A11[Patch Development]
        A11 --> A5
    end
```

## Key Recommendations Summary

1. **Base Image Security**
   - Use minimal base images (Distroless, Scratch)
   - Regularly update base images
   - Maintain approved base image list
   - Pin to specific digests, not tags

2. **Build Failure Criteria**
   - Zero tolerance for critical CVEs
   - Fail on secrets detection
   - Enforce image signing
   - Block prohibited licenses

3. **Image Signing**
   - Sign all production images
   - Verify signatures before deployment
   - Implement key rotation policies
   - Use admission controllers for enforcement

4. **Continuous Monitoring**
   - Scan images in registry continuously
   - Monitor runtime behavior
   - Implement automated remediation
   - Maintain comprehensive audit trails

5. **Multi-Layer Security**
   - Combine multiple scanning tools
   - Implement security gates at each stage
   - Use both static and dynamic analysis
   - Integrate with runtime protection

This comprehensive container scanning approach ensures security is integrated throughout the container lifecycle, from development to runtime, with appropriate fail-safes and automated enforcement mechanisms.