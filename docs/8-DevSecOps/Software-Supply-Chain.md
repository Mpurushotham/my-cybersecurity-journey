# Software Supply Chain Security: Comprehensive Guide

## 1. Complete Software Supply Chain Security Architecture

```mermaid
flowchart TD
    subgraph SupplyChainSecurity[Software Supply Chain Security Architecture]
        subgraph DevelopmentChain[Development Supply Chain]
            DC1[Source Code<br/>Git Repositories] --> DC2[Dependencies<br/>Open Source, Third-party]
            DC2 --> DC3[Build System<br/>CI/CD Pipelines]
            DC3 --> DC4[Artifact Creation<br/>Container Images, Binaries]
            DC4 --> DC5[Registry Storage<br/>Container Registries]
        end

        subgraph SecurityRisks[Supply Chain Security Risks]
            SR1[Compromised Dependencies<br/>Malicious Packages] --> SR2[Build System Compromise<br/>CI/CD Attack]
            SR2 --> SR3[Artifact Tampering<br/>MITM, Registry Attacks]
            SR3 --> SR4[Source Code Compromise<br/>Git Repository Attacks]
            SR4 --> SR5[Insider Threats<br/>Malicious Contributors]
        end

        subgraph SecurityControls[Security Controls & Mitigations]
            SC1[SBOM Management<br/>Software Bill of Materials] --> SC2[Provenance & Attestation<br/>Build Provenance]
            SC2 --> SC3[Dependency Security<br/>Pinning, Scanning]
            SC3 --> SC4[Artifact Security<br/>Signing, Verification]
            SC4 --> SC5[Access Control<br/>Least Privilege, 2FA]
        end

        subgraph SecurityTools[Security Tooling]
            ST1[SBOM Generators<br/>Syft, SPDX] --> ST2[Signing Tools<br/>Cosign, Sigstore]
            ST2 --> ST3[Dependency Scanners<br/>Snyk, OSS Index]
            ST3 --> ST4[Policy Engines<br/>OPA, Kyverno]
            ST4 --> ST5[Runtime Security<br/>Falco, RASP]
        end

        subgraph Compliance[Compliance & Assurance]
            C1[SLSA Framework<br/>Supply-chain Levels] --> C2[NTIA SBOM Standards<br/>Minimum Elements]
            C2 --> C3[CIS Benchmarks<br/>Supply Chain Security]
            C3 --> C4[NIST SSDF<br/>Secure Software Development]
            C4 --> C5[ISO 27034<br/>Application Security]
        end
    end

    DevelopmentChain --> SecurityRisks
    SecurityRisks --> SecurityControls
    SecurityControls --> SecurityTools
    SecurityTools --> Compliance
```

## 2. Software Supply Chain Attack Vectors

```mermaid
flowchart TD
    subgraph SupplyChainAttacks[Software Supply Chain Attack Vectors]
        subgraph DependencyAttacks[Dependency Attacks]
            DA1[Typosquatting<br/>Malicious Package Names] --> DA2[Account Takeover<br/>Compromised Maintainer]
            DA2 --> DA3[Malicious Updates<br/>Backdoored Versions]
            DA3 --> DA4[Dependency Confusion<br/>Private Package Spoofing]
            DA4 --> DA5[License Manipulation<br/>Compliance Violations]
        end

        subgraph BuildSystemAttacks[Build System Attacks]
            BA1[CI/CD Compromise<br/>Pipeline Manipulation] --> BA2[Build Environment<br/>Malicious Build Tools]
            BA2 --> BA3[Secrets Exposure<br/>Credentials in Builds]
            BA3 --> BA4[Cache Poisoning<br/>Compromised Build Cache]
            BA4 --> BA5[Environment Variables<br/>Injected Malicious Code]
        end

        subgraph ArtifactAttacks[Artifact & Distribution Attacks]
            AA1[Registry Compromise<br/>Malicious Image Upload] --> AA2[Man-in-the-Middle<br/>Download Interception]
            AA2 --> AA3[Hash Collision<br/>Different Content, Same Hash]
            AA3 --> AA4[Signature Spoofing<br/>Fake Digital Signatures]
            AA4 --> AA5[Metadata Tampering<br/>Modified SBOM, Provenance]
        end

        subgraph SourceCodeAttacks[Source Code Attacks]
            SCA1[Git Repository Compromise<br/>Malicious Commits] --> SCA2[Developer Workstation<br/>Compromised Developer Machine]
            SCA2 --> SCA3[Social Engineering<br/>Malicious PR/Merge]
            SCA3 --> SCA4[Access Control Bypass<br/>Unauthorized Changes]
            SCA4 --> SCA5[CI Configuration<br/>Malicious Pipeline Config]
        end

        subgraph RuntimeAttacks[Runtime & Deployment Attacks]
            RA1[Container Escape<br/>Privilege Escalation] --> RA2[Configuration Drift<br/>Unauthorized Changes]
            RA2 --> RA3[Secret Leakage<br/>Runtime Secret Exposure]
            RA3 --> RA4[Supply Chain Propagation<br/>Downstream Infection]
            RA4 --> RA5[Update Mechanism Abuse<br/>Malicious Updates]
        end
    end

    DependencyAttacks --> BuildSystemAttacks
    BuildSystemAttacks --> ArtifactAttacks
    ArtifactAttacks --> SourceCodeAttacks
    SourceCodeAttacks --> RuntimeAttacks
```

## 3. SBOM (Software Bill of Materials) Management

```mermaid
flowchart TD
    subgraph SBOMManagement[SBOM - Software Bill of Materials Management]
        subgraph SBOMCreation[SBOM Creation]
            SC1[Source Code Analysis<br/>Dependency Discovery] --> SC2[Build-time Analysis<br/>Actual Dependencies]
            SC2 --> SC3[Container Image Analysis<br/>Layered Analysis]
            SC3 --> SC4[Binary Analysis<br/>Compiled Dependencies]
            SC4 --> SC5[Runtime Analysis<br/>Actual Used Dependencies]
        end

        subgraph SBOMFormats[SBOM Formats & Standards]
            SF1[SPDX<br/>Linux Foundation Standard] --> SF2[CycloneDX<br/>OWASP Standard]
            SF2 --> SF3[SWID Tags<br/>ISO/IEC 19770-2]
            SF3 --> SF4[Proprietary Formats<br/>Vendor-specific]
            SF4 --> SF5[Conversion Tools<br/>Format Interoperability]
        end

        subgraph SBOMContent[SBOM Content & Metadata]
            SM1[Component Identification<br/>Name, Version, PURL] --> SM2[Relationship Mapping<br/>Dependency Tree]
            SM2 --> SM3[License Information<br/>Compliance Tracking]
            SM3 --> SM4[Vulnerability Data<br/>CVE Mapping]
            SM4 --> SM5[Provenance Information<br/>Build Details]
        end

        subgraph SBOMTools[SBOM Tool Ecosystem]
            ST1[Generation Tools<br/>Syft, Snyk, OWASP DC] --> ST2[Analysis Tools<br/>Dependency-Track, OSS Review]
            ST2 --> ST3[Registry Integration<br/>Registry Storage]
            ST3 --> ST4[CI/CD Integration<br/>Automated SBOM Generation]
            ST4 --> ST5[Policy Enforcement<br/>SBOM Quality Gates]
        end

        subgraph SBOMWorkflow[SBOM Workflow]
            SW1[Generate SBOM<br/>Build-time Automation] --> SW2[Store SBOM<br/>Immutable Storage]
            SW2 --> SW3[Verify SBOM<br/>Completeness & Accuracy]
            SW3 --> SW4[Use SBOM<br/>Vulnerability Analysis]
            SW4 --> SW5[Update SBOM<br/>Dependency Changes]
            SW5 --> SW6[Distribute SBOM<br/>Customer Delivery]
        end
    end

    SBOMCreation --> SBOMFormats
    SBOMFormats --> SBOMContent
    SBOMContent --> SBOMTools
    SBOMTools --> SBOMWorkflow
```

## 4. Provenance and Attestation Framework

```mermaid
flowchart TD
    subgraph ProvenanceFramework[Provenance & Attestation Framework]
        subgraph BuildProvenance[Build Provenance]
            BP1[Build Environment<br/>OS, Tools, Versions] --> BP2[Build Inputs<br/>Source, Dependencies]
            BP2 --> BP3[Build Process<br/>Commands, Parameters]
            BP3 --> BP4[Build Outputs<br/>Artifacts, Metadata]
            BP4 --> BP5[Build Identity<br/>Builder, Signer]
        end

        subgraph AttestationTypes[Attestation Types]
            AT1[SBOM Attestation<br/>Component Provenance] --> AT2[Build Attestation<br/>Build Process Proof]
            AT2 --> AT3[Test Attestation<br/>Security Test Results]
            AT3 --> AT4[Vulnerability Attestation<br/>Scan Results]
            AT4 --> AT5[Policy Attestation<br/>Compliance Evidence]
        end

        subgraph SigstoreIntegration[Sigstore & Cosign]
            SI1[Keyless Signing<br/>OpenID Connect] --> SI2[Transparency Log<br/>Rekor - Immutable Log]
            SI2 --> SI3[Certificate Authority<br/>Fulcio - Code Signing]
            SI3 --> SI4[Timestamp Authority<br/>RFC 3161 Timestamps]
            SI4 --> SI5[Verification Workflow<br/>Signature Validation]
        end

        subgraph SLSAFramework[SLSA Framework Implementation]
            SL1[SLSA Level 1<br/>Provenance] --> SL2[SLSA Level 2<br/>Hosted Build Service]
            SL2 --> SL3[SLSA Level 3<br/>Hardened Build]
            SL3 --> SL4[SLSA Level 4<br/>Two-person Review]
            SL4 --> SL5[SLSA Requirements<br/>Build Integrity]
        end

        subgraph VerificationWorkflow[Verification Workflow]
            VW1[Verify Signature<br/>Digital Signature Check] --> VW2[Verify Provenance<br/>Build Source Validation]
            VW2 --> VW3[Verify Attestations<br/>SBOM, Test, Scan Results]
            VW3 --> VW4[Verify Policy Compliance<br/>Security Policies]
            VW4 --> VW5{All Verifications Pass?}
            VW5 -->|Yes| VW6[Allow Deployment]
            VW5 -->|No| VW7[Block Deployment]
        end
    end

    BuildProvenance --> AttestationTypes
    AttestationTypes --> SigstoreIntegration
    SigstoreIntegration --> SLSAFramework
    SLSAFramework --> VerificationWorkflow
```

## 5. Dependency Security Management

```mermaid
flowchart TD
    subgraph DependencySecurity[Dependency Security Management]
        subgraph DependencyPinning[Dependency Pinning Strategies]
            DP1[Exact Version Pinning<br/>No Version Ranges] --> DP2[Hash Pinning<br/>Content-addressable]
            DP2 --> DP3[Reproducible Installs<br/>Lock Files]
            DP3 --> DP4[Dependency Vendoring<br/>Local Copy Storage]
            DP4 --> DP5[Private Registry<br/>Controlled Source]
        end

        subgraph DependencyScanning[Dependency Scanning]
            DS1[Vulnerability Scanning<br/>CVE Databases] --> DS2[License Compliance<br/>License Violations]
            DS2 --> DS3[Malware Detection<br/>Malicious Packages]
            DS3 --> DS4[Behavioral Analysis<br/>Suspicious Activities]
            DS4 --> DS5[Dependency Graph Analysis<br/>Transitive Risks]
        end

        subgraph UpdateManagement[Update Management]
            UM1[Automated Updates<br/>Dependabot, Renovate] --> UM2[Security-focused Updates<br/>Priority: Security Patches]
            UM2 --> UM3[Testing & Validation<br/>Update Impact Assessment]
            UM3 --> UM4[Gradual Rollout<br/>Canary Deployments]
            UM4 --> UM5[Rollback Capability<br/>Quick Reversion]
        end

        subgraph PolicyEnforcement[Dependency Policies]
            PE1[Approved Dependencies<br/>Allow-list Approach] --> PE2[Prohibited Dependencies<br/>Deny-list Maintenance]
            PE2 --> PE3[Version Constraints<br/>Minimum Security Standards]
            PE3 --> PE4[License Restrictions<br/>Approved Licenses Only]
            PE4 --> PE5[Source Restrictions<br/>Approved Registries]
        end

        subgraph RiskAssessment[Dependency Risk Assessment]
            RA1[Popularity & Maintenance<br/>Community Health] --> RA2[Update Frequency<br/>Security Responsiveness]
            RA2 --> RA3[Transitive Dependencies<br/>Dependency Tree Depth]
            RA3 --> RA4[Attack Surface<br/>Exposed Interfaces]
            RA4 --> RA5[Business Impact<br/>Criticality Assessment]
        end
    end

    DependencyPinning --> DependencyScanning
    DependencyScanning --> UpdateManagement
    UpdateManagement --> PolicyEnforcement
    PolicyEnforcement --> RiskAssessment
```

## 6. Reproducible Builds System

```mermaid
flowchart TD
    subgraph ReproducibleBuilds[Reproducible Builds System]
        subgraph BuildDeterminism[Build Determinism]
            BD1[Fixed Build Environment<br/>Container Images] --> BD2[Version Pinning<br/>Tool Versions Locked]
            BD2 --> BD3[Source Control<br/>Immutable Source References]
            BD3 --> BD4[Build Parameter Control<br/>Reproducible Flags]
            BD4 --> BD5[Timestamp Control<br/>SOURCE_DATE_EPOCH]
        end

        subgraph BuildVerification[Build Verification]
            BV1[Multiple Builder Verification<br/>Independent Rebuilds] --> BV2[Binary Comparison<br/>Bit-for-bit Identical]
            BV2 --> BV3[Provenance Comparison<br/>Build Process Matching]
            BV3 --> BV4[Signature Verification<br/>Multiple Signers]
            BV4 --> BV5[Transparency Log<br/>Public Verification]
        end

        subgraph BuildInfrastructure[Build Infrastructure Security]
            BI1[Isolated Build Environments<br/>Ephemeral Containers] --> BI2[Immutable Build Tools<br/>Pre-built, Verified]
            BI2 --> BI3[Secure Secret Management<br/>Build-time Secrets]
            BI3 --> BI4[Build Log Integrity<br/>Tamper-evident Logs]
            BI4 --> BI5[Access Control<br/>Builder Authentication]
        end

        subgraph BuildArtifacts[Build Artifact Security]
            BA1[Artifact Signing<br/>Digital Signatures] --> BA2[Artifact Storage<br/>Immutable Registries]
            BA2 --> BA3[Artifact Verification<br/>Pre-deployment Checks]
            BA3 --> BA4[Artifact Promotion<br/>Security Gates]
            BA4 --> BA5[Artifact Rotation<br/>Key Rotation]
        end

        subgraph CICDIntegration[CI/CD Integration]
            CI1[Pipeline Definition<br/>Infrastructure as Code] --> CI2[Build Triggers<br/>Secure Webhooks]
            CI2 --> CI3[Environment Isolation<br/>Build Sandboxing]
            CI3 --> CI4[Audit Trail<br/>Comprehensive Logging]
            CI4 --> CI5[Security Gates<br/>Quality Checks]
        end
    end

    BuildDeterminism --> BuildVerification
    BuildVerification --> BuildInfrastructure
    BuildInfrastructure --> BuildArtifacts
    BuildArtifacts --> CICDIntegration
```

## 7. Software Supply Chain Security Controls

```mermaid
flowchart TD
    subgraph SecurityControls[Software Supply Chain Security Controls]
        subgraph PreventiveControls[Preventive Controls]
            PC1[Code Signing<br/>Developer & Build Signing] --> PC2[Two-Person Review<br/>Pull Request Approvals]
            PC2 --> PC3[Branch Protection<br/>Main Branch Security]
            PC3 --> PC4[Environment Hardening<br/>Build & Runtime]
            PC4 --> PC5[Access Control<br/>RBAC, Least Privilege]
        end

        subgraph DetectiveControls[Detective Controls]
            DC1[Dependency Scanning<br/>Continuous Monitoring] --> DC2[SBOM Analysis<br/>Component Tracking]
            DC2 --> DC3[Behavioral Analysis<br/>Anomaly Detection]
            DC3 --> DC4[Provenance Verification<br/>Build Chain Integrity]
            DC4 --> DC5[Runtime Protection<br/>RASP, WAF]
        end

        subgraph ResponsiveControls[Responsive Controls]
            RC1[Incident Response<br/>Supply Chain Attacks] --> RC2[Artifact Revocation<br/>Malicious Component Removal]
            RC2 --> RC3[Key Rotation<br/>Compromised Key Response]
            RC3 --> RC4[System Isolation<br/>Containment Measures]
            RC4 --> RC5[Forensic Analysis<br/>Root Cause Investigation]
        end

        subgraph AssuranceControls[Assurance Controls]
            AC1[Third-party Audits<br/>External Validation] --> AC2[Penetration Testing<br/>Red Team Exercises]
            AC2 --> AC3[Compliance Certification<br/>SOC2, ISO27001]
            AC3 --> AC4[Bug Bounty Programs<br/>External Researcher Testing]
            AC4 --> AC5[Security Training<br/>Developer Education]
        end

        subgraph GovernanceControls[Governance Controls]
            GC1[Policy as Code<br/>Automated Enforcement] --> GC2[Risk Assessment<br/>Continuous Risk Evaluation]
            GC2 --> GC3[Compliance Monitoring<br/>Regulatory Requirements]
            GC3 --> GC4[Metrics & Reporting<br/>Security Posture]
            GC4 --> GC5[Continuous Improvement<br/>Feedback Loops]
        end
    end

    PreventiveControls --> DetectiveControls
    DetectiveControls --> ResponsiveControls
    ResponsiveControls --> AssuranceControls
    AssuranceControls --> GovernanceControls
```

## 8. End-to-End Supply Chain Security Pipeline

```mermaid
flowchart TD
    subgraph EndToEndPipeline[End-to-End Supply Chain Security Pipeline]
        subgraph DevelopmentPhase[Development Phase]
            DP1[Secure Coding<br/>SAST, IDE Plugins] --> DP2[Dependency Management<br/>Pinning, Scanning]
            DP2 --> DP3[Code Review<br/>Security-focused Reviews]
            DP3 --> DP4[Pre-commit Hooks<br/>Secret Detection]
            DP4 --> DP5[Signed Commits<br/>Developer Identity]
        end

        subgraph BuildPhase[Build Phase]
            BP1[Isolated Build Environment<br/>Ephemeral Containers] --> BP2[Reproducible Builds<br/>Deterministic Output]
            BP2 --> BP3[SBOM Generation<br/>Build-time Component List]
            BP3 --> BP4[Artifact Signing<br/>Cosign, Sigstore]
            BP4 --> BP5[Provenance Generation<br/>Build Attestation]
        end

        subgraph TestingPhase[Testing Phase]
            TP1[Security Testing<br/>SAST, DAST, IAST] --> TP2[Vulnerability Scanning<br/>Container, Dependency]
            TP2 --> TP3[Policy Compliance<br/>OPA, Gatekeeper]
            TP3 --> TP4[Attestation Collection<br/>Test Results Evidence]
            TP4 --> TP5[Quality Gates<br/>Security Thresholds]
        end

        subgraph DistributionPhase[Distribution Phase]
            DP1[Secure Registry<br/>Access Control, Scanning] --> DP2[Artifact Promotion<br/>Security Validation]
            DP2 --> DP3[Signature Verification<br/>Deployment-time Checks]
            DP3 --> DP4[Provenance Verification<br/>Build Chain Validation]
            DP4 --> DP5[Admission Control<br/>Kubernetes Webhooks]
        end

        subgraph RuntimePhase[Runtime Phase]
            RP1[Runtime Protection<br/>RASP, Service Mesh] --> RP2[Continuous Monitoring<br/>Behavioral Analysis]
            RP2 --> RP3[Vulnerability Detection<br/>New CVE Alerts]
            RP3 --> RP4[Incident Response<br/>Supply Chain Attacks]
            RP4 --> RP5[Feedback Loop<br/>Improve Development]
        end
    end

    DevelopmentPhase --> BuildPhase
    BuildPhase --> TestingPhase
    TestingPhase --> DistributionPhase
    DistributionPhase --> RuntimePhase
```

## Detailed Explanations and Implementation

### 1. SBOM Implementation Best Practices

**SBOM Generation and Management:**

```bash
#!/bin/bash
# Automated SBOM generation pipeline

# Generate SBOM during build
echo "Generating SBOM for application..."
syft packages src/ -o spdx-json > sbom.spdx.json

# Generate SBOM for container image
syft myapp:latest -o cyclonedx-json > sbom.cyclonedx.json

# Attach SBOM to container image
cosign attach sbom --sbom sbom.spdx.json myapp:latest

# Verify SBOM attachment
cosign verify-attestation --type spdxjson myapp:latest

# Store SBOM in artifact repository
curl -X POST https://artifact-registry/sboms \
  -H "Authorization: Bearer $TOKEN" \
  -F "sbom=@sbom.spdx.json"
```

**SBOM Quality Requirements:**
- **Completeness**: All direct and transitive dependencies
- **Accuracy**: Correct versions and relationships
- **Timeliness**: Generated with each build
- **Accessibility**: Available to security teams and customers
- **Actionability**: Integrated with vulnerability management

### 2. Provenance and Attestation Implementation

**Build Provenance with SLSA:**

```yaml
# GitHub Actions SLSA provenance generation
name: SLSA Build with Provenance
on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build container
      run: |
        docker build -t myapp:${{ github.sha }} .
        docker save myapp:${{ github.sha }} > myapp.tar
        
    - name: Generate SLSA provenance
      uses: slsa-framework/slsa-github-generator/.github/actions/generator@v1.2.0
      with:
        base64-subjects: "${{ hashFiles('myapp.tar') }}"
        upload-assets: true
        
    - name: Sign provenance
      uses: sigstore/cosign-installer@v2.6.0
      with:
        cosign-release: 'v1.11.0'
        
    - name: Sign container image
      run: |
        cosign sign --key cosign.key myapp:${{ github.sha }}
        cosign attest --key cosign.key --type slsaprovenance myapp:${{ github.sha }}
```

**Provenance Verification:**

```bash
#!/bin/bash
# Verify provenance before deployment

# Verify image signature
cosign verify --key cosign.pub myapp:latest

# Verify SLSA provenance attestation
cosign verify-attestation --key cosign.pub \
  --type slsaprovenance myapp:latest

# Verify SBOM attestation
cosign verify-attestation --key cosign.pub \
  --type spdxjson myapp:latest

# Check transparency log
cosign verify --key cosign.pub \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  myapp:latest
```

### 3. Dependency Security Implementation

**Dependency Pinning Strategy:**

```python
# requirements.txt with exact pinning
Django==4.2.1
requests==2.28.2
cryptography==39.0.1
celery==5.2.7

# requirements.in for pip-tools
Django>=4.2,<5.0
requests>=2.28,<3.0
cryptography>=39.0,<40.0
```

```yaml
# GitHub Actions dependency scanning
name: Dependency Security
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly scans
  push:
    branches: [main]

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Snyk to check for vulnerabilities
      uses: snyk/actions/python@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
        
    - name: OSS Index Scan
      uses: sonatype-nexus-community/scan-action@main
      with:
        path: .
        
    - name: Check licenses
      uses: fossa-contrib/fossa-action@main
      with:
        api-key: ${{ secrets.FOSSA_API_KEY }}
```

### 4. Reproducible Builds Implementation

**Dockerfile for Reproducible Builds:**

```dockerfile
# Use specific base image digest
FROM alpine:3.18@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851f65

# Pin package versions
RUN apk add --no-cache \
    python3=3.9.18-r0 \
    py3-pip=20.3.4-r1 \
    && pip3 install --no-cache-dir \
    django==4.2.1 \
    requests==2.28.2

# Set reproducible timestamp
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.created=$SOURCE_DATE_EPOCH

# Use specific user ID
USER 1000:1000

# Non-root user and fixed paths
WORKDIR /app
COPY --chown=1000:1000 . .

# Fixed command
CMD ["python3", "app.py"]
```

**Build Script with Reproducibility:**

```bash
#!/bin/bash
# Reproducible build script

# Set reproducible timestamp
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

# Build with fixed parameters
docker build \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --tag myapp:$GIT_SHA \
  .

# Generate build provenance
cat > provenance.json << EOF
{
  "builder": "docker",
  "build_timestamp": "$(date -u -d @$SOURCE_DATE_EPOCH)",
  "source": {
    "git_commit": "$GIT_SHA",
    "git_url": "$GIT_URL"
  },
  "dependencies": {
    "base_image": "alpine@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851f65"
  }
}
EOF
```

### 5. Supply Chain Policy Enforcement

**Kyverno Policies for Supply Chain Security:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom
spec:
  background: false
  rules:
  - name: check-sbom-attestation
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "All containers must have SBOM attestation"
      pattern:
        spec:
          containers:
          - image: "*"
            # This would require cosign verification in real implementation
            
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-unpinned-images
spec:
  background: false
  rules:
  - name: require-image-digest
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Container images must be pinned by digest"
      pattern:
        spec:
          containers:
          - image: "*@sha256:*"
```

**OPA Policies for Dependency Security:**

```rego
# rego policy for dependency security
package artifactsecurity

# Deny deployment if critical vulnerabilities found
deny[msg] {
    some container in input.review.object.spec.containers
    vuln_count := vuln_data.images[container.image].critical
    vuln_count > 0
    msg := sprintf("Image %v has %d critical vulnerabilities", [container.image, vuln_count])
}

# Require SBOM for all images
deny[msg] {
    some container in input.review.object.spec.containers
    not has_sbom(container.image)
    msg := sprintf("Image %v missing SBOM attestation", [container.image])
}

has_sbom(image) {
    # Check if image has SBOM attestation
    cosign.verify_attestation(image, "spdxjson")
}
```

### 6. Continuous Monitoring and Response

**Supply Chain Monitoring Dashboard:**

```yaml
# Grafana dashboard for supply chain security
apiVersion: v1
kind: ConfigMap
metadata:
  name: supply-chain-dashboard
  labels:
    grafana_dashboard: "1"
data:
  supply-chain.json: |
    {
      "dashboard": {
        "title": "Software Supply Chain Security",
        "panels": [
          {
            "title": "SBOM Coverage",
            "type": "stat",
            "targets": [
              {
                "expr": "sum(sbom_generated) / sum(images_built) * 100",
                "legendFormat": "SBOM Coverage"
              }
            ]
          },
          {
            "title": "Critical Vulnerabilities",
            "type": "graph",
            "targets": [
              {
                "expr": "sum(vulnerabilities{severity=\"critical\"}) by (image)",
                "legendFormat": "{{image}}"
              }
            ]
          },
          {
            "title": "Provenance Verification Rate",
            "type": "stat",
            "targets": [
              {
                "expr": "sum(provenance_verified) / sum(deployments) * 100",
                "legendFormat": "Provenance Verified"
              }
            ]
          }
        ]
      }
    }
```

**Incident Response Playbook for Supply Chain Attacks:**

```yaml
# Supply chain incident response playbook
apiVersion: v1
kind: ConfigMap
metadata:
  name: supply-chain-ir-playbook
data:
  playbook.yaml: |
    stages:
      - detection:
          triggers:
            - malicious_dependency_detected
            - build_system_compromise
            - artifact_tampering_alert
          
      - containment:
          actions:
            - block_malicious_dependencies
            - revoke_compromised_artifacts
            - isolate_build_systems
          
      - eradication:
          actions:
            - identify_root_cause
            - remove_malicious_components
            - rotate_compromised_keys
          
      - recovery:
          actions:
            - rebuild_clean_artifacts
            - redeploy_verified_systems
            - update_security_controls
          
      - post_incident:
          actions:
            - conduct_root_cause_analysis
            - update_policies_procedures
            - share_lessons_learned
```

## Key Best Practices Summary

### 1. SBOM Management
- **Generate SBOMs automatically** with every build
- **Use standard formats** (SPDX, CycloneDX) for interoperability
- **Store SBOMs immutably** with corresponding artifacts
- **Verify SBOM completeness** and accuracy regularly
- **Distribute SBOMs** to customers and security teams

### 2. Provenance and Attestation
- **Implement SLSA framework** for build integrity
- **Use Sigstore** for keyless signing and verification
- **Generate build provenance** for all artifacts
- **Verify attestations** before deployment
- **Maintain transparency logs** for auditability

### 3. Dependency Security
- **Pin all dependencies** to exact versions or digests
- **Scan dependencies continuously** for vulnerabilities
- **Maintain approved dependency lists**
- **Implement automated dependency updates**
- **Monitor for dependency confusion attacks**

### 4. Reproducible Builds
- **Use fixed build environments** and tool versions
- **Control build parameters** for deterministic output
- **Verify builds independently** across multiple systems
- **Document build processes** completely
- **Test reproducibility** regularly

### 5. Policy Enforcement
- **Implement policy as code** for security requirements
- **Use admission controllers** for runtime enforcement
- **Establish security gates** in CI/CD pipelines
- **Monitor policy compliance** continuously
- **Automate security controls** wherever possible

### 6. Continuous Monitoring
- **Monitor supply chain metrics** and security posture
- **Implement runtime protection** (RASP, service mesh)
- **Establish incident response** procedures for supply chain attacks
- **Conduct regular security assessments**
- **Maintain audit trails** for all supply chain activities

This comprehensive approach to software supply chain security ensures that organizations can prevent, detect, and respond to supply chain attacks while maintaining the integrity and security of their software delivery process.

