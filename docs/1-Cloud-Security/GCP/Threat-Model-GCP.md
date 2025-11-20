# 👨‍💻 GCP Threat Modeling: Identifying and Mitigating Key Attack Vectors in Google Cloud Platform (GCP) Environments 🔥
### **My GCP Threat Model Notes**

**Philosophy:** Assume breach. The cloud shared responsibility model means Google secures the *infrastructure*, but I secure my *configuration*. My goal is to raise the attacker's cost and reduce my attack surface. Think like an attacker to defend like an engineer.

---

### **1. The Big Picture: Attack Vectors**

Most compromises aren't zero-days; they're misconfigurations an attacker can exploit.

| Attack Vector | Why It's Dangerous | My Mindset |
| :--- | :--- | :--- |
| **Misconfigured IAM** | The #1 cause of breaches. Over-privileged accounts are a gold mine. | "Least privilege is not a suggestion; it's the law." |
| **Exposed Storage Buckets** | Public data leaks, ransomware entry point, data exfiltration. | "All buckets are private until proven otherwise." |
| **Insecure GKE Clusters** | A pivot point to control entire projects. Pods running as root, exposed dashboards. | "A cluster is a server room; lock the door and give out specific keys." |
| **VMs with Defaults/No Shield** | Cryptojacking, pivot to metadata server for SA keys. | "A default VM is a compromised VM." |
| **Weak Org Policies & Networking** | Allows the above misconfigurations to happen in the first place. | "Prevention over detection. Stop the stupid early." |

---

### **2. Threat Considerations & Mitigations Deep Dive**

#### **THREAT: Misconfigured IAM & Privilege Escalation**

*   **The Attack:**
    1.  Phish a user with `roles/editor`.
    2.  Find a SA with `roles/editor` on a VM.
    3.  Use the SA to assign itself more roles or access the Compute Engine default SA.
*   **My Mitigations:**

    *   **Prevention (Build-Time):**
        *   **Orgs Policy:** Enforce `iam.disableServiceAccountKeyCreation` to block static SA key uploads.
        *   **Orgs Policy:** Enforce `iam.allowedPolicyMemberDomains` to restrict to my company's domain.
        *   **Principle of Least Privilege:** Use predefined roles or custom roles. `roles/editor` and `roles/owner` are for break-glass *only*.
        *   **Service Account Usage:**
            *   Never use the default Compute Engine SA.
            *   Use **Workload Identity** for GKE (eliminates keys!).
            *   For Cloud Functions/Cloud Run, use a dedicated, minimal-privilege SA.

    *   **Detection (Run-Time):**
        *   **Cloud Audit Logs:** Alert on critical IAM events: `SetIamPolicy`, `serviceAccount.keys.create`.
        *   **Policy Analyzer:** Regularly query "who has `storage.admin`" or other powerful roles.
        *   **IAM Recommender:** **ACTIVATE THIS.** Automatically identifies unused roles and suggests removal. Review quarterly.

#### **THREAT: Exposed Cloud Storage Buckets**

*   **The Attack:**
    1.  Scanner finds bucket with `allUsers` or `allAuthenticatedUsers` read permission.
    2.  Data is downloaded (leak) or encrypted (ransomware).
    3.  If write is allowed, attacker uploads malware or phishing kits.
*   **My Mitigations:**

    *   **Prevention (Build-Time):**
        *   **Orgs Policy: `storage.publicAccessPrevention`** - **ENFORCE THIS.** This is the single best control. It prevents any object in a bucket from being made public, overriding any fine-grained ACLs.
        *   **Orgs Policy: `storage.uniformBucketLevelAccess`** - Enforce this to simplify perms and avoid confusing ACLs.
        *   **Default:** All new buckets should be created with `--public-access-prevention enforced`.

    *   **Detection (Run-Time):**
        *   **Security Command Center (SCC):** The "Public Cloud Storage Bucket" finding is a critical alert.
        *   **Custom Script:** Use Asset Inventory to list all buckets and their IAM policies, flagging any with non-project members.
        ```bash
        # Quick check for publicly accessible buckets
        gcloud storage buckets list --format="table(name, publicAccessPrevention, uniformBucketLevelAccess)"
        ```

#### **THREAT: Insecure GKE Clusters**

*   **The Attack:**
    1.  Exposed Kubernetes API (public endpoint with weak auth).
    2.  Compromised Pod (running as root) escapes to node.
    3.  Pod accesses the node's metadata server, steals the powerful default SA key.
    4.  Attacker now owns the project.
*   **My Mitigations (The HARDENING Checklist):**

    *   **Network Security:**
        *   **Control Plane:** Never use a public endpoint for the control plane unless you have a *very* good reason. Use **Private Cluster**.
        *   **Authorized Networks:** If you *must* have a public endpoint, restrict it to your corporate IPs. This is a weak control; prefer private.

    *   **Node Security:**
        *   **Use COS (Container-Optimized OS):** Hardened by default. Don't use Ubuntu for nodes.
        *   **Enable Shielded Nodes:** Ensures node integrity. Prevents rootkits.

    *   **Workload & Pod Security (CRITICAL):**
        *   **Workload Identity:** **MANDATORY.** Prevents pods from using the node's SA. Isolates permissions per workload.
        *   **Disable Legacy Metadata API:** On new clusters, the VMM-style metadata server is disabled by default (good). On old clusters, disable it. This blocks the `169.254.169.254` attack.
        *   **Pod Security:**
            *   **Use `securityContext`:**
                ```yaml
                securityContext:
                  runAsNonRoot: true
                  runAsUser: 1000
                  allowPrivilegeEscalation: false
                  capabilities:
                    drop:
                      - ALL
                ```
            *   **Adopt `PodSecurityAdmission`** (successor to PodSecurityPolicies) to enforce standards at the namespace level.

---

### **3. My Proactive Defense Stack**

This is my "set it and forget it" foundation.

1.  **Organization Policies:** The guardrails. Prevents the creation of insecure resources.
    *   *My Must-Haves:* `storage.publicAccessPrevention`, `iam.disableServiceAccountKeyCreation`, `constraints/compute.vmExternalIpAccess` (restrict VMs with public IPs).

2.  **Security Command Center (SCC) Premium:** The continuous monitoring.
    *   Scans for misconfigs (public buckets, weak firewall rules).
    *   Provides vulnerability scanning for container images.
    *   **Action:** Enable it at the *organization* level. Review findings weekly.

3.  **Cloud Audit Logs (Immutable):** The "what happened."
    *   **Sink to a locked-down project:** Export all logs to a central, tightly controlled project. This prevents an attacker from deleting their tracks.
    *   **Alerting:** Set up Log-based alerts in Cloud Monitoring for critical events (IAM changes, custom SA key creation, big firewall rule changes).

4.  **Binary Authorization:** For high-security workloads. Deploy only signed, approved container images. Prevents known-malicious or unvetted code from running.

### **My Quick Threat Model Review Script**

```bash
#!/bin/bash
# My Quick GCP Threat Surface Check
PROJECT_ID="my-project"

echo "=== GCP Threat Surface Check for $PROJECT_ID ==="

# 1. Check for Public Buckets
echo -e "\n[!] Checking Cloud Storage Buckets..."
gcloud storage buckets list --project=$PROJECT_ID --format="table(name, location, publicAccessPrevention, uniformBucketLevelAccess)"

# 2. Check GKE Cluster Configs
echo -e "\n[!] Checking GKE Clusters..."
gcloud container clusters list --project=$PROJECT_ID --format="table(name, location, masterIpv4CidrBlock, privateClusterConfig.enablePrivateNodes, workloadIdentityConfig.workloadPool)"

# 3. Check VMs with Public IPs
echo -e "\n[!] Checking VMs with External IPs..."
gcloud compute instances list --project=$PROJECT_ID --filter="(networkInterfaces[].accessConfigs[].type:EXTERNAL_NAT)" --format="table(name, zone, networkInterfaces[].accessConfigs[].natIP)"

# 4. Check Powerful IAM Bindings
echo -e "\n[!] Checking for Primitive Roles (Owner/Editor)..."
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role)" | sort | uniq | grep -E "(roles\/owner|roles\/editor|roles\/admin)"

echo -e "\n=== Review SCC Findings and Audit Logs for a complete picture. ==="
```

**Final Thought:** A threat model is a living document. Run this checklist every time you start a new project and during quarterly security reviews.