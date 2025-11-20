
*** my own personal notes on GCP IAM Security. This format is designed to be a quick reference and a conceptual guide, breaking down complex topics into core principles and actionable steps.
***

### **My GCP IAM Security Notes**

**Philosophy:** IAM is the foundation of GCP security. It's not a one-time setup; it's a continuous process of granting *least privilege* and *verifying* enforcement.

---

### **1. Core IAM Principles: The "Why"**

*   **Least Privilege:** The Golden Rule. A user/service should have only the permissions *absolutely necessary* to perform its intended task. No more. Start with nothing and add only what's needed.
*   **Separation of Duties:** No single identity should have too much power. Don't assign the `roles/owner` and `roles/editor` broadly. Break down tasks.
*   **Who can do what to which resource?:**
    *   **Who:** Identity (User, Group, Service Account)
    *   **Can do what:** Role (Collection of Permissions)
    *   **To which resource:** Resource (Project, VM, Bucket, etc.)

---

### **2. Service Accounts (SAs): The "How" for Non-Humans**

SAs are for applications and workloads, not people. They are the #1 source of privilege escalation if misconfigured.

#### **Key Practices:**

*   **Naming Convention:** `sa-<purpose>-<environment>@<project-id>.iam.gserviceaccount.com`
    *   Example: `sa-dataflow-prod@my-project.iam.gserviceaccount.com`
*   **Minimal Scopes (ONLY for GCE/GKE VMs):** Scopes are a legacy, project-wide blanket permission. **Avoid them.**
    *   If you must, use the least permissive scope like `https://www.googleapis.com/auth/devstorage.read_only` instead of `cloud-platform`.
*   **Use IAM Roles on the SA:** This is the modern, recommended way. Assign specific roles (e.g., `roles/storage.objectViewer`) to the SA *on the specific resource* (e.g., a Cloud Storage bucket). This is granular and secure.

#### **Massive Win: Workload Identity for GKE**

*   **The Problem:** Using a static SA key file inside a Kubernetes Pod is a huge risk. Keys can be leaked, rotated painfully, and have broad permissions.
*   **The Solution: Workload Identity.** It allows a Kubernetes Service Account (KSA) to impersonate a GCP Service Account (GSA).
    *   No more key files!
    *   Short-lived, automatically rotated credentials.
    *   Beautifully enforces least privilege per Pod.

**Setup Workload Identity (My Cheat Sheet):**

1.  **Enable the APIs:**
    ```bash
    gcloud services enable iamcredentials.googleapis.com container.googleapis.com
    ```
2.  **Create a GCP Service Account (GSA):**
    ```bash
    gcloud iam service-accounts create my-app-sa
    ```
3.  **Grant the GSA permissions** on the resources it needs (e.g., a Cloud Storage bucket).
    ```bash
    gcloud storage buckets add-iam-policy-binding gs://my-bucket \
      --member="serviceAccount:my-app-sa@my-project.iam.gserviceaccount.com" \
      --role="roles/storage.objectViewer"
    ```
4.  **Create a K8s Service Account (KSA)** in your cluster.
    ```bash
    kubectl create serviceaccount -n <namespace> my-ksa
    ```
5.  **Bind them together:** Create an IAM Policy Binding.
    ```bash
    gcloud iam service-accounts add-iam-policy-binding \
      --role="roles/iam.workloadIdentityUser" \
      --member="serviceAccount:my-project.svc.id.goog[<namespace>/my-ksa]" \
      my-app-sa@my-project.iam.gserviceaccount.com
    ```
6.  **Annotate the KSA** in your cluster to complete the link.
    ```bash
    kubectl annotate serviceaccount my-ksa \
      --namespace <namespace> \
      iam.gke.io/gcp-service-account=my-app-sa@my-project.iam.gserviceaccount.com
    ```
7.  **In your Pod spec, reference the KSA.**
    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: my-app-pod
      namespace: <namespace>
    spec:
      serviceAccountName: my-ksa # <-- This KSA is now impersonating the GSA
      containers:
      - name: app
        image: my-app:latest
    ```
    **Boom.** The Pod now has the permissions of `my-app-sa` without any keys.

---

### **3. Audit & Analysis: The "Verification"**

You can't secure what you can't see. These tools are for monitoring and proving your IAM posture.

#### **Cloud Audit Logs**

*   **What it is:** An immutable trail of "who did what, where, and when" for admin and data access.
*   **Critical Logs:**
    *   `Admin Activity` (Enabled by default): Logs all IAM changes, resource creations/deletions. **Never turn this off.**
    *   `Data Access` (Disabled by default): Logs reads/writes to data. Very verbose, can be expensive. Enable selectively on sensitive resources (e.g., buckets with PII).
*   **Where to find them:** Logging Explorer -> `log_id("cloudaudit.googleapis.com/activity")`

#### **Policy Analyzer & IAM Recommender**

*   **What it is:** Proactive tools to find over-privileged accounts *before* they are exploited.
*   **Policy Analyzer:** A GUI tool to answer "who has access to what" across the entire organization. Great for audits.
    *   **Location:** IAM & Admin -> Policy Analyzer.
    *   Use it to query, e.g., "Show all principals who have the `storage.admin` role."
*   **IAM Recommender:** Uses machine learning to analyze service account usage and suggests removing unused roles. **Gold mine.**
    *   **Location:** IAM & Admin -> IAM -> Click on a principal -> See "Recommended" roles.
    *   **Action:** Review and apply recommendations to shrink the attack surface automatically.

#### **Cloud Asset Inventory**

*   **What it is:** A searchable catalog of *all* your GCP resources and IAM policies.
*   **Powerful Combo:** Use Asset Inventory *feeds* to dump all IAM policies to a BigQuery table. Then, you can write SQL queries to find security gaps.
    *   Example Query: "Find all SAs with the `editor` role."
    *   **Location:** Asset Inventory -> Export -> Create Feed.

---

### **My Quick-Start Security Audit Script**

```bash
#!/bin/bash
# My Quick IAM Health Check
PROJECT_ID="my-project"

echo "=== IAM Audit for $PROJECT_ID ==="

# 1. List all Service Accounts
echo "1. Service Accounts:"
gcloud iam service-accounts list --project=$PROJECT_ID

# 2. Find SAs with Primitive Roles (DANGER)
echo -e "\n2. SAs with Primitive Roles (Owner/Editor):"
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  | grep -E "(roles\/owner|roles\/editor)" | grep serviceAccount

# 3. Check for IAM Recommender findings
echo -e "\n3. IAM Recommender Summary (check console for details):"
# This is easier in the GUI, but you can list SAs to check manually.
gcloud recommender recommendations list \
  --project=$PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format="json" | jq -r '.[] | .description' | head -5

echo -e "\n=== Audit Logs Check ==="
echo "4. Check Admin Activity logs are enabled (they always are)."
echo "5. Manually check if Data Access logs are enabled for critical buckets."

echo -e "\n=== GKE Check ==="
# 4. Check if Workload Identity is enabled on clusters
echo "6. GKE Clusters and Workload Identity Status:"
gcloud container clusters list --project=$PROJECT_ID --format="table(name, workloadIdentityConfig)"
```

**Next Steps:**
*   Run this script periodically.
*   Set up Logging Alerts for critical IAM events (e.g., `SetIamPolicy`).
*   Enforce SSoT (Single Source of Truth) using Terraform/Deployment Manager for IAM, don't use the console manually.