+# 👨‍💻 GCP Workload Identity: Securely Managing GKE Workload Credentials without Static Keys 🔥
***

### **My Workload Identity Notes**

**Philosophy:** Static service account keys are cancer. They're long-lived, easily leaked, hard to rotate, and often over-privileged. Workload Identity is the cure. It's the **only** correct way for GKE workloads to authenticate to GCP services.

---

### **1. Core Concept: What Is This Magic?**

*   **The Problem:** You have a Pod in GKE that needs to talk to Cloud Storage. How do you give it credentials?
    *   ❌ **Bad:** Mount a JSON key file as a Kubernetes Secret. (Leakable, permanent, painful rotation).
    *   ❌ **Less Bad:** Use the node's service account (the VM's identity). Every Pod on the node inherits the same broad permissions. **Massive privilege escalation risk.**
    *   ✅ **Correct:** Use Workload Identity.

*   **The Solution:** Workload Identity lets a **Kubernetes Service Account (KSA)** impersonate a **GCP Service Account (GSA)**.
    *   The Pod doesn't get a key. It gets a short-lived access token automatically.
    *   It's like giving your Pod a specific, temporary badge to access only what it needs.

**The Mental Model:**
`Kubernetes Pod` -> `Kubernetes Service Account (KSA)` -> **Workload Identity Binding** -> `GCP Service Account (GSA)` -> `GCP APIs (Cloud Storage, etc.)`

---

### **2. Step-by-Step Setup (My Cheat Sheet)**

This is the muscle memory I've built. Follow this exactly.

#### **Prerequisites**
*   GKE cluster created with Workload Identity enabled. (It's the default now!).
*   `gcloud`, `kubectl` configured.
*   The GKE cluster's control plane has IAM permissions to get credentials for the GSA (the `gkehub` SA does this magic).

#### **Step 1: Create the GCP Service Account (GSA)**
This is the identity that holds the GCP permissions.
```bash
# Create the GSA
gcloud iam service-accounts create my-app-gsa \
  --description="GSA for my app to read from Cloud Storage" \
  --display-name="my-app-gsa"

# Grant it the LEAST PRIVILEGE it needs (e.g., read a specific bucket)
gcloud storage buckets add-iam-policy-binding gs://my-app-bucket \
  --member="serviceAccount:my-app-gsa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

#### **Step 2: Create the Kubernetes Service Account (KSA)**
This is the identity your Pod uses inside the cluster.
```bash
# Create a namespace for clean isolation
kubectl create namespace my-app

# Create the KSA in that namespace
kubectl create serviceaccount my-app-ksa --namespace my-app
```

#### **Step 3: Bind Them Together with IAM**
This is the magic step. You're telling GCP: *"The KSA `my-app-ksa` in namespace `my-app` is allowed to impersonate the GSA `my-app-gsa`."*

```bash
gcloud iam service-accounts add-iam-policy-binding \
  my-app-gsa@${PROJECT_ID}.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[my-app/my-app-ksa]"
```
*   **`roles/iam.workloadIdentityUser`:** This specific role allows the impersonation.
*   **`member=`:** Note the special format: `[NAMESPACE/KSA_NAME]`.

#### **Step 4: Annotate the KSA**
This completes the link on the Kubernetes side. You're telling the KSA: *"Hey, when you need GCP creds, pretend to be this GSA."*

```bash
kubectl annotate serviceaccount my-app-ksa \
  --namespace my-app \
  iam.gke.io/gcp-service-account=my-app-gsa@${PROJECT_ID}.iam.gserviceaccount.com
```

#### **Step 5: Deploy Your Pod Using the KSA**
In your Pod spec, simply reference the KSA you created.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
  namespace: my-app
spec:
  serviceAccountName: my-app-ksa # <-- This is the magic line
  containers:
  - name: app
    image: us-docker.pkg.dev/my-project/my-repo/my-app:latest
    command: ["/bin/sleep"]
    args: ["infinity"]
```

**Test It:**
```bash
kubectl exec -it my-app-pod -n my-app -- /bin/sh

# Inside the pod, use the GCP metadata server to get a token.
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Or use gcloud if installed in the pod
gcloud storage ls gs://my-app-bucket/ # This should work!
gcloud storage ls gs://some-other-bucket/ # This should FAIL. (Least privilege!)
```

---

### **3. Best Practices & Pro Tips**

#### **1. Namespace Isolation is Key**
*   **Always** create KSAs in a namespace, never in `default`.
*   This prevents naming collisions and enforces security boundaries. A KSA in the `prod` namespace should impersonate a different GSA than one in `dev`.

#### **2. Strict 1:1 Mapping (Where Possible)**
*   Ideal: One KSA per application/team per namespace maps to one GSA with a specific purpose.
*   This makes auditing trivial. If a Pod needs new permissions, you modify the GSA's IAM bindings, not the KSA annotation.

#### **3. GSA Naming Convention**
My standard: `{app}-{env}-gsa`
*   Example: `data-processor-prod-gsa`, `frontend-dev-gsa`
*   This makes it instantly clear in IAM audits what the account is for.

#### **4. Handling Multiple Clusters/Environments**
*   **Dev/Prod Separation:** Use different GSAs for dev and prod. A KSA in the `dev` cluster can bind to `my-app-dev-gsa`, while a KSA in the `prod` cluster binds to `my-app-prod-gsa`. This is a clean separation.
*   **Same GSA, Multiple Clusters:** You can bind KSAs from *different* clusters to the *same* GSA. Just repeat Step 3 for each cluster's member identity.
    ```bash
    # For cluster-1
    --member="serviceAccount:project-id.svc.id.goog[my-ns/my-ksa]"
    # For cluster-2
    --member="serviceAccount:project-id.svc.id.goog[my-ns/my-ksa]"
    ```

#### **5. Migrating FROM Static Keys TO Workload Identity**
1.  Create the new GSA and KSA with Workload Identity as above.
2.  Deploy your application with the new KSA, but keep the old secret-mounted key configuration for now.
3.  In your app code, use **Application Default Credentials (ADC)**. It will automatically find the Workload Identity credentials and ignore the key file.
4.  Test thoroughly. The app should work identically.
5.  Once confirmed, remove the volume mount for the old key Secret from your Deployment.
6.  Delete the old Secret and the old, powerful GSA key. **Celebrate.**

---

### **My "Did I Set It Up Right?" Debugging Checklist**

When it doesn't work (it's always a step missing):

1.  ✅ Is Workload Identity enabled on the cluster? (`gcloud container clusters describe my-cluster | grep workloadIdentity`)
2.  ✅ Does the GSA have the correct IAM permissions on the target resource (e.g., the bucket)?
3.  ✅ Is the IAM binding between the KSA and GSA correct? (Check the `member=` string for typos in namespace/name).
4.  ✅ Is the KSA annotated correctly? (`kubectl get sa my-ksa -n my-ns -o yaml | grep iam.gke.io`)
5.  ✅ Is the Pod *actually* using the correct KSA? (`kubectl get pod my-pod -n my-ns -o jsonpath='{.spec.serviceAccountName}'`)
6.  ✅ Have I waited ~30 seconds after annotating the KSA before deploying the Pod? (The credential cache can be slightly slow).

### **Example: Real-World Snippet for Terraform/Config Connector**

```yaml
# This is how I'd do it with GCP Config Connector (K8s-native GCP management)
apiVersion: iam.cnrm.cloud.google.com/v1
kind: IAMServiceAccount
metadata:
  name: my-app-gsa
  namespace: my-app-ns # Namespace in Config Connector, not K8s
spec:
  displayName: "My App GSA"
---
apiVersion: storage.cnrm.cloud.google.com/v1
kind: StorageBucketIAMMember
metadata:
  name: my-app-bucket-binding
  namespace: my-app-ns
spec:
  member: serviceAccount:my-app-gsa@${PROJECT_ID}.iam.gserviceaccount.com
  role: roles/storage.objectViewer
  bucketRef:
    name: my-app-bucket
---
apiVersion: iam.cnrm.cloud.google.com/v1
kind: IAMPolicyMember
metadata:
  name: my-app-wi-binding
  namespace: my-app-ns
spec:
  member: serviceAccount:${PROJECT_ID}.svc.id.goog[my-app/my-app-ksa]
  role: roles/iam.workloadIdentityUser
  resourceRef:
    apiVersion: iam.cnrm.cloud.google.com/v1
    kind: IAMServiceAccount
    name: my-app-gsa
```

**Final Word:** Once you go Workload Identity, you never go back. It's the single biggest security and operational improvement you can make for GKE workloads.