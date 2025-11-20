# 👨‍💻 IAM Fundamentals: Core Concepts and Best Practices for Identity and Access Management 🔥

***

### **My IAM Fundamentals Notes**

**Philosophy:** IAM is the foundation of *everything*. If you get this wrong, nothing else matters. A flaw in IAM is a direct path to a breach. It's not an IT task; it's a core security control.

---

### **1. Core Concepts: The Building Blocks**

#### **Authentication (AuthN) vs. Authorization (AuthZ)**
This is the most critical distinction. Mix them up and your security design will be flawed.

*   **Authentication (AuthN): "Who are you?"**
    *   The process of verifying an identity.
    *   **It's about proving you are who you claim to be.**
    *   *Examples:* Password, SSH key, X.509 certificate, OAuth 2.0 token, biometrics.
    *   **My Mental Model:** Showing your ID badge at the front door.

*   **Authorization (AuthZ): "What are you allowed to do?"**
    *   The process of verifying what permissions an authenticated identity has.
    *   **It's about granting or denying access to specific resources.**
    *   *Examples:* Can user `alice` delete a Cloud Storage bucket? Can service account `sa-data` write to a BigQuery dataset?
    *   **My Mental Model:** The permissions on your ID badge that determine which rooms you can enter after you're inside.

**The Flow:**
`Request` -> **AuthN** (Prove Identity) -> **AuthZ** (Check Permissions) -> `Grant/Deny Access`

#### **Identity Types: Know Your Actors**

*   **End Users:** Humans. Typically from a corporate directory (Google Workspace, Azure AD).
*   **Service Accounts (Machines/Workloads):** Non-human identities for applications, VMs, or functions.
    *   **GCP Specific:** `project-id@.iam.gserviceaccount.com`
    *   **These are the most dangerous identities if misconfigured.** They often have broad permissions and their keys can be leaked.
*   **Groups:** A collection of users or service accounts. **The primary way to assign access.** Never assign roles directly to users; always use groups.
*   **Google Groups:** Can be used in GCP IAM bindings. Enables easy access management outside of GCP.

#### **Access Control Models: The "How" of Authorization**

*   **RBAC (Role-Based Access Control):**
    *   **How it works:** You assign *roles* (a collection of permissions) to *identities*.
    *   **GCP Example:** Assigning the predefined role `roles/storage.admin` to a group.
    *   **Pro:** Simple, easy to manage and audit. "What can this *user* do?"
    *   **Con:** Can lead to role explosion. Not as granular as ABAC.

*   **ABAC (Attribute-Based Access Control):**
    *   **How it works:** Access is granted based on *attributes* of the user, resource, and environment.
    *   **GCP Implementation:** **IAM Conditions.**
    *   **Example:** "Grant `roles/storage.objectViewer` if the user is a member of `project-a-auditors` **AND** the bucket has the label `project: project-a`."
    *   **Pro:** Extremely granular and dynamic. Reduces the number of roles needed.
    *   **Con:** More complex to manage and debug. Policies can become difficult to read.

*   **DAC (Discretionary Access Control):**
    *   **How it works:** The *owner* of the resource decides who has access.
    *   **Example:** A user who creates a Cloud Storage bucket can add other users to it. Linux file permissions (`chmod`).
    *   **Pro:** Flexible.
    *   **Con:** Inconsistent, hard to govern centrally. Leads to access sprawl. **Minimize this in the cloud.**

*   **MAC (Mandatory Access Control):**
    *   **How it works:** Access is determined by a central authority based on security labels (e.g., "Top Secret," "Public").
    *   **Example:** A system where a user with "Secret" clearance cannot access a "Top Secret" file, regardless of who owns it.
    *   **Pro:** Very secure, centralized control.
    *   **Con:** Inflexible, complex to implement.

**My GCP Rule of Thumb:** Use **RBAC for broad strokes** (team-level access) and **ABAC (IAM Conditions) for fine-grained, dynamic scenarios**.

---

### **2. Foundational Principles: The "Why"**

These are non-negotiable. They are the pillars of a secure IAM strategy.

#### **1. Principle of Least Privilege (PoLP)**
*   **What:** Grant only the permissions absolutely necessary to perform a task.
*   **Why:** Minimizes the attack surface. If an account is compromised, the blast radius is contained.
*   **How in GCP:**
    *   Start with no permissions.
    *   Use predefined roles over primitive ones (`roles/editor`).
    *   Prefer custom roles if predefined ones are too broad.
    *   **Use IAM Recommender** to automatically find and remove unused permissions.

#### **2. Multi-Factor Authentication (MFA)**
*   **What:** Requiring two or more pieces of evidence to authenticate.
*   **Why:** Passwords are weak. MFA is the single most effective control against account takeover.
*   **My Rule:** **MANDATORY for all human users, especially those with any IAM roles.** No exceptions.

#### **3. Just-in-Time (JIT) Access**
*   **What:** Privileged access is granted only when needed, for a limited time, and is automatically revoked.
*   **Why:** Reduces the standing privileged access that attackers love to exploit.
*   **How in GCP:**
    *   Use **IAM Conditions** with time-based constraints.
        ```bash
        # Example condition for temporary access
        request.time < timestamp("2024-01-15T00:00:00Z")
        ```
    *   For true JIT elevation, use a tool like **PAM (Privileged Access Management)** that integrates with GCP.

#### **4. Centralized Identity Management**
*   **What:** Using a single, authoritative source for identities (e.g., Google Workspace, Azure AD).
*   **Why:** Eliminates shadow accounts, ensures consistent offboarding, and allows for centralized policy enforcement (like MFA).
*   **My Rule:** **Never use Google accounts for business.** Use Cloud Identity or Google Workspace. Federate identity from your existing IdP (e.g., Azure AD) if possible.

---

### **3. When to Use What: A Practical Guide**

| Scenario | Recommended Approach | GCP Tool |
| :--- | :--- | :--- |
| **Giving a team access to a project** | RBAC with Groups | Assign `roles/viewer` to group `team-data-engineers@myco.com` at the project level. |
| **A pod needs to read a specific bucket** | RBAC + Workload Identity | Create a GSA with `roles/storage.objectViewer` on the bucket. Bind to a KSA. |
| **An auditor needs temp read access to prod** | JIT with ABAC | Assign role with a **time condition**: `request.time < timestamp('...')` |
| **External user needs one-time access** | ABAC + Time Limit | Assign role with condition based on their email and a future expiration time. |
| **Enforcing "only from corp network"** | ABAC (Context) | IAM Condition: `request.ip == "192.0.2.0/24"` or use **Context-Aware Access**. |
| **A developer owns their own bucket** | DAC (Carefully) | They get `roles/storage.admin` on the bucket they create. Use Org Policy to limit this. |

### **My IAM Fundamentals Health Check**

```bash
#!/bin/bash
# My IAM Foundation Health Check Script

echo "=== IAM Fundamentals Health Check ==="

# 1. Check for Primitive Roles (DANGER)
echo -e "\n1. PRIMITIVE ROLES CHECK (Owner, Editor, Viewer):"
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role)" | sort | uniq | grep -E "(roles\/owner|roles\/editor|roles\/viewer)"

# 2. Check for Users Assigned Directly (Should use Groups)
echo -e "\n2. USERS ASSIGNED DIRECTLY (Should be minimal):"
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --format="table(bindings.members)" | grep "@" | grep -v "gserviceaccount" | grep -v "google.com" | sort | uniq

# 3. Check for Powerful Service Accounts
echo -e "\n3. SERVICE ACCOUNTS WITH PRIMITIVE ROLES (CRITICAL):"
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role, bindings.members)" | grep -E "(roles\/owner|roles\/editor)" | grep "gserviceaccount"

# 4. Check MFA Enforcement (Conceptual - check Admin Console)
echo -e "\n4. MFA ENFORCEMENT:"
echo "   - MANUALLY CHECK GOOGLE WORKSPACE/CLOUD IDENTITY ADMIN CONSOLE"
echo "   - Confirm MFA is enforced for all users, especially admins."

# 5. Check for IAM Conditions (ABAC)
echo -e "\n5. IAM POLICIES WITH CONDITIONS (ABAC):"
gcloud projects get-iam-policy $PROJECT_ID --format=json | jq -r '.bindings[] | select(.condition != null) | .role'
```

### **Best Practices Summary**

1.  **Never use primitive roles** (`owner`, `editor`, `viewer`) for daily operations.
2.  **Assign to Groups, not Users.**
3.  **Use Service Accounts for workloads,** and leverage **Workload Identity** for GKE.
4.  **Enforce MFA for all human accounts.**
5.  **Review IAM policies regularly** using Policy Analyzer and IAM Recommender.
6.  **Start with a deny-all posture** and add permissions as needed.
7.  **Use IAM Conditions** to enforce time-based, IP-based, or resource-based constraints.
8.  **Have a break-glass procedure** for emergency access that doesn't break your standard policies.

**Final Thought:** IAM is not a one-time project. It's a continuous cycle of **Grant, Review, Revoke.** Your goal is to make the "Grant" as minimal and precise as possible, the "Review" automatic and continuous, and the "Revoke" immediate and comprehensive.