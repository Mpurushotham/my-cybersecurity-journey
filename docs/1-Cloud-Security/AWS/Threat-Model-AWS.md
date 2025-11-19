# AWS Security: A Comprehensive Threat Model & Defense Guide

*A practical, battle-tested approach to securing AWS infrastructure*

---

## Introduction: Why AWS Security Matters

Every day, organizations migrate critical workloads to AWS, trusting the cloud to handle everything from customer data to financial transactions. But here's the reality: **AWS secures the cloud, you secure what's IN the cloud.** This shared responsibility model means that while AWS protects the physical infrastructure, you're responsible for everything you build on top of it.

This guide walks through the real attack surfaces in AWS environments, the controls that actually work (not just checkbox compliance), and practical steps to implement them. Think of this as your field manual—written from the trenches, not the theory books.

---

## Part 1: Understanding the Attack Surface

### 1.1 IAM Misconfigurations: The Crown Jewel of Cloud Attacks

IAM (Identity and Access Management) is both your strongest defense and your weakest link. When misconfigured, it's like leaving the master key under the doormat.

**Common IAM Attack Vectors:**

- **Overly permissive policies**: The classic `"Action": "*"` on `"Resource": "*"` — essentially giving someone the keys to the kingdom
- **Stale credentials**: Former employees' access keys still active months after departure
- **Cross-account trust abuse**: Trusted external accounts that shouldn't be trusted anymore
- **Privilege escalation paths**: Users who can attach policies to themselves or create new privileged users
- **Long-lived access keys**: Hard-coded credentials in applications that never rotate

**Real-world scenario:**
```
An engineer creates a temporary IAM user for testing with AdministratorAccess.
The user never gets deleted. Six months later, the credentials leak in a public
GitHub repository. Attackers find them, spin up crypto-mining instances across
all regions, and you wake up to a $50,000 AWS bill.
```

**What makes this particularly dangerous:**
- IAM changes are often invisible to traditional security tools
- Permissions can be nested across groups, roles, and policies
- Resource-based policies add another layer of complexity
- Service-linked roles can be exploited if not understood

---

### 1.2 Exposed S3 Buckets: The Gift That Keeps On Giving

S3 buckets are the most commonly breached AWS service, and for good reason—they're everywhere, and misconfigurations are trivial to exploit.

**Attack patterns:**

**Public read access:**
```bash
# Attacker's perspective - it's this easy:
aws s3 ls s3://company-backup-bucket --no-sign-request
aws s3 cp s3://company-backup-bucket/database-dump.sql . --no-sign-request
```

**Bucket policies vs ACLs confusion:**
- Bucket Policy says "deny all public"
- But an ACL on individual objects says "allow public read"
- Result? Objects are public. The most permissive rule wins.

**Predictable bucket names:**
```
company-name-backups
company-name-logs
company-name-prod
company-name-prod-backups-2024

Attackers script these patterns and probe thousands per hour.
```

**Pre-signed URL abuse:**
- Developer generates a pre-signed URL with 7-day expiration
- URL gets shared in Slack, forwarded via email, cached in browsers
- Original file deleted, but URL still grants access to bucket
- URL leaks publicly, now anyone can write to your bucket

---

### 1.3 ECR Exposure: Container Image Vulnerabilities

ECR (Elastic Container Registry) stores your Docker images. Compromising it means attackers control what runs in your production environment.

**Attack vectors:**

**Unscanned images with vulnerabilities:**
```dockerfile
# Your Dockerfile
FROM ubuntu:18.04  # End-of-life, known CVEs
RUN apt-get install old-package
COPY secret-key.pem /app/  # Embedded secrets
```

**Overly permissive repository policies:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "ecr:*"
  }]
}
```
This allows anyone (including anonymous users) to pull, push, and delete images.

**Cross-account image poisoning:**
- Attacker gains access to a trusted account
- Pushes malicious image with same tag as legitimate image
- Your CD pipeline pulls and deploys the poisoned image
- Backdoor now running in production

---

### 1.4 Compromised Credentials: The Initial Access Broker

**How credentials get compromised:**

1. **Code repositories**: Hard-coded in source code, committed to GitHub
2. **Instance metadata service (IMDS)**: Attackers SSRF to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. **CloudFormation/Terraform state**: Stored in unencrypted S3, contains secrets
4. **Phishing**: Social engineering to steal console passwords
5. **Third-party breaches**: SaaS vendor compromised, AWS keys in their database
6. **Container escape**: Breaking out of Docker to access host IAM role
7. **Lambda environment variables**: Exposed through logs or error messages

**Credential types and their risks:**

| Credential Type | Lifetime | Risk Level | Common Exposure |
|----------------|----------|------------|-----------------|
| Root account | Permanent | Critical | Rarely used, often unsecured |
| IAM user access keys | Until rotated | High | Hard-coded, committed to repos |
| IAM role temporary credentials | 1-12 hours | Medium | Instance metadata, ECS task roles |
| STS session tokens | 1-36 hours | Medium | Assumed role credentials |
| EC2 instance profile | Rotated automatically | Low-Medium | Metadata service exploitation |

---

## Part 2: Defense in Depth - Controls That Actually Work

### 2.1 Least Privilege: The Non-Negotiable Foundation

Least privilege isn't just a buzzword—it's the difference between a contained incident and a full-blown breach.

**Implementing real least privilege:**

**Bad approach (what most people do):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  }]
}
```

**Good approach (what you should do):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-specific-bucket/app-uploads/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-specific-bucket",
      "Condition": {
        "StringLike": {
          "s3:prefix": "app-uploads/*"
        }
      }
    }
  ]
}
```

**Practical workflow for least privilege:**

1. **Start with nothing** - Deny by default
2. **Grant minimum** - Add only required actions
3. **Monitor usage** - Use Access Analyzer and CloudTrail
4. **Refine based on real data** - IAM Access Advisor shows last used services
5. **Set expiration** - Time-bound elevated permissions

**Tools to find overpermissive policies:**

```bash
# Use AWS IAM Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name my-account-analyzer \
  --type ACCOUNT

# Review findings
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:region:account:analyzer/my-account-analyzer

# Check last used services per IAM entity
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::123456789012:user/engineer
```

**Permission boundaries - the safety net:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:*",
      "s3:*",
      "rds:Describe*"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:RequestedRegion": ["us-east-1", "us-west-2"]
      }
    }
  }]
}
```

Permission boundaries limit the maximum permissions, even if the role's policy grants more. A developer can't accidentally (or maliciously) grant themselves admin access.

---

### 2.2 Comprehensive Logging: Your Security DVR

If you don't have logs, you're fighting blind. Logging captures what happened, when, where, and by whom—critical for both detection and forensics.

**The logging trinity:**

1. **CloudTrail** - API call logging (who did what)
2. **VPC Flow Logs** - Network traffic (who talked to whom)
3. **S3 Access Logs** - Object-level operations (what was accessed)

**Setting up CloudTrail properly:**

```bash
# Create a trail that logs everything across all regions
aws cloudtrail create-trail \
  --name my-organization-trail \
  --s3-bucket-name my-cloudtrail-logs-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation

# Enable it
aws cloudtrail start-logging --name my-organization-trail

# Enable data events for S3 and Lambda (extra logging)
aws cloudtrail put-event-selectors \
  --trail-name my-organization-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::sensitive-bucket/*"]
    },{
      "Type": "AWS::Lambda::Function",
      "Values": ["arn:aws:lambda:*:*:function/*"]
    }]
  }]'
```

**VPC Flow Logs - see the network traffic:**

```bash
# Enable for entire VPC
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-1234567890abcdef0 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::my-flow-logs-bucket/vpc-flows/
```

**What to monitor in logs:**

- Failed authentication attempts (brute force detection)
- Changes to IAM policies or users (privilege escalation)
- S3 bucket policy modifications (data exfiltration setup)
- Security group changes (backdoor creation)
- Unusual API calls from strange IPs (compromised credentials)
- Cross-region API calls if you only operate in one region

**Log aggregation architecture:**

```
CloudTrail → S3 Bucket → Lambda (trigger) → OpenSearch/SIEM
VPC Flow Logs → S3 Bucket ↗
Application Logs → CloudWatch Logs → Subscription Filter → Lambda → OpenSearch

OpenSearch/SIEM runs detection rules and alerts
```

**Sample detection rule (in pseudo-code):**

```python
# Alert on root account usage
if event['userIdentity']['type'] == 'Root':
    alert('ROOT_ACCOUNT_USED', severity='CRITICAL')

# Alert on IAM policy changes
if 'PutUserPolicy' in event['eventName'] or \
   'AttachUserPolicy' in event['eventName']:
    alert('IAM_POLICY_MODIFIED', severity='HIGH')

# Alert on public S3 bucket
if event['eventName'] == 'PutBucketAcl' and \
   'AllUsers' in event['requestParameters']:
    alert('S3_MADE_PUBLIC', severity='CRITICAL')
```

---

### 2.3 Network Segmentation: Castle and Moat Architecture

Defense in depth means layers. Even if attackers breach the outer wall, they shouldn't be able to walk straight into the treasury.

**VPC architecture for security:**

```
Internet
    │
    ↓
[Internet Gateway]
    │
    ↓
[Public Subnet] ← NAT Gateway, Bastion, Load Balancers
    │
    ↓
[Private Subnet - Application Tier] ← EC2, ECS, Lambda
    │
    ↓
[Private Subnet - Data Tier] ← RDS, ElastiCache
    │
    ↓
[Isolated Subnet] ← Backups, sensitive processing
```

**Security group rules (acting as firewalls):**

```bash
# Web tier - only accept HTTPS from ALB
aws ec2 authorize-security-group-ingress \
  --group-id sg-web-tier \
  --protocol tcp \
  --port 443 \
  --source-group sg-alb

# App tier - only accept connections from web tier
aws ec2 authorize-security-group-ingress \
  --group-id sg-app-tier \
  --protocol tcp \
  --port 8080 \
  --source-group sg-web-tier

# Database tier - only accept from app tier
aws ec2 authorize-security-group-ingress \
  --group-id sg-db-tier \
  --protocol tcp \
  --port 5432 \
  --source-group sg-app-tier

# Deny all egress except necessary (least privilege for networks)
aws ec2 revoke-security-group-egress \
  --group-id sg-app-tier \
  --ip-permissions IpProtocol=-1,FromPort=-1,ToPort=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'
```

**Network ACLs as a second layer:**

```bash
# Deny known malicious IPs at the subnet boundary
aws ec2 create-network-acl-entry \
  --network-acl-id acl-12345678 \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block 198.51.100.0/24 \
  --egress false
```

**PrivateLink for secure service access:**

```bash
# Access AWS services without traversing the internet
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-12345678 \
  --vpc-endpoint-type Interface \
  --service-name com.amazonaws.us-east-1.s3 \
  --subnet-ids subnet-abcdef01 subnet-abcdef02
```

---

### 2.4 Automated Remediation: Security That Scales

Manual security doesn't scale. Humans are slow, make mistakes, and can't monitor 24/7. Automation fixes problems in seconds, not hours.

**Architecture for auto-remediation:**

```
AWS Config (detects violations)
    │
    ↓
[Config Rule Evaluation] → Non-compliant resource detected
    │
    ↓
SNS Topic (notification)
    │
    ↓
Lambda Function (remediation action)
    │
    ↓
Resource Fixed (S3 bucket made private, SG locked down, etc.)
    │
    ↓
Slack/Email notification sent to security team
```

**Example: Auto-remediate public S3 bucket**

```python
import boto3
import json

def lambda_handler(event, context):
    """
    Triggered by AWS Config when S3 bucket becomes public.
    Automatically removes public access.
    """
    
    s3 = boto3.client('s3')
    
    # Parse the Config event
    config_item = json.loads(event['configurationItem'])
    bucket_name = config_item['resourceName']
    
    try:
        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Remove any public ACLs
        s3.put_bucket_acl(
            Bucket=bucket_name,
            ACL='private'
        )
        
        # Alert security team
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Subject=f'Auto-remediated: Public S3 bucket {bucket_name}',
            Message=f'Bucket {bucket_name} was made public and has been automatically secured.'
        )
        
        return {
            'statusCode': 200,
            'body': f'Successfully secured bucket {bucket_name}'
        }
        
    except Exception as e:
        # If auto-remediation fails, alert immediately
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Subject=f'URGENT: Failed to auto-remediate bucket {bucket_name}',
            Message=f'Error: {str(e)}\nManual intervention required!'
        )
        raise
```

**Config rules to implement:**

```bash
# Check for S3 public read access
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}'

# Check for unrestricted SSH access
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "INCOMING_SSH_DISABLED"
  }
}'

# Check for encrypted EBS volumes
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "encrypted-volumes",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "ENCRYPTED_VOLUMES"
  }
}'
```

**EventBridge for real-time response:**

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateAccessKey"],
    "userIdentity": {
      "type": ["Root"]
    }
  }
}
```

This rule triggers when someone creates access keys for the root account (which should never happen). Your Lambda can immediately delete the keys and alert the security team.

---

## Part 3: Implementing Your Security Program

### 3.1 Immediate Actions (Week 1)

**Day 1: Inventory and assessment**

```bash
# List all IAM users
aws iam list-users --output table

# Check for users with console access
aws iam get-login-profile --user-name <username>

# Find all access keys
aws iam list-access-keys --user-name <username>

# Check last key usage
aws iam get-access-key-last-used --access-key-id <key-id>

# Find all S3 buckets
aws s3 ls

# Check each bucket's public access settings
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "Checking $bucket..."
  aws s3api get-public-access-block --bucket $bucket 2>/dev/null || echo "  ⚠️  No public access block!"
  aws s3api get-bucket-acl --bucket $bucket | grep -i "AllUsers\|AuthenticatedUsers" && echo "  🚨 PUBLIC ACL DETECTED!"
done
```

**Day 2: Enable foundational logging**

```bash
# Enable CloudTrail organization-wide
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name org-cloudtrail-logs \
  --is-organization-trail \
  --is-multi-region-trail

aws cloudtrail start-logging --name org-trail

# Enable GuardDuty (managed threat detection)
aws guardduty create-detector --enable

# Enable Security Hub (centralized findings)
aws securityhub enable-security-hub
```

**Day 3: Lock down the root account**

```bash
# Delete root access keys (if any exist)
# This must be done in the AWS Console as root

# Enable MFA for root (Console only)
# AWS Console → IAM → Security Credentials → MFA

# Set up account contacts for security notifications
aws account put-contact-information \
  --contact-information SecurityEmailAddress=security@company.com
```

**Day 4-5: S3 bucket hardening**

```bash
# Block public access account-wide (do this NOW)
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable encryption by default for all new buckets
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Enable versioning (protect against accidental deletion)
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

# Enable access logging
aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-logs-bucket",
      "TargetPrefix": "access-logs/"
    }
  }'
```

---

### 3.2 30-Day Security Roadmap

**Week 2: IAM hardening**

1. **Implement MFA for all users**
```bash
# Require MFA for all actions
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
    }
  }]
}
```

2. **Rotate all access keys older than 90 days**

```bash
# Find old keys
aws iam list-users --query 'Users[].UserName' --output text | while read user; do
  aws iam list-access-keys --user-name $user --query "AccessKeyMetadata[?CreateDate<='$(date -d '90 days ago' -I)']"
done

# Create rotation script
for user in $(cat old-key-users.txt); do
  # Create new key
  NEW_KEY=$(aws iam create-access-key --user-name $user)
  # Email user with new credentials
  # Wait 24 hours for them to update
  # Delete old key
  aws iam delete-access-key --user-name $user --access-key-id $OLD_KEY_ID
done
```

3. **Implement SCPs (Service Control Policies) in AWS Organizations**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": [
      "ec2:RunInstances"
    ],
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringNotEquals": {
        "ec2:InstanceType": ["t3.micro", "t3.small", "t3.medium"]
      }
    }
  }]
}
```

**Week 3: Network security**

1. **Deploy VPC Flow Logs everywhere**
2. **Review all security groups** - remove `0.0.0.0/0` ingress rules
3. **Implement AWS Network Firewall** for egress filtering
4. **Deploy WAF** on all internet-facing load balancers

```bash
# Create WAF with common protections
aws wafv2 create-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --default-action Block={} \
  --rules file://waf-rules.json
```

**Week 4: Monitoring and response**

1. **Set up CloudWatch alarms** for critical events
2. **Create runbooks** for common security incidents
3. **Test your incident response** with tabletop exercises
4. **Implement automated backups** and test restoration

---

### 3.3 Advanced Security Patterns

**Assume Role workflow (instead of long-lived keys):**

```bash
# Application requests temporary credentials
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/AppRole \
  --role-session-name app-session-$(date +%s)

# Returns temporary credentials (valid 1-12 hours)
# No need to store long-term access keys
```

**Secrets Manager for dynamic credentials:**

```python
import boto3
import json

def get_database_credentials():
    """Fetch database credentials from Secrets Manager"""
    client = boto3.client('secretsmanager')
    
    response = client.get_secret_value(SecretId='prod/db/postgres')
    secret = json.loads(response['SecretString'])
    
    return {
        'host': secret['host'],
        'username': secret['username'],
        'password': secret['password'],  # Rotated automatically
        'database': secret['database']
    }
```

**IMDSv2 enforcement (prevents SSRF credential theft):**

```bash
# Require IMDSv2 for all new instances
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**S3 bucket keys (reduce KMS costs by 99%):**

```bash
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

---

## Part 4: Visual Reference Guide

### Threat Model Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         ATTACK SURFACE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │     IAM      │    │  S3 Buckets  │    │     ECR      │    │
│  │              │    │              │    │              │    │
│  │ • Overpermis │    │ • Public ACLs│    │ • Unscanned  │    │
│  │ • Stale creds│    │ • Policy bugs│    │   images     │    │
│  │ • Priv escal │    │ • Leaked URLs│    │ • Permissive │    │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    │
│         │                   │                   │             │
│         └───────────────────┴───────────────────┘             │
│                             │                                 │
│                    ┌────────▼────────┐                        │
│                    │  Compromised    │                        │
│                    │  Credentials    │                        │
│                    └────────┬────────┘                        │
│                             │                                 │
└─────────────────────────────┼─────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   ATTACK CHAIN    │
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
  ┌─────▼─────┐        ┌──────▼──────┐      ┌──────▼──────┐
  │Persistence│        │Lateral Move │      │ Exfiltration│
  │           │        │             │      │             │
  │• IAM user │        │• Role assume│      │• S3 copy    │
  │• Backdoor │        │• EC2 pivot  │      │• DB dump    │
  └───────────┘        └─────────────┘      └─────────────┘
```

### Defense in Depth Layers

```
                    ╔═══════════════════════════════╗
                    ║   PREVENTIVE CONTROLS         ║
                    ╚═══════════════════════════════╝
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐      ┌─────────▼─────────┐     ┌────────▼───────┐
│ Least Privilege│      │ Network Segment.  │     │  Encryption    │
│                │      │                   │     │                │
│ • IAM policies │      │ • VPC subnets     │     │ • At rest      │
│ • Permission   │      │ • Security groups │     │ • In transit   │
│   boundaries   │      │ • NACLs           │     │ • KMS keys     │
└────────────────┘      └───────────────────┘     └────────────────┘

                    ╔═══════════════════════════════╗
                    ║   DETECTIVE CONTROLS          ║
                    ╚═══════════════════════════════╝
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐      ┌─────────▼─────────┐     ┌────────▼───────┐
│    Logging     │      │    Monitoring     │     │  Threat Detect │
│                │      │                   │     │                │
│ • CloudTrail   │      │ • CloudWatch      │     │ • GuardDuty    │
│ • VPC Flow     │      │ • Config Rules    │     │ • Security Hub │
│ • S3 Access    │      │ • Access Analyzer │     │ • Macie        │
└────────────────┘      └───────────────────┘     └────────────────┘

                    ╔═══════════════════════════════╗
                    ║   RESPONSIVE CONTROLS         ║
                    ╚═══════════════════════════════╝
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐      ┌─────────▼─────────┐     ┌────────▼───────┐
│   Automated    │      │  Incident Response│     │   Forensics    │
│  Remediation   │      │                   │     │                │
│                │      │ • Playbooks       │     │ • Log analysis │
│ • Lambda fns   │      │ • Isolation       │     │ • Memory dumps │
│ • Config auto  │      │ • Communication   │     │ • Timeline     │
└────────────────┘      └───────────────────┘     └────────────────┘
```

### Secure Architecture Blueprint

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTERNET (Untrusted)                         │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Route 53 + WAF │ ◄── DDoS Protection
                  └────────┬────────┘     Rate Limiting
                           │              Geo-blocking
                  ┌────────▼────────┐
                  │ CloudFront CDN  │ ◄── TLS 1.3
                  └────────┬────────┘     Certificate Manager
                           │
┌──────────────────────────┼──────────────────────────────────────┐
│                  VPC (10.0.0.0/16)                               │
│                          │                                       │
│  ┌───────────────────────▼───────────────────────┐             │
│  │      PUBLIC SUBNET (10.0.1.0/24)              │             │
│  │  ┌─────────────┐         ┌─────────────┐     │             │
│  │  │     ALB     │         │ NAT Gateway │     │             │
│  │  │  (HTTPS)    │         │             │     │             │
│  │  └──────┬──────┘         └──────┬──────┘     │             │
│  └─────────┼───────────────────────┼────────────┘             │
│            │                       │                           │
│  ┌─────────▼───────────────────────┼────────────┐             │
│  │   PRIVATE SUBNET - App Tier (10.0.10.0/24)   │             │
│  │                                  │            │             │
│  │  ┌─────────────┐  ┌──────────────▼──────┐   │             │
│  │  │    EC2      │  │    ECS/Fargate      │   │             │
│  │  │  (Web App)  │  │   (Microservices)   │   │             │
│  │  │             │  │                     │   │             │
│  │  │ SG: only    │  │ SG: only from ALB  │   │             │
│  │  │ from ALB    │  │                     │   │             │
│  │  └──────┬──────┘  └──────┬──────────────┘   │             │
│  └─────────┼────────────────┼──────────────────┘             │
│            │                │                                 │
│  ┌─────────▼────────────────▼──────────────────┐             │
│  │   PRIVATE SUBNET - Data Tier (10.0.20.0/24) │             │
│  │                                              │             │
│  │  ┌─────────────┐         ┌─────────────┐   │             │
│  │  │     RDS     │         │ ElastiCache │   │             │
│  │  │  (encrypted)│         │   (Redis)   │   │             │
│  │  │             │         │             │   │             │
│  │  │ SG: only    │         │ SG: only    │   │             │
│  │  │ from app    │         │ from app    │   │             │
│  │  └─────────────┘         └─────────────┘   │             │
│  └──────────────────────────────────────────────┘             │
│                                                               │
│  ┌───────────────────────────────────────────────┐           │
│  │   VPC Endpoints (PrivateLink)                 │           │
│  │   • S3  • DynamoDB  • Secrets Manager         │           │
│  │   No internet egress required                 │           │
│  └───────────────────────────────────────────────┘           │
│                                                               │
└───────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────┐
  │      SECURITY & MONITORING LAYER             │
  │                                              │
  │  CloudTrail → S3 → Athena (query logs)      │
  │  VPC Flow Logs → CloudWatch Logs            │
  │  GuardDuty → EventBridge → Lambda → SNS     │
  │  Security Hub → Centralized findings        │
  │  Config → Compliance monitoring             │
  └──────────────────────────────────────────────┘
```

---

## Part 5: Real-World Incident Response

### 5.1 Scenario: Compromised IAM Credentials

**Detection:**
```
GuardDuty Alert: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
API calls from IP 203.0.113.42 (Russia) using credentials for iam-user-prod-app
```

**Immediate response (first 15 minutes):**

```bash
# 1. Disable the compromised user immediately
aws iam attach-user-policy \
  --user-name iam-user-prod-app \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# 2. Delete all access keys
aws iam list-access-keys --user-name iam-user-prod-app \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  xargs -I {} aws iam delete-access-key \
    --user-name iam-user-prod-app \
    --access-key-id {}

# 3. Revoke all active sessions
aws iam put-user-policy \
  --user-name iam-user-prod-app \
  --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'

# 4. Query CloudTrail for all actions taken by attacker
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=iam-user-prod-app \
  --start-time $(date -d '1 hour ago' +%s) \
  --max-results 1000 > attacker-actions.json
```

**Investigation (next 60 minutes):**

```bash
# Analyze what the attacker did
cat attacker-actions.json | jq -r '.Events[] | 
  .CloudTrailEvent' | jq -r '
  [.eventTime, .eventName, .sourceIPAddress, .requestParameters] | 
  @tsv' | sort

# Common attacker actions to look for:
# - DescribeInstances (reconnaissance)
# - CreateAccessKey (persistence)
# - AttachUserPolicy (privilege escalation)
# - RunInstances (crypto mining)
# - CreateSnapshot (data exfiltration)
# - ModifyInstanceAttribute (disable monitoring)
```

**Containment and eradication:**

```bash
# If attacker created new IAM users
aws iam list-users --query 'Users[?CreateDate>`2024-11-20T00:00:00Z`]' | \
  jq -r '.[].UserName' | \
  xargs -I {} aws iam delete-user --user-name {}

# If attacker launched instances
aws ec2 describe-instances \
  --filters "Name=launch-time,Values=$(date -d '1 hour ago' -I)*" \
  --query 'Reservations[].Instances[].InstanceId' --output text | \
  xargs -I {} aws ec2 terminate-instances --instance-ids {}

# If attacker modified security groups
aws ec2 describe-security-groups \
  --filters "Name=description,Values=*suspicious*" \
  --query 'SecurityGroups[].GroupId' --output text | \
  xargs -I {} aws ec2 delete-security-group --group-id {}

# Review and remove any backdoors
aws iam list-users --query 'Users[].UserName' --output text | \
  while read user; do
    echo "Checking $user for unexpected policies..."
    aws iam list-attached-user-policies --user-name $user
    aws iam list-user-policies --user-name $user
  done
```

**Post-incident:**

1. **Root cause analysis**: How did credentials leak?
   - Check git history: `git log -p -S "AKIA" --all`
   - Review application logs for credential exposure
   - Scan container images for embedded secrets

2. **Prevent recurrence**:
   - Implement AWS Secrets Manager
   - Enforce IAM role usage (no long-term keys)
   - Enable IMDSv2 everywhere
   - Add git pre-commit hooks to catch secrets

3. **Document and share lessons learned**

---

### 5.2 Scenario: Public S3 Bucket Discovery

**Detection:**
```
Config Alert: s3-bucket-public-read-prohibited - NON_COMPLIANT
Bucket: company-prod-backups
Public access: ENABLED via bucket ACL
```

**Immediate response:**

```bash
# 1. Block public access immediately
aws s3api put-public-access-block \
  --bucket company-prod-backups \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 2. Remove public ACL
aws s3api put-bucket-acl \
  --bucket company-prod-backups \
  --acl private

# 3. Check S3 access logs to see who accessed what
aws s3 sync s3://my-logs-bucket/company-prod-backups-logs/ ./logs/
grep "REST.GET.OBJECT" logs/* | grep -v "YOUR_IP_RANGE" > suspicious-access.log

# 4. Enable versioning if not already (protect against deletion)
aws s3api put-bucket-versioning \
  --bucket company-prod-backups \
  --versioning-configuration Status=Enabled

# 5. Enable MFA Delete (prevent unauthorized deletion)
aws s3api put-bucket-versioning \
  --bucket company-prod-backups \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789012:mfa/root-account-mfa-device XXXXXX"
```

**Damage assessment:**

```bash
# Analyze access logs to determine exposure
cat suspicious-access.log | awk '{print $8}' | sort | uniq -c | sort -rn
# This shows which objects were accessed most

# Check if any sensitive data was exposed
aws s3 ls s3://company-prod-backups/ --recursive | \
  grep -E "\.(sql|dump|bak|db|pem|key)$"

# Review bucket policy history
aws s3api get-bucket-policy-status --bucket company-prod-backups
```

**Notifications required:**
- If PII exposed: Report to DPO, may require breach notification
- If customer data exposed: Customer notification
- If credentials exposed: Rotate immediately
- If financial data exposed: Compliance team, auditors

---

## Part 6: Compliance and Audit Readiness

### 6.1 Evidence Collection for Auditors

**SOC 2 / ISO 27001 evidence:**

```bash
# Generate IAM credential report
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --output text | base64 -d > iam-credential-report.csv

# This shows:
# - Users without MFA
# - Access keys older than 90 days
# - Password last used dates
# - Users who never logged in

# Config compliance report
aws configservice describe-compliance-by-config-rule \
  --output json > config-compliance-report.json

# CloudTrail log validation
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail \
  --start-time 2024-10-01T00:00:00Z \
  --end-time 2024-11-01T00:00:00Z

# Encryption status of all resources
aws rds describe-db-instances \
  --query 'DBInstances[].[DBInstanceIdentifier,StorageEncrypted]' \
  --output table

aws ec2 describe-volumes \
  --query 'Volumes[].[VolumeId,Encrypted]' \
  --output table

aws s3api list-buckets --query 'Buckets[].Name' --output text | \
  while read bucket; do
    encryption=$(aws s3api get-bucket-encryption --bucket $bucket 2>/dev/null)
    echo "$bucket: $encryption"
  done
```

### 6.2 AWS Security Reference Architecture

**Multi-account strategy (best practice):**

```
AWS Organization
│
├── Security Account
│   ├── CloudTrail (organization trail)
│   ├── GuardDuty (delegated admin)
│   ├── Security Hub (aggregator)
│   └── Config (aggregator)
│
├── Log Archive Account
│   ├── S3 bucket (all logs)
│   ├── Glacier (long-term retention)
│   └── Locked down (WORM)
│
├── Shared Services Account
│   ├── AD Connector / SSO
│   ├── Transit Gateway
│   └── DNS (Route 53)
│
├── Production Account
│   ├── VPCs (workloads)
│   ├── RDS (databases)
│   └── S3 (data)
│
├── Staging Account
│   └── (mirrors prod)
│
└── Development Account
    └── (more permissive)
```

**Service Control Policies (organization guardrails):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PreventLeavingOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "PreventDisablingSecurityServices",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "securityhub:DeleteInvitations",
        "securityhub:DisableSecurityHub",
        "config:DeleteConfigurationRecorder",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PreventModifyingCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EnforceRegionRestrictions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*",
        "iam:*",
        "route53:*",
        "support:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

---

## Part 7: Tool Arsenal

### 7.1 Open Source Security Tools

**ScoutSuite - Multi-cloud security auditing:**
```bash
# Install
pip install scoutsuite

# Run full AWS audit
scout aws --profile prod-account --report-dir ./scout-report

# Generates HTML report showing:
# - Overpermissive IAM policies
# - Public S3 buckets
# - Unencrypted resources
# - Security group misconfigurations
# - And 150+ other checks
```

**Prowler - AWS security assessment:**
```bash
# Install
pip3 install prowler

# Run specific checks
prowler aws --profile prod --checks iam1,s3*,ec2_ebs_volume_encryption

# Run full CIS AWS Foundations Benchmark
prowler aws --profile prod --compliance cis_2.0_aws

# Output to CSV for tracking
prowler aws --profile prod --output-formats csv html
```

**CloudMapper - AWS environment visualization:**
```bash
# Install
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip install -r requirements.txt

# Collect account data
python cloudmapper.py collect --account my-account

# Generate network diagram
python cloudmapper.py prepare --account my-account
python cloudmapper.py webserver

# Opens browser showing your VPCs, subnets, and connections
```

**git-secrets - Prevent committing credentials:**
```bash
# Install
brew install git-secrets  # macOS
# or
git clone https://github.com/awslabs/git-secrets.git

# Install hooks in repo
cd your-repo
git secrets --install
git secrets --register-aws

# This prevents commits containing:
# - AWS access keys (AKIA...)
# - AWS secret keys
# - Private keys
```

**Pacu - AWS exploitation framework (for penetration testing):**
```bash
# Install
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
pip3 install -r requirements.txt
python3 pacu.py

# Example: Enumerate IAM permissions
Pacu (test:No Keys Set) > run iam__enum_permissions

# Example: Search for secrets in EC2 user data
Pacu (test) > run ec2__enum_userdata
```

### 7.2 AWS Native Security Tools

**Comparison matrix:**

| Tool | Purpose | Cost | Best For |
|------|---------|------|----------|
| GuardDuty | Threat detection | $4.46/million events | Detecting compromised instances, unusual API activity |
| Security Hub | Finding aggregation | $0.001/finding | Central security dashboard across accounts |
| Macie | Data discovery | $0.0005/GB scanned | Finding PII/sensitive data in S3 |
| Inspector | Vulnerability scanning | $0.09/agent/month | Scanning EC2/containers for CVEs |
| IAM Access Analyzer | Permission analysis | Free | Finding overly permissive policies |
| Config | Resource compliance | $0.003/rule/region | Continuous compliance monitoring |
| CloudWatch | Metrics & logging | $0.50/GB ingested | Application monitoring, log aggregation |

**Quick win: Enable all free tools now:**

```bash
# IAM Access Analyzer (FREE)
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT

# AWS Config (pay for rules, but free tier available)
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/config-role

# Trusted Advisor (basic checks FREE with any account)
aws support describe-trusted-advisor-checks --language en
```

---

## Part 8: Terraform/IaC Security Patterns

### 8.1 Secure-by-Default Terraform Modules

**S3 bucket module (hardened):**

```hcl
# modules/secure-s3-bucket/main.tf

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  
  tags = merge(
    var.tags,
    {
      "Security" = "Hardened"
      "ManagedBy" = "Terraform"
    }
  )
}

# Block ALL public access by default
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning (protect against accidental deletion)
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Encrypt everything by default
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_id
    }
    bucket_key_enabled = true
  }
}

# Enable access logging
resource "aws_s3_bucket_logging" "this" {
  bucket = aws_s3_bucket.this.id

  target_bucket = var.logging_bucket
  target_prefix = "s3-access-logs/${var.bucket_name}/"
}

# Lifecycle policy (delete old versions)
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "delete-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Deny insecure transport
resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.this.arn,
          "${aws_s3_bucket.this.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
```

**IAM role module (least privilege):**

```hcl
# modules/app-role/main.tf

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    # Require requests from specific VPC
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpc"
      values   = [var.vpc_id]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.app_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  # Permission boundary prevents privilege escalation
  permissions_boundary = var.permission_boundary_arn

  tags = {
    Application = var.app_name
    Environment = var.environment
  }
}

# Scoped down policy
data "aws_iam_policy_document" "app_policy" {
  # Only allow reading specific S3 bucket
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::${var.data_bucket_name}",
      "arn:aws:s3:::${var.data_bucket_name}/*"
    ]
  }

  # Only allow writing to CloudWatch Logs
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/${var.app_name}/*"
    ]
  }

  # Only allow reading secrets for this app
  statement {
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:${var.app_name}/*"
    ]
  }
}

resource "aws_iam_role_policy" "app" {
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app_policy.json
}
```

### 8.2 Pre-Deployment Security Scanning

```bash
# tfsec - Terraform security scanner
brew install tfsec
tfsec .

# Checks for:
# - Unencrypted resources
# - Public exposure
# - Weak security groups
# - Missing logging
# - And 300+ other issues

# Checkov - policy-as-code scanner
pip install checkov
checkov -d . --framework terraform

# terrascan - detect compliance violations
brew install terrascan
terrascan scan -t aws
```

---

## Part 9: Cost vs Security Trade-offs

### 9.1 Budget-Conscious Security

**Free tier security stack:**
- IAM Access Analyzer: ✅ Free
- AWS Config basic checks: 2 free rules
- CloudTrail: 1 free trail (management events only)
- GuardDuty: 30-day free trial, then ~$5-20/month
- VPC Flow Logs: Storage cost only (~$0.50/GB)

**Total: ~$10-30/month for basic security**

**Mid-tier security stack ($100-500/month):**
- All of the above
- Security Hub: ~$0.001 per finding
- Macie: Data discovery for sensitive S3 buckets
- Inspector: Vulnerability scanning for production hosts
- CloudWatch alarms: 10 alarms free, then $0.10 each

**Enterprise security stack ($1000+/month):**
- All of the above
- Third-party SIEM integration
- AWS Systems Manager Session Manager
- WAF on all public endpoints
- AWS Shield Advanced ($3000/month - only if you face DDoS risks)

---

## Part 10: Quick Reference Checklists

### ✅ Day 1 Security Checklist

```
□ Enable MFA on root account
□ Delete root access keys
□ Create CloudTrail organization trail
□ Enable GuardDuty
□ Block S3 public access (account-wide)
□ Create AWS Config rules for critical resources
□ Set up billing alerts
□ Document emergency contacts
```

### ✅ Weekly Security Tasks

```
□ Review GuardDuty findings
□ Check Security Hub compliance score
□ Review IAM credential report for:
  - Unused access keys (90+ days)
  - Users without MFA
  - Unused users (no activity 90+ days)
□ Scan CloudTrail for root account usage
□ Review new S3 buckets for public access
□ Check for security group changes
```

### ✅ Monthly Security Tasks

```
□ Rotate access keys for service accounts
□ Review IAM policies for overpermissive rules
□ Update security group rules (remove stale entries)
□ Test backup restoration procedures
□ Review and update incident response runbooks
□ Conduct phishing simulation for team
□ Review AWS service limit increases
```

### ✅ Quarterly Security Tasks

```
□ Full account security assessment (ScoutSuite/Prowler)
□ Penetration test (internal or third-party)
□ Disaster recovery drill
□ Review and update threat model
□ Security awareness training for all staff
□ Review third-party integrations and permissions
□ Compliance audit (SOC 2, ISO, HIPAA, etc.)
```

---

## Conclusion: Security is a Journey, Not a Destination

AWS security isn't about achieving perfection—it's about continuous improvement. The threat landscape evolves daily, new vulnerabilities are discovered, and attackers get more sophisticated.

**Key takeaways:**

1. **Start simple**: Enable logging, block public S3, use IAM roles
2. **Automate everything**: Manual security doesn't scale
3. **Assume breach**: Build detection and response, not just prevention
4. **Least privilege always**: Every permission should be justified
5. **Stay curious**: Read AWS security bulletins, follow security researchers
6. **Test your defenses**: Regular drills and red team exercises

**Resources to bookmark:**

- AWS Security Blog: https://aws.amazon.com/blogs/security/
- AWS Security Best Practices: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
- AWS Security Reference Architecture: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/

---

**Remember**: The best security program is one that balances protection with usability. Don't let perfect be the enemy of good. Implement the basics well, automate what you can, and iterate continuously.

*Stay safe out there.* 🛡️