# AWS IAM Security Essentials - Complete Guide

*A practical, hands-on guide to securing your AWS environment*

---

## Table of Contents
1. [Introduction](#introduction)
2. [Core Security Principles](#core-security-principles)
3. [Roles vs Long-Lived Keys](#roles-vs-long-lived-keys)
4. [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
5. [Least Privilege Principle](#least-privilege-principle)
6. [Permission Boundaries](#permission-boundaries)
7. [Monitoring & Auditing](#monitoring--auditing)
8. [Practical Implementation](#practical-implementation)
9. [Common Pitfalls & Best Practices](#common-pitfalls--best-practices)
10. [References](#references)

---

## Introduction

IAM (Identity and Access Management) is the backbone of AWS security. Think of it as the bouncer at the door of your cloud infrastructure - it decides who gets in, what they can do, and keeps a record of everything that happens.

The stakes are high: misconfigured IAM can lead to data breaches, unauthorized resource access, or massive unexpected bills. But don't worry - this guide will walk you through everything you need to know.

---

## Core Security Principles

### The IAM Security Trinity

```
┌─────────────────────────────────────────┐
│                                         │
│         AWS IAM SECURITY                │
│                                         │
│     ┌──────────┐  ┌──────────┐         │
│     │          │  │          │         │
│     │   WHO    │  │   WHAT   │         │
│     │          │  │          │         │
│     │ Identity │  │  Actions │         │
│     │          │  │          │         │
│     └────┬─────┘  └─────┬────┘         │
│          │              │              │
│          └──────┬───────┘              │
│                 │                      │
│           ┌─────▼──────┐               │
│           │            │               │
│           │   WHERE    │               │
│           │            │               │
│           │ Resources  │               │
│           │            │               │
│           └────────────┘               │
│                                         │
└─────────────────────────────────────────┘
```

Every IAM decision involves three questions:
- **Who** is trying to access? (User, Role, Service)
- **What** are they trying to do? (Action: read, write, delete)
- **Where** are they trying to do it? (Resource: S3 bucket, EC2 instance)

---

## Roles vs Long-Lived Keys

### Why Roles Win Every Time

**Long-lived access keys** are like giving someone a copy of your house key - once it's out there, you lose control. They can be:
- Leaked in code repositories
- Stolen from compromised machines
- Shared accidentally via Slack or email
- Never rotated (I've seen keys 1000+ days old!)

**IAM Roles** are like a hotel keycard - temporary, automatically expiring, and easy to revoke.

### The Architecture Difference

```
❌ BAD: Long-Lived Keys
┌─────────────┐
│   EC2       │
│  Instance   │─────► Hardcoded Access Key
│             │       Secret Access Key
└─────────────┘       (Never expires!)
                      │
                      ▼
                   AWS Services


✅ GOOD: IAM Role
┌─────────────┐
│   EC2       │
│  Instance   │─────► IAM Role attached
│             │       (Temporary credentials)
└─────────────┘       Auto-rotate every 15min!
                      │
                      ▼
                   AWS Services
```

### Practical Implementation

#### Setting up an EC2 Instance with a Role

```bash
# Step 1: Create a trust policy (who can assume this role)
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Step 2: Create the IAM role
aws iam create-role \
  --role-name MyEC2S3AccessRole \
  --assume-role-policy-document file://trust-policy.json

# Step 3: Attach a policy to the role
aws iam attach-role-policy \
  --role-name MyEC2S3AccessRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Step 4: Create an instance profile
aws iam create-instance-profile \
  --instance-profile-name MyEC2S3AccessProfile

# Step 5: Add role to instance profile
aws iam add-role-to-instance-profile \
  --instance-profile-name MyEC2S3AccessProfile \
  --role-name MyEC2S3AccessRole

# Step 6: Launch EC2 with the instance profile
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --iam-instance-profile Name=MyEC2S3AccessProfile
```

#### For Developers: Using Roles Locally

Instead of storing keys in `~/.aws/credentials`, use AWS SSO or assume roles:

```bash
# Configure AWS SSO (one-time setup)
aws configure sso

# Start your work session
aws sso login --profile my-dev-profile

# Now all CLI commands use temporary credentials!
aws s3 ls
```

---

## Multi-Factor Authentication (MFA)

### Why MFA is Non-Negotiable

Passwords alone are like a screen door - they give the illusion of security. According to Verizon's 2023 Data Breach Report, 81% of breaches involve stolen credentials. MFA stops attackers even when they have your password.

### MFA Flow Diagram

```
User Login Attempt
       │
       ▼
┌──────────────┐
│   Username   │
│   Password   │
└──────┬───────┘
       │
       ▼
┌──────────────┐       YES      ┌──────────────┐
│  Credentials │────────────────►│   Request    │
│    Valid?    │                 │   MFA Code   │
└──────┬───────┘                 └──────┬───────┘
       │ NO                             │
       ▼                                ▼
   Access Denied            ┌──────────────────┐
                            │ User enters code │
                            │ from MFA device  │
                            └────────┬─────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │   MFA Valid?    │
                            └────┬───────┬────┘
                              YES│       │NO
                                 │       └──► Access Denied
                                 ▼
                            Access Granted!
```

### Setting Up MFA for Root Account (Critical!)

```bash
# You MUST do this through the AWS Console for root account
# 1. Sign in as root
# 2. Click your account name → Security Credentials
# 3. Under "Multi-factor authentication (MFA)", click "Assign MFA device"
# 4. Choose "Virtual MFA device" (like Google Authenticator, Authy)
# 5. Scan the QR code with your authenticator app
# 6. Enter two consecutive MFA codes to confirm
```

### Enforcing MFA for IAM Users

Create a policy that requires MFA for sensitive operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:ListVirtualMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnVirtualMFADevice",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:DeleteVirtualMFADevice"
      ],
      "Resource": "arn:aws:iam::*:mfa/${aws:username}"
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Apply this policy:

```bash
# Save the above JSON as require-mfa.json
aws iam create-policy \
  --policy-name RequireMFAPolicy \
  --policy-document file://require-mfa.json

# Attach to a group or user
aws iam attach-user-policy \
  --user-name john-developer \
  --policy-arn arn:aws:iam::123456789012:policy/RequireMFAPolicy
```

---

## Least Privilege Principle

### The Golden Rule

**"Grant only the permissions required to perform a task"**

Think of it like giving someone directions to your house - you don't give them keys to every room, the garage code, and the safe combination. You give them exactly what they need to get to the living room.

### Permission Evolution

```
Stage 1: Too Permissive (DANGER!)
┌─────────────────────────────┐
│   AdministratorAccess       │
│   (Full access to everything)│
└─────────────────────────────┘
           ▼
           
Stage 2: Service-Level (Better)
┌─────────────────────────────┐
│   AmazonS3FullAccess        │
│   (All S3 operations)       │
└─────────────────────────────┘
           ▼
           
Stage 3: Resource-Specific (Good)
┌─────────────────────────────┐
│   Access to specific bucket │
│   my-app-production         │
└─────────────────────────────┘
           ▼
           
Stage 4: Action-Limited (Best!)
┌─────────────────────────────┐
│   Read-only access to       │
│   specific bucket           │
│   my-app-production         │
└─────────────────────────────┘
```

### Practical Example: Developer S3 Access

Instead of giving developers full S3 access, scope it down:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "DevBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-dev/*",
        "arn:aws:s3:::my-app-dev"
      ]
    },
    {
      "Sid": "DenyProductionAccess",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-app-production/*",
        "arn:aws:s3:::my-app-production"
      ]
    }
  ]
}
```

### Finding the Right Permissions

Use **IAM Access Analyzer** to generate policies based on actual usage:

```bash
# Enable Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name my-account-analyzer \
  --type ACCOUNT

# After users work for a while, generate a policy based on activity
aws accessanalyzer generate-policy \
  --policy-generation-details '{
    "principalArn": "arn:aws:iam::123456789012:user/john-developer"
  }'
```

---

## Permission Boundaries

### What Are They?

Permission boundaries are like a fence around a property - they define the maximum permissions someone can have, even if their policies try to grant more.

### The Mental Model

```
Without Permission Boundary:
┌────────────────────────────────┐
│                                │
│    All AWS Permissions         │
│                                │
│  ┌──────────────────┐          │
│  │  User's Policy   │          │
│  │                  │          │
│  │  Effective       │          │
│  │  Permissions     │          │
│  └──────────────────┘          │
│                                │
└────────────────────────────────┘


With Permission Boundary:
┌────────────────────────────────┐
│     Permission Boundary        │
│  ┌──────────────────────────┐  │
│  │                          │  │
│  │  ┌────────────────┐      │  │
│  │  │ User's Policy  │      │  │
│  │  │                │      │  │
│  │  │  Effective     │      │  │
│  │  │  Permissions   │      │  │
│  │  └────────────────┘      │  │
│  │  (Intersection!)         │  │
│  └──────────────────────────┘  │
│                                │
└────────────────────────────────┘
```

### Use Case: Delegating User Creation

Let's say you want team leads to create IAM users, but you don't want them creating admin users:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LimitedEC2AndS3Access",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "s3:Get*",
        "s3:List*",
        "s3:PutObject"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyIAMAndBilling",
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "aws-portal:*",
        "budgets:*"
      ],
      "Resource": "*"
    }
  ]
}
```

Create and attach the boundary:

```bash
# Save the above as developer-boundary.json
aws iam create-policy \
  --policy-name DeveloperBoundary \
  --policy-document file://developer-boundary.json

# Attach as a permission boundary
aws iam put-user-permissions-boundary \
  --user-name john-developer \
  --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary
```

Now even if someone gives this user AdministratorAccess, they still can't access IAM or billing!

---

## Monitoring & Auditing

### The Visibility Triad

```
┌──────────────────────────────────────────────┐
│                                              │
│            AWS Security Monitoring           │
│                                              │
│  ┌──────────────┐  ┌──────────────┐         │
│  │              │  │              │         │
│  │  CloudTrail  │  │ IAM Access   │         │
│  │              │  │  Analyzer    │         │
│  │  WHO did     │  │              │         │
│  │  WHAT and    │  │  Policy      │         │
│  │  WHEN        │  │  Analysis    │         │
│  │              │  │              │         │
│  └──────┬───────┘  └──────┬───────┘         │
│         │                 │                 │
│         └────────┬────────┘                 │
│                  │                          │
│         ┌────────▼─────────┐                │
│         │                  │                │
│         │   CloudWatch     │                │
│         │   Alarms         │                │
│         │                  │                │
│         │   Real-time      │                │
│         │   Alerts         │                │
│         │                  │                │
│         └──────────────────┘                │
│                                              │
└──────────────────────────────────────────────┘
```

### Setting Up CloudTrail

CloudTrail is your security camera - it records every API call made in your account.

```bash
# Create an S3 bucket for logs
aws s3 mb s3://my-company-cloudtrail-logs --region us-east-1

# Apply bucket policy (CloudTrail needs write access)
cat > trail-bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-company-cloudtrail-logs"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-company-cloudtrail-logs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket my-company-cloudtrail-logs \
  --policy file://trail-bucket-policy.json

# Create the trail
aws cloudtrail create-trail \
  --name my-security-trail \
  --s3-bucket-name my-company-cloudtrail-logs

# Start logging
aws cloudtrail start-logging \
  --name my-security-trail

# Enable log file validation (detect tampering)
aws cloudtrail update-trail \
  --name my-security-trail \
  --enable-log-file-validation
```

### What to Monitor

Create CloudWatch alarms for these critical events:

```bash
# Root account usage (should NEVER happen in production)
aws cloudwatch put-metric-alarm \
  --alarm-name root-account-usage \
  --alarm-description "Alert on root account usage" \
  --metric-name RootAccountUsage \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1

# Unauthorized API calls
# Policy changes
# IAM changes
# Console login failures
# Access key creation
```

### IAM Access Analyzer Setup

This tool continuously monitors your resources and alerts you if they're accessible from outside your account.

```bash
# Create an analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name my-account-analyzer \
  --type ACCOUNT

# List findings
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-account-analyzer

# Get detailed finding info
aws accessanalyzer get-finding \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-account-analyzer \
  --id finding-id-here
```

### Regular Audit Script

Here's a practical script to run weekly:

```bash
#!/bin/bash
# iam-audit.sh - Weekly IAM security audit

echo "=== IAM Security Audit Report ==="
echo "Generated: $(date)"
echo ""

echo "1. Users without MFA:"
aws iam get-credential-report
aws iam list-users --query 'Users[*].[UserName]' --output text | while read user; do
    mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)
    if [ -z "$mfa" ]; then
        echo "  ⚠️  $user"
    fi
done

echo ""
echo "2. Access keys older than 90 days:"
aws iam list-users --query 'Users[*].[UserName]' --output text | while read user; do
    aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate]' --output text | while read key date; do
        age=$(( ($(date +%s) - $(date -d "$date" +%s)) / 86400 ))
        if [ $age -gt 90 ]; then
            echo "  ⚠️  $user: $key ($age days old)"
        fi
    done
done

echo ""
echo "3. Unused access keys (no activity in 90 days):"
aws iam list-users --query 'Users[*].[UserName]' --output text | while read user; do
    aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[*].[AccessKeyId]' --output text | while read key; do
        last_used=$(aws iam get-access-key-last-used --access-key-id "$key" --query 'AccessKeyLastUsed.LastUsedDate' --output text)
        if [ "$last_used" != "None" ]; then
            days_since=$(( ($(date +%s) - $(date -d "$last_used" +%s)) / 86400 ))
            if [ $days_since -gt 90 ]; then
                echo "  ⚠️  $user: $key (last used $days_since days ago)"
            fi
        fi
    done
done

echo ""
echo "4. Users with AdministratorAccess:"
aws iam list-users --query 'Users[*].[UserName]' --output text | while read user; do
    policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`]' --output text)
    if [ ! -z "$policies" ]; then
        echo "  ⚠️  $user"
    fi
done

echo ""
echo "=== End of Report ==="
```

Make it executable and schedule it:

```bash
chmod +x iam-audit.sh

# Add to crontab (runs every Monday at 9 AM)
crontab -e
# Add: 0 9 * * 1 /path/to/iam-audit.sh | mail -s "IAM Audit Report" security@company.com
```

---

## Practical Implementation

### Complete Security Setup Checklist

#### Phase 1: Foundation (Day 1)

```bash
# 1. Enable MFA on root account (Console only)
# 2. Create an admin user for daily use
aws iam create-user --user-name admin-alice

# 3. Add to admin group
aws iam create-group --group-name Administrators
aws iam attach-group-policy \
  --group-name Administrators \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam add-user-to-group \
  --user-name admin-alice \
  --group-name Administrators

# 4. Create console password
aws iam create-login-profile \
  --user-name admin-alice \
  --password 'TempP@ssw0rd!' \
  --password-reset-required

# 5. Enable MFA for admin user (Console)
```

#### Phase 2: CloudTrail & Monitoring (Day 1-2)

```bash
# 1. Set up CloudTrail (see CloudTrail section above)
# 2. Enable AWS Config
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/config-role \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# 3. Create SNS topic for alerts
aws sns create-topic --name security-alerts
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:security-alerts \
  --protocol email \
  --notification-endpoint security@company.com
```

#### Phase 3: User & Role Strategy (Week 1)

```bash
# Create department-based groups
aws iam create-group --group-name Developers
aws iam create-group --group-name DataScientists
aws iam create-group --group-name Auditors

# Attach appropriate policies
aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Create service roles for applications
aws iam create-role --role-name AppServerRole --assume-role-policy-document file://trust-policy.json
```

#### Phase 4: Continuous Improvement (Ongoing)

```bash
# Weekly: Run audit script
./iam-audit.sh

# Monthly: Review IAM Access Analyzer findings
aws accessanalyzer list-findings --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-account-analyzer

# Quarterly: Review all IAM policies for unused permissions
# Use IAM Access Analyzer policy generation
```

---

## Common Pitfalls & Best Practices

### 🚨 Pitfall 1: "Administrator for Everyone"

**Problem:** Giving everyone AdministratorAccess because it's easier.

**Solution:**
```bash
# Instead of this:
aws iam attach-user-policy --user-name developer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Do this (example for EC2/S3 developer):
aws iam attach-user-policy --user-name developer \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam attach-user-policy --user-name developer \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```

### 🚨 Pitfall 2: Hardcoded Credentials in Code

**Problem:**
```python
# DON'T DO THIS!
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Solution:**
```python
# Use the SDK's default credential chain
import boto3

# Automatically uses IAM role if on EC2
# Or uses AWS CLI configured credentials locally
s3 = boto3.client('s3')
```

### 🚨 Pitfall 3: Never Rotating Access Keys

**Problem:** Access keys from 2019 still active.

**Solution:**
```bash
# Rotate keys every 90 days
# 1. Create new key
aws iam create-access-key --user-name john-developer

# 2. Update applications with new key
# 3. Test everything works
# 4. Deactivate old key
aws iam update-access-key \
  --user-name john-developer \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive

# 5. After 24 hours, delete old key
aws iam delete-access-key \
  --user-name john-developer \
  --access-key-id AKIAIOSFODNN7EXAMPLE
```

### ✅ Best Practice 1: Tag Everything

```bash
# Tag users, roles, and policies for better organization
aws iam tag-user \
  --user-name john-developer \
  --tags Key=Department,Value=Engineering Key=Environment,Value=Production

# Later, find all engineering resources
aws iam list-users --query 'Users[?Tags[?Key==`Department` && Value==`Engineering`]]'
```

### ✅ Best Practice 2: Use AWS Organizations for Multi-Account

```
Root Organization
│
├── Production Account
│   ├── Workload 1
│   └── Workload 2
│
├── Development Account
│   └── All dev resources
│
└── Security Account
    ├── CloudTrail logs
    └── GuardDuty
```

This isolates blast radius - a compromised dev account can't touch production.

### ✅ Best Practice 3: Implement Break-Glass Procedures

Create an emergency access role with clear documentation:

```bash
# Create break-glass role
aws iam create-role \
  --role-name EmergencyAccess \
  --assume-role-policy-document file://emergency-trust.json

# Attach full access
aws iam attach-role-policy \
  --role-name EmergencyAccess \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Document clearly: "Only use in production emergencies"
# Require MFA to assume
# Alert security team when used
```

---

## Quick Reference Commands

### User Management
```bash
# List all users
aws iam list-users

# Create user
aws iam create-user --user-name newuser

# Delete user
aws iam delete-user --user-name olduser

# Check user's policies
aws iam list-attached-user-policies --user-name username
aws iam list-user-policies --user-name username
```

### Policy Management
```bash
# List managed policies
aws iam list-policies --scope Local

# Get policy content
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --version-id v1

# Simulate policy (before applying)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/testuser \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::mybucket/*
```

### Role Management
```bash
# List roles
aws iam list-roles

# Assume a role (get temporary credentials)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name my-session

# Check who you are
aws sts get-caller-identity
```

### Auditing
```bash
# Generate credential report
aws iam generate-credential-report
aws iam get-credential-report --output text | base64 -d > report.csv

# Check last activity for user
aws iam get-user --user-name username
```

---

## References

### Official AWS Documentation
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM Policy Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html)
- [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/)

### Tools & Resources
- **AWS IAM Policy Simulator**: Test policies before deployment
  - https://policysim.aws.amazon.com/
- **Parliament**: IAM policy linter by Duo Security
  - https://github.com/duo-labs/parliament
- **CloudMapper**: Visualize your AWS environment
  - https://github.com/duo-labs/cloudmapper
- **Prowler**: AWS security best practices assessment tool
  - https://github.com/prowler-cloud/prowler

### Security Frameworks & Standards
- **CIS AWS Foundations Benchmark**: Industry-standard security baseline
- **AWS Well-Architected Framework**: Security pillar guidelines
- **NIST Cybersecurity Framework**: Comprehensive security standards

---

## Advanced Topics

### Cross-Account Access Patterns

When you need resources in Account A to access Account B:

```
Account A (Production)          Account B (Shared Services)
┌─────────────────┐            ┌─────────────────┐
│                 │            │                 │
│  EC2 Instance   │            │   S3 Bucket     │
│  with Role      │───────────►│   with Policy   │
│                 │  AssumeRole│                 │
└─────────────────┘            └─────────────────┘
```

**Account B (Resource Account)** - S3 Bucket Policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/ProductionAppRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::shared-data-bucket/*"
    }
  ]
}
```

**Account A (Accessing Account)** - IAM Role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::222222222222:role/SharedServicesRole"
    }
  ]
}
```

### Service Control Policies (SCPs)

SCPs work at the organization level - think of them as the ultimate permission boundary:

```
AWS Organization
│
├─ SCP: DenyRootAccount (applies to ALL accounts)
├─ SCP: DenyRegionRestriction (only allow us-east-1, eu-west-1)
│
└─ Production OU
   ├─ SCP: DenyDangerousActions (prevent data deletion)
   │
   ├─ Account 1
   └─ Account 2
```

Example SCP to deny leaving organization:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "organizations:LeaveOrganization"
      ],
      "Resource": "*"
    }
  ]
}
```

### Identity Federation

Instead of creating IAM users for everyone, federate with your existing identity provider:

```
Corporate Identity Provider          AWS
(Azure AD, Okta, Google)
┌─────────────────┐                ┌─────────────────┐
│                 │                │                 │
│  User logs in   │───────────────►│  SAML/OIDC      │
│  with corp ID   │    Assertion   │  Identity       │
│                 │                │  Provider       │
└─────────────────┘                └────────┬────────┘
                                            │
                                            ▼
                                   ┌─────────────────┐
                                   │  IAM Role       │
                                   │  Assumed        │
                                   │  (Temporary)    │
                                   └─────────────────┘
```

Setup AWS SSO (now called IAM Identity Center):
```bash
# Enable through console, then assign users/groups to accounts
# Users access via https://mycompany.awsapps.com/start
```

### Session Policies

Fine-tune permissions when assuming a role:

```bash
# Assume role with additional restrictions
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/DeveloperRole \
  --role-session-name dev-session \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "s3:DeleteBucket",
        "Resource": "*"
      }
    ]
  }'
```

---

## Real-World Scenarios

### Scenario 1: Developer Needs Temporary Production Access

**Problem**: Developer needs to debug production issue but shouldn't have standing access.

**Solution**: Time-limited role assumption with approval

```bash
#!/bin/bash
# emergency-access.sh

# 1. Developer requests access (tracked in ticket system)
# 2. Manager approves
# 3. Script grants temporary access

DEVELOPER_USER="arn:aws:iam::123456789012:user/jane-developer"
DURATION=3600  # 1 hour

# Create temporary credentials
TEMP_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/ProductionDebugRole \
  --role-session-name "emergency-$(date +%s)" \
  --duration-seconds $DURATION \
  --output json)

# Extract credentials
export AWS_ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r '.Credentials.SessionToken')

# Log the access
echo "$(date): Emergency access granted to jane-developer" >> /var/log/emergency-access.log

# Send alert
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:123456789012:security-alerts \
  --message "Emergency production access granted to jane-developer for 1 hour"

echo "Access granted for 1 hour. Credentials expire at:"
echo $TEMP_CREDS | jq -r '.Credentials.Expiration'
```

### Scenario 2: Third-Party Vendor Needs Access

**Problem**: External auditor needs read-only access to specific resources.

**Solution**: External ID trust policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::999999999999:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        }
      }
    }
  ]
}
```

The external ID prevents the "confused deputy" problem - ensures the vendor can only access your account, not someone else's.

### Scenario 3: Lambda Function Needs DynamoDB Access

**Problem**: Serverless function needs to read/write to DynamoDB table.

**Solution**: Function-specific execution role

```bash
# 1. Create trust policy for Lambda
cat > lambda-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# 2. Create the role
aws iam create-role \
  --role-name MyLambdaDynamoDBRole \
  --assume-role-policy-document file://lambda-trust.json

# 3. Create custom policy (least privilege)
cat > lambda-dynamodb-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyAppTable"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF

# 4. Create and attach policy
aws iam create-policy \
  --policy-name MyLambdaDynamoDBPolicy \
  --policy-document file://lambda-dynamodb-policy.json

aws iam attach-role-policy \
  --role-name MyLambdaDynamoDBRole \
  --policy-arn arn:aws:iam::123456789012:policy/MyLambdaDynamoDBPolicy

# 5. Deploy Lambda with role
aws lambda create-function \
  --function-name my-function \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/MyLambdaDynamoDBRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip
```

---

## Incident Response Playbook

### When an Access Key is Compromised

**Act Fast - Minutes Matter!**

```bash
# STEP 1: IMMEDIATE - Deactivate the key (within 60 seconds)
aws iam update-access-key \
  --user-name compromised-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive

# STEP 2: Assess damage (check CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%S) \
  --max-results 100

# STEP 3: Check for unauthorized resources
# Look for new EC2 instances (crypto mining)
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,LaunchTime,InstanceType]'

# Look for unusual regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "Checking $region..."
  aws ec2 describe-instances --region $region --query 'Reservations[*].Instances[*].[InstanceId]' --output text
done

# STEP 4: Revoke all sessions for the user
aws iam put-user-policy \
  --user-name compromised-user \
  --policy-name DenyAllPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }'

# STEP 5: Delete the compromised key
aws iam delete-access-key \
  --user-name compromised-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE

# STEP 6: Contact AWS Support if needed
# Open a support case under "Account and Billing Support"

# STEP 7: Document everything for post-mortem
```

### Post-Incident Checklist

- [ ] Timeline of events documented
- [ ] All unauthorized resources terminated
- [ ] New access keys generated (if user is legitimate)
- [ ] Root cause identified (how was key exposed?)
- [ ] Security controls improved
- [ ] Team trained on findings
- [ ] Notify affected parties if data breach occurred

---

## Testing Your IAM Security

### Security Testing Checklist

Run these tests quarterly:

```bash
#!/bin/bash
# iam-security-tests.sh

echo "=== IAM Security Tests ==="
echo ""

# Test 1: Can anyone assume admin role without MFA?
echo "Test 1: MFA enforcement for admin role"
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/AdminRole \
  --role-session-name test-no-mfa 2>&1 | grep -q "MultiFactorAuthentication"
if [ $? -eq 0 ]; then
  echo "✅ PASS: MFA required"
else
  echo "❌ FAIL: MFA not required!"
fi

# Test 2: Can regular user access root-level resources?
echo "Test 2: Root resource protection"
aws iam list-users --profile regular-user 2>&1 | grep -q "AccessDenied"
if [ $? -eq 0 ]; then
  echo "✅ PASS: Regular users cannot list all IAM users"
else
  echo "❌ FAIL: Regular users have too much access!"
fi

# Test 3: CloudTrail enabled and logging?
echo "Test 3: CloudTrail status"
TRAIL_STATUS=$(aws cloudtrail get-trail-status --name my-security-trail --query 'IsLogging' --output text)
if [ "$TRAIL_STATUS" = "True" ]; then
  echo "✅ PASS: CloudTrail is logging"
else
  echo "❌ FAIL: CloudTrail not logging!"
fi

# Test 4: Any access keys older than 90 days?
echo "Test 4: Access key age"
OLD_KEYS=$(aws iam get-credential-report --output text | base64 -d | awk -F',' 'NR>1 {print $1,$11}' | while read user date; do
  if [ "$date" != "N/A" ]; then
    age=$(( ($(date +%s) - $(date -d "$date" +%s)) / 86400 ))
    if [ $age -gt 90 ]; then
      echo "$user"
    fi
  fi
done)

if [ -z "$OLD_KEYS" ]; then
  echo "✅ PASS: No access keys older than 90 days"
else
  echo "❌ FAIL: Old access keys found: $OLD_KEYS"
fi

# Test 5: Root account usage in last 30 days?
echo "Test 5: Root account usage"
ROOT_USAGE=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S) \
  --query 'Events[0]' --output text)

if [ -z "$ROOT_USAGE" ]; then
  echo "✅ PASS: No root account usage in last 30 days"
else
  echo "❌ FAIL: Root account was used!"
fi

echo ""
echo "=== End of Tests ==="
```

---

## Cost Optimization Tips

IAM itself is free, but poor IAM practices can cost you:

### Monitor for Unauthorized Resources

```bash
# Script to find expensive resources in unusual regions
#!/bin/bash
# cost-anomaly-detector.sh

NORMAL_REGIONS="us-east-1 eu-west-1"
ALL_REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for region in $ALL_REGIONS; do
  if [[ ! " $NORMAL_REGIONS " =~ " $region " ]]; then
    echo "Checking unusual region: $region"
    
    # Check for EC2 instances
    instances=$(aws ec2 describe-instances --region $region \
      --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,LaunchTime]' \
      --output text)
    
    if [ ! -z "$instances" ]; then
      echo "⚠️  ALERT: Instances found in $region:"
      echo "$instances"
    fi
  fi
done
```

### Budget Alerts for IAM Actions

Create a CloudWatch alarm for expensive operations:

```bash
# Alert when someone creates large instances
aws cloudwatch put-metric-alarm \
  --alarm-name large-instance-creation \
  --alarm-description "Alert on large EC2 instance creation" \
  --metric-name RunInstancesEvents \
  --namespace CustomMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold
```

---

## Compliance Mapping

### Common Compliance Requirements

| Requirement | IAM Control |
|-------------|-------------|
| SOC 2 - Access Control | MFA, least privilege, regular access reviews |
| PCI DSS - Requirement 7 | Role-based access control, permission boundaries |
| HIPAA - Access Management | CloudTrail logging, IAM Access Analyzer |
| GDPR - Data Protection | Encryption, IAM policies limiting data access |
| ISO 27001 - Access Control | Regular audits, MFA, access reviews |

### Generating Compliance Reports

```bash
# Generate a compliance report for auditors
#!/bin/bash
# compliance-report.sh

cat > compliance-report.md <<EOF
# AWS IAM Compliance Report
Generated: $(date)

## Access Control (IAM)
EOF

# MFA Status
echo "### Multi-Factor Authentication" >> compliance-report.md
aws iam get-credential-report --output text | base64 -d | \
  awk -F',' 'NR>1 {print "- User: "$1", MFA: "$4}' >> compliance-report.md

# Active Users
echo "" >> compliance-report.md
echo "### Active Users (Last 90 Days)" >> compliance-report.md
aws iam list-users --query 'Users[*].[UserName]' --output text | while read user; do
  last=$(aws iam get-user --user-name "$user" --query 'User.PasswordLastUsed' --output text 2>/dev/null)
  if [ ! -z "$last" ]; then
    echo "- $user: Last activity $last" >> compliance-report.md
  fi
done

# CloudTrail Status
echo "" >> compliance-report.md
echo "### Audit Logging (CloudTrail)" >> compliance-report.md
aws cloudtrail describe-trails --query 'trailList[*].[Name,IsLogging]' --output text >> compliance-report.md

echo "Report generated: compliance-report.md"
```

---

## Conclusion

IAM security isn't a one-time setup - it's an ongoing practice. Remember the key principles:

1. **Trust but verify**: Use roles, but monitor everything
2. **Least privilege always**: Start with nothing, add only what's needed
3. **Defense in depth**: MFA + permission boundaries + CloudTrail
4. **Automate reviews**: Weekly audits, quarterly deep dives
5. **Incident readiness**: Have a playbook before you need it

The tools are there, the documentation exists, but security ultimately comes down to discipline and attention to detail. Make IAM review part of your team's culture, not a checkbox exercise.

Stay secure! 🔒

---

## Glossary

- **IAM**: Identity and Access Management
- **MFA**: Multi-Factor Authentication
- **STS**: Security Token Service (provides temporary credentials)
- **ARN**: Amazon Resource Name (unique identifier for AWS resources)
- **SCP**: Service Control Policy (organization-level permissions)
- **SAML**: Security Assertion Markup Language (federation protocol)
- **OIDC**: OpenID Connect (modern federation protocol)
- **Permission Boundary**: Maximum permissions an identity can have
- **Trust Policy**: Defines who can assume a role
- **Principal**: Entity that can perform actions (user, role, service)
- **Resource Policy**: Policy attached to a resource (like S3 bucket)

---

*Last Updated: November 2025*  
*Author: Purushotham Muktha*

*For questions or updates, contact: Owner of the page repo*

