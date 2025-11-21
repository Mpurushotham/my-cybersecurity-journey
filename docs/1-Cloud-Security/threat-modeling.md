

# Comprehensive Guide to Threat Modeling Frameworks

## Table of Contents
1. [Introduction to Threat Modeling](#introduction)
2. [STRIDE Framework](#stride)
3. [PASTA Framework](#pasta)
4. [DREAD Framework](#dread)
5. [Additional Frameworks](#additional)
6. [Framework Comparison](#comparison)      
7. [Implementation Guide](#implementation)
8. [Real-World Use Cases](#use-cases)

---


## **What's Included:**

### 📚 **Complete Framework Coverage**
- **STRIDE** - Microsoft's 6-category threat model with detailed examples
- **PASTA** - 7-stage risk-centric methodology  
- **DREAD** - Quantitative risk scoring system
- **LINDDUN** - Privacy-focused threat modeling
- **Attack Trees** - Visual attack path analysis
- **OWASP Top 10** - Web application security risks
- **MITRE ATT&CK** - Real-world adversary tactics

### 📊 **Visual Flow Diagrams**
- Architecture diagrams for each use case
- Data flow diagrams (DFDs)
- Attack trees with cost/time/skill analysis
- Process flows for each framework
- Risk heat maps and scoring matrices
- Defense-in-depth layer visualizations

### 🏢 **5 Real-World Use Cases**

1. **E-Commerce Platform** - Credential stuffing, payment security, DDoS protection
2. **Healthcare Patient Portal** - HIPAA compliance, insider threats, privacy protection
3. **Fintech Mobile Banking** - Mobile security, SIM swap attacks, biometric authentication
4. **IoT Smart Home** - Physical security, Z-Wave attacks, camera privacy
5. **SaaS Collaboration Platform** - Supply chain security, zero trust, insider threats

### 📖 **Practical Implementation Guide**
- 7-phase implementation roadmap
- Team formation and roles
- Documentation templates
- Risk assessment matrices
- Mitigation planning strategies
- Continuous monitoring processes

### 💡 **Key Features**
- Framework comparison matrix for selection
- Hybrid approach recommendations
- ROI calculations from real cases
- Compliance mappings (GDPR, HIPAA, PCI-DSS, SOC 2)
- Tool recommendations
- Quick reference cheat sheets

> *Each use case demonstrates measurable business impact with specific metrics like 90%+ fraud reduction, prevented breaches, and ROI calculations ranging from 92% to 1,200%.*

>[!TIP] The guide is structured as a complete reference document that can be used for training, implementation, or as an ongoing resource for security teams.

-----

## Introduction to Threat Modeling {#introduction}

### What is Threat Modeling?

Threat modeling is a structured approach to identifying, quantifying, and addressing security threats in systems and applications. It enables organizations to think like attackers and discover vulnerabilities before they can be exploited.

### Why Threat Modeling Matters

- **Proactive Security**: Identifies risks during design phase, not after deployment
- **Cost Reduction**: Fixing vulnerabilities early is 60-100x cheaper than post-production
- **Compliance**: Meets regulatory requirements (GDPR, HIPAA, PCI-DSS)
- **Risk Prioritization**: Focuses resources on the most critical threats
- **Stakeholder Communication**: Creates shared understanding of security posture

### When to Perform Threat Modeling

- During system architecture and design
- Before major feature releases
- After significant infrastructure changes
- During security audits
- When integrating third-party systems

---

## STRIDE Framework {#stride}

### Overview

STRIDE, developed by Microsoft in 1999, is the most widely adopted threat modeling framework. It categorizes threats into six types, providing comprehensive coverage during the design phase.

### The STRIDE Categories

#### 1. **Spoofing Identity**
- **Definition**: Impersonating a user, system, or component to gain unauthorized access
- **Examples**:
  - Stolen credentials or session tokens
  - Email phishing with fake sender addresses
  - Man-in-the-middle attacks
  - IP address spoofing
- **Mitigations**:
  - Multi-factor authentication (MFA)
  - Digital certificates and signatures
  - Secure session management
  - Mutual authentication protocols

#### 2. **Tampering with Data**
- **Definition**: Unauthorized modification of data in transit or at rest
- **Examples**:
  - SQL injection attacks modifying database records
  - Intercepting and altering API requests
  - Modifying configuration files
  - Changing application binaries
- **Mitigations**:
  - Input validation and sanitization
  - Digital signatures and checksums
  - Encryption (TLS/SSL for transit, AES for rest)
  - Immutable infrastructure patterns

#### 3. **Repudiation**
- **Definition**: Denying performing an action without the ability to prove otherwise
- **Examples**:
  - User denies making a purchase
  - Administrator denies deleting critical data
  - Lack of transaction logs
  - Missing audit trails
- **Mitigations**:
  - Comprehensive logging and monitoring
  - Non-repudiation mechanisms (digital signatures)
  - Blockchain for immutable records
  - Tamper-evident audit logs

#### 4. **Information Disclosure**
- **Definition**: Exposing information to unauthorized individuals
- **Examples**:
  - Database dumps with sensitive customer data
  - Exposed API keys in public repositories
  - Verbose error messages revealing system details
  - Unencrypted backups
- **Mitigations**:
  - Data classification and encryption
  - Principle of least privilege
  - Secure error handling
  - Data loss prevention (DLP) tools

#### 5. **Denial of Service (DoS)**
- **Definition**: Making a system or service unavailable to legitimate users
- **Examples**:
  - Distributed DDoS attacks overwhelming servers
  - Resource exhaustion attacks
  - Application-layer attacks (slowloris)
  - Logical bombs in code
- **Mitigations**:
  - Rate limiting and throttling
  - Load balancing and redundancy
  - CDN and DDoS protection services
  - Resource quotas and circuit breakers

#### 6. **Elevation of Privilege**
- **Definition**: Gaining unauthorized higher-level permissions
- **Examples**:
  - Exploiting buffer overflows to gain root access
  - SQL injection to access admin functions
  - Privilege escalation through misconfigured permissions
  - Exploiting insecure direct object references
- **Mitigations**:
  - Role-based access control (RBAC)
  - Principle of least privilege
  - Regular security patching
  - Secure coding practices

### STRIDE Process Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    STRIDE Process Flow                       │
└─────────────────────────────────────────────────────────────┘

Step 1: Create Architecture Diagram
    ↓
┌─────────────────────────────────────┐
│  • Identify components              │
│  • Map data flows                   │
│  • Define trust boundaries          │
│  • Note external dependencies       │
└─────────────────────────────────────┘
    ↓
Step 2: Identify Threats Using STRIDE
    ↓
┌─────────────────────────────────────┐
│  For each component/data flow:      │
│  S - Can identity be spoofed?       │
│  T - Can data be tampered?          │
│  R - Can actions be repudiated?     │
│  I - Can info be disclosed?         │
│  D - Can service be denied?         │
│  E - Can privilege be elevated?     │
└─────────────────────────────────────┘
    ↓
Step 3: Document Threats
    ↓
┌─────────────────────────────────────┐
│  • Threat description               │
│  • Affected component               │
│  • STRIDE category                  │
│  • Attack vector                    │
└─────────────────────────────────────┘
    ↓
Step 4: Identify Mitigations
    ↓
┌─────────────────────────────────────┐
│  • Existing controls                │
│  • Required controls                │
│  • Implementation plan              │
└─────────────────────────────────────┘
    ↓
Step 5: Validate & Review
```

### STRIDE-per-Element Approach

Different system elements face different threat categories:

| Element Type | Applicable STRIDE Threats |
|-------------|---------------------------|
| **External Entity** | S (Spoofing), R (Repudiation) |
| **Process** | S, T, R, I, D, E (All) |
| **Data Store** | T, R, I, D |
| **Data Flow** | T, I, D |
| **Trust Boundary** | All threats apply at boundaries |

### Example: E-Commerce Application

**Scenario**: Online shopping platform with user accounts, payment processing, and inventory management.

```
Architecture Diagram:
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Browser    │◄───────►│ Web Server   │◄───────►│  Database    │
│  (Customer)  │   HTTPS │  (TLS)       │   SQL   │  (Customer   │
└──────────────┘         └──────────────┘         │   Data)      │
                                ↕                  └──────────────┘
                         ┌──────────────┐
                         │  Payment     │
                         │  Gateway     │
                         └──────────────┘
```

**STRIDE Analysis**:

1. **Spoofing**: Attacker impersonates legitimate user
   - *Threat*: Stolen session cookies used to access accounts
   - *Mitigation*: Implement MFA, secure session tokens, IP validation

2. **Tampering**: Attacker modifies product prices in cart
   - *Threat*: Client-side price manipulation before checkout
   - *Mitigation*: Server-side price validation, signed tokens

3. **Repudiation**: Customer denies placing an order
   - *Threat*: No proof of transaction authorization
   - *Mitigation*: Email confirmations, digital receipts, audit logs

4. **Information Disclosure**: Credit card data exposed
   - *Threat*: Database breach reveals payment information
   - *Mitigation*: PCI-DSS compliance, tokenization, encryption

5. **Denial of Service**: Site overwhelmed during Black Friday
   - *Threat*: DDoS attack makes site unavailable
   - *Mitigation*: CDN, rate limiting, auto-scaling infrastructure

6. **Elevation of Privilege**: User gains admin access
   - *Threat*: SQL injection grants unauthorized admin rights
   - *Mitigation*: Parameterized queries, RBAC, input validation

---

## PASTA Framework {#pasta}

### Overview

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric, seven-stage methodology that bridges the gap between business objectives and technical security controls by simulating real-world attacks.

### The Seven Stages

#### Stage 1: Define Objectives (DO)
**Purpose**: Align security efforts with business goals

**Activities**:
- Identify business objectives and compliance requirements
- Define security and privacy goals
- Establish success criteria
- Determine impact tolerance levels

**Deliverables**:
- Business impact analysis
- Compliance requirements matrix
- Risk tolerance statement

**Example**: For a healthcare app, objectives might include HIPAA compliance, protecting patient privacy, and maintaining 99.9% availability.

#### Stage 2: Define Technical Scope (DTS)
**Purpose**: Understand the technical environment

**Activities**:
- Document application architecture
- Identify technology stack and dependencies
- Map network topology
- Catalog assets and data flows

**Deliverables**:
- Architecture diagrams
- Asset inventory
- Network maps
- Technology stack documentation

**Example**: Cloud-based healthcare app using AWS, React frontend, Node.js backend, PostgreSQL database, Redis cache.

#### Stage 3: Application Decomposition (AD)
**Purpose**: Break down the application into analyzable components

**Activities**:
- Identify entry and exit points
- Define trust boundaries
- Document authentication and authorization mechanisms
- Map data flows and transformations

**Deliverables**:
- Data flow diagrams (DFDs)
- Trust boundary maps
- Component interaction models

**Example DFD**:
```
┌─────────────┐        ┌─────────────┐        ┌─────────────┐
│   Patient   │───1───►│   Portal    │───2───►│     API     │
│   (User)    │◄───8───│  (React)    │◄───7───│  (Node.js)  │
└─────────────┘        └─────────────┘        └─────────────┘
                                                      │
                                                   3  │  6
                                                      ↓
                                              ┌─────────────┐
                                              │  Database   │
                                              │ (PostgreSQL)│
                                              └─────────────┘
                                                      ↕
                                                   4  │  5
                                              ┌─────────────┐
                                              │    Cache    │
                                              │   (Redis)   │
                                              └─────────────┘

Data Flow Legend:
1. Patient submits health record
2. Portal sends encrypted data to API
3. API writes to database
4. Database updates cache
5. Cache returns data
6. API retrieves patient data
7. API sends to portal
8. Portal displays to patient
```

#### Stage 4: Threat Analysis (TA)
**Purpose**: Identify potential threats using intelligence sources

**Activities**:
- Review threat intelligence feeds
- Analyze industry-specific threats
- Study attacker motivations and capabilities
- Reference frameworks (MITRE ATT&CK, CAPEC)

**Deliverables**:
- Threat actor profiles
- Threat scenario library
- Attack pattern catalog

**Example Threats for Healthcare App**:
- Ransomware targeting patient records
- Insider threats from disgruntled employees
- Nation-state actors seeking medical research data
- Financially motivated cybercriminals selling PHI

#### Stage 5: Vulnerability Analysis (VA)
**Purpose**: Identify weaknesses that could be exploited

**Activities**:
- Perform automated vulnerability scanning
- Conduct code reviews
- Analyze configuration weaknesses
- Review third-party dependencies

**Deliverables**:
- Vulnerability assessment report
- CVE mappings
- Security gap analysis

**Example Vulnerabilities**:
- Outdated SSL/TLS versions
- Missing security headers
- SQL injection points in legacy code
- Weak password policies

#### Stage 6: Attack Modeling (AM)
**Purpose**: Simulate how attacks could be executed

**Activities**:
- Create attack trees
- Model attack scenarios
- Simulate attack paths
- Calculate likelihood and impact

**Deliverables**:
- Attack tree diagrams
- Attack scenario playbooks
- Exploitation probability scores

**Example Attack Tree**:
```
                    Goal: Steal Patient Records
                              |
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
   Exploit Web App     Compromise Employee    Physical Access
        |                     |                     |
    ┌───┴───┐            ┌────┴────┐          ┌────┴────┐
    ↓       ↓            ↓         ↓          ↓         ↓
  SQLi   XSS Attack  Phishing  Credential  Steal    Tailgate
                                Stuffing   Laptop    into DC

Likelihood Scores:
- SQL Injection: HIGH (vulnerable endpoint found)
- XSS Attack: MEDIUM (input validation present but incomplete)
- Phishing: HIGH (no security awareness training)
- Physical Access: LOW (strong physical controls)
```

#### Stage 7: Risk & Impact Analysis (RIA)
**Purpose**: Quantify risks and prioritize remediation

**Activities**:
- Calculate risk scores (Likelihood × Impact)
- Prioritize risks by business impact
- Develop mitigation strategies
- Create remediation roadmap

**Deliverables**:
- Risk register
- Risk heat map
- Prioritized remediation plan
- Residual risk assessment

**Risk Scoring Matrix**:
```
Impact
  ↑
5 │  M    H    H    C    C
4 │  M    M    H    H    C
3 │  L    M    M    H    H
2 │  L    L    M    M    H
1 │  L    L    L    M    M
  └─────────────────────────→
    1    2    3    4    5  Likelihood

L = Low Risk (1-4)
M = Medium Risk (5-9)
H = High Risk (10-16)
C = Critical Risk (17-25)
```

### PASTA Complete Flow

```
┌──────────────────────────────────────────────────────────────┐
│                    PASTA Methodology Flow                     │
└──────────────────────────────────────────────────────────────┘

Stage 1: Define Objectives
    │  • Business goals
    │  • Compliance requirements
    ↓  • Risk tolerance

Stage 2: Define Technical Scope
    │  • Architecture
    │  • Technology stack
    ↓  • Assets & dependencies

Stage 3: Application Decomposition
    │  • Data flows
    │  • Trust boundaries
    ↓  • Entry/exit points

Stage 4: Threat Analysis
    │  • Threat intelligence
    │  • Attacker profiles
    ↓  • Attack patterns

Stage 5: Vulnerability Analysis
    │  • Vulnerability scanning
    │  • Code review
    ↓  • Config analysis

Stage 6: Attack Modeling
    │  • Attack trees
    │  • Simulation
    ↓  • Exploitation paths

Stage 7: Risk & Impact Analysis
    │  • Risk scoring
    │  • Prioritization
    ↓  • Remediation plan

Implementation & Monitoring
```

---

## DREAD Framework {#dread}

### Overview

DREAD is a quantitative risk assessment model that scores threats based on five criteria. While Microsoft deprecated it due to subjectivity concerns, many organizations still use it for prioritization.

### The DREAD Criteria

#### 1. **Damage Potential**
How much damage could be caused if the threat is realized?

**Scoring Scale (0-10)**:
- **0-2**: Minimal damage, minor inconvenience
- **3-5**: Limited damage to individual users
- **6-8**: Significant damage, data loss, or service disruption
- **9-10**: Complete system compromise, massive data breach

**Example**: SQL injection allowing full database access = 10

#### 2. **Reproducibility**
How easy is it to reproduce the attack?

**Scoring Scale (0-10)**:
- **0-2**: Extremely difficult, requires specific conditions
- **3-5**: Difficult, requires some expertise
- **6-8**: Easy to reproduce with documentation
- **9-10**: Trivial, works every time

**Example**: Publicly known vulnerability with PoC code = 9

#### 3. **Exploitability**
How much effort is required to launch the attack?

**Scoring Scale (0-10)**:
- **0-2**: Requires advanced skills, custom tools, insider access
- **3-5**: Requires moderate skill level
- **6-8**: Requires basic skills, available tools
- **9-10**: No skill required, automated tools available

**Example**: Cross-site scripting with automated scanner = 8

#### 4. **Affected Users**
How many users would be impacted?

**Scoring Scale (0-10)**:
- **0-2**: Single user or very small subset
- **3-5**: Small group of users
- **6-8**: Significant portion of user base
- **9-10**: All users affected

**Example**: Authentication bypass affecting all users = 10

#### 5. **Discoverability**
How easy is it for an attacker to discover the vulnerability?

**Scoring Scale (0-10)**:
- **0-2**: Extremely difficult, requires source code access
- **3-5**: Difficult, requires detailed analysis
- **6-8**: Easy to discover with tools
- **9-10**: Obvious, publicly documented

**Example**: Default credentials in documentation = 10

### DREAD Risk Calculation

**Formula**: Risk Score = (D + R + E + A + D) / 5

**Risk Levels**:
- **0-3**: Low Risk
- **4-6**: Medium Risk
- **7-8**: High Risk
- **9-10**: Critical Risk

### DREAD Scoring Example

**Scenario**: Unencrypted API exposing user personal data

| Criterion | Score | Justification |
|-----------|-------|---------------|
| **Damage** | 8 | Exposes names, emails, addresses, phone numbers |
| **Reproducibility** | 10 | Works consistently, no special conditions |
| **Exploitability** | 9 | Simple HTTP request, no authentication needed |
| **Affected Users** | 10 | All registered users (100,000+) |
| **Discoverability** | 7 | Found through basic API testing |
| **Total Risk** | **8.8** | **CRITICAL** |

**Mitigation Priority**: Immediate action required

### DREAD Comparison Matrix

```
┌────────────────────────────────────────────────────────────┐
│                 Threat Comparison Matrix                    │
├──────────────┬─────┬─────┬─────┬─────┬─────┬──────┬────────┤
│ Threat       │  D  │  R  │  E  │  A  │  D  │ Risk │Priority│
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ Unencrypted  │  8  │ 10  │  9  │ 10  │  7  │ 8.8  │   P0   │
│ API          │     │     │     │     │     │      │        │
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ SQL          │  9  │  8  │  7  │  9  │  6  │ 7.8  │   P1   │
│ Injection    │     │     │     │     │     │      │        │
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ XSS in       │  5  │  9  │  8  │  6  │  7  │ 7.0  │   P1   │
│ Comments     │     │     │     │     │     │      │        │
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ Weak         │  7  │  6  │  6  │  8  │  5  │ 6.4  │   P2   │
│ Password     │     │     │     │     │     │      │        │
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ Missing      │  3  │  8  │  7  │  4  │  6  │ 5.6  │   P2   │
│ CSRF Token   │     │     │     │     │     │      │        │
├──────────────┼─────┼─────┼─────┼─────┼─────┼──────┼────────┤
│ Info         │  2  │ 10  │  9  │  3  │  8  │ 6.4  │   P3   │
│ Leakage      │     │     │     │     │     │      │        │
└──────────────┴─────┴─────┴─────┴─────┴─────┴──────┴────────┘
```

### Limitations of DREAD

**Subjectivity Issues**:
- Different evaluators assign different scores
- Criteria overlap (Exploitability vs Discoverability)
- Cultural and organizational bias

**Addressing Limitations**:
- Use calibration sessions with team
- Define clear scoring guidelines
- Combine with other frameworks (STRIDE for identification, DREAD for prioritization)
- Regular reassessment as context changes

---

## Additional Frameworks {#additional}

### LINDDUN (Privacy-Focused)

LINDDUN specifically addresses privacy threats, making it essential for GDPR, CCPA, and other privacy regulation compliance.

#### The LINDDUN Categories

**1. Linkability**
- Ability to link multiple data items to the same user
- *Example*: Tracking users across sessions via fingerprinting
- *Mitigation*: Anonymization, unlinkable pseudonyms

**2. Identifiability**
- Ability to identify a user from data
- *Example*: Re-identification from anonymized datasets
- *Mitigation*: K-anonymity, differential privacy

**3. Non-repudiation**
- Inability to deny actions (sometimes a privacy threat)
- *Example*: Permanent records of browsing history
- *Mitigation*: Ephemeral messaging, data retention policies

**4. Detectability**
- Ability to detect someone's involvement
- *Example*: Metadata revealing political affiliation
- *Mitigation*: Steganography, traffic obfuscation

**5. Disclosure of Information**
- Unauthorized access to personal data
- *Example*: Medical records exposed in breach
- *Mitigation*: Encryption, access controls, DLP

**6. Unawareness**
- Lack of transparency about data processing
- *Example*: Hidden data collection in mobile apps
- *Mitigation*: Privacy notices, consent management

**7. Non-compliance**
- Violation of privacy regulations
- *Example*: Processing data without legal basis
- *Mitigation*: Privacy impact assessments, compliance audits

**LINDDUN Process Flow**:
```
1. Define System & Scope → 2. Create DFDs → 3. Map Privacy Threats
     ↓                          ↓                    ↓
4. Identify Threat Scenarios → 5. Prioritize → 6. Mitigate
```

### Attack Trees

Attack trees provide a visual, hierarchical representation of attack paths, making it easy to understand how attackers might reach their goals.

**Structure**:
- **Root**: Attacker's goal
- **Branches**: Different methods to achieve goal
- **Leaves**: Specific actions or conditions

**Example: Steal Customer Database**
```
                    Steal Customer Database
                            |
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    Network             Application         Social
    Attack              Exploit            Engineering
        |                   |                   |
    ┌───┴───┐          ┌────┴────┐         ┌───┴───┐
    │       │          │         │         │       │
  WiFi    VPN      SQL Inj   File        Phish  Bribe
  Crack   Exploit            Upload      Admin  Employee

Metrics for each path:
- Cost: $, $$, $$$, $$$$
- Time: Hours, Days, Weeks, Months
- Skill: Low, Medium, High, Expert
- Detection Risk: Low, Medium, High
```

**Analysis**:
- **Most Likely Path**: Phishing → Medium cost, Medium skill, High success
- **Highest Impact**: SQL Injection → Direct database access
- **Easiest Detection**: File Upload → Triggers security alerts

### OWASP Top 10

The OWASP Top 10 is a standard awareness document representing critical web application security risks.

**2021 Edition**:

| Rank | Threat | Description |
|------|--------|-------------|
| A01 | Broken Access Control | Restrictions on authenticated users not properly enforced |
| A02 | Cryptographic Failures | Exposing sensitive data due to weak/missing encryption |
| A03 | Injection | Hostile data sent to interpreter causing unintended commands |
| A04 | Insecure Design | Missing or ineffective control design |
| A05 | Security Misconfiguration | Incomplete/incorrect security configuration |
| A06 | Vulnerable Components | Using outdated/insecure third-party components |
| A07 | Authentication Failures | Flaws allowing identity compromise |
| A08 | Software/Data Integrity | Code/infrastructure without integrity verification |
| A09 | Logging & Monitoring | Insufficient logging enabling breach persistence |
| A10 | SSRF | Allowing application to send malicious crafted requests |

**Using OWASP Top 10**:
- Use as checklist during threat modeling
- Integrate into secure development lifecycle
- Train developers on common vulnerabilities
- Map findings to OWASP categories for reporting

### MITRE ATT&CK

MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

**Framework Structure**:
- **Tactics**: The "why" - attacker's objectives (14 categories)
- **Techniques**: The "how" - methods to achieve tactics (100+ techniques)
- **Procedures**: Specific implementations by threat groups

**ATT&CK Enterprise Matrix (Partial)**:
```
┌────────────┬────────────┬────────────┬────────────┬────────────┐
│  Initial   │ Execution  │Persistence │ Privilege  │  Defense   │
│   Access   │            │            │ Escalation │   Evasion  │
├────────────┼────────────┼────────────┼────────────┼────────────┤
│ Phishing   │ PowerShell │ Registry   │ Process    │ Obfuscated │
│            │            │ Run Keys   │ Injection  │ Files      │
├────────────┼────────────┼────────────┼────────────┼────────────┤
│ Exploit    │ Command    │ Scheduled  │ Valid      │ Indicator  │
│ Public     │ & Script   │ Task       │ Accounts   │ Removal    │
│ Facing App │ Interpreter│            │            │            │
└────────────┴────────────┴────────────┴────────────┴────────────┘
```

**Using ATT&CK**:
- Map detected techniques to ATT&CK for threat intelligence
- Design detection rules based on technique behaviors
- Assess security control coverage across matrix
- Simulate adversary behavior in red team exercises

### NIST SP 800-154

NIST Special Publication 800-154 provides a data-centric approach to threat modeling, focusing on protecting data throughout its lifecycle.

**Key Principles**:
1. **Data-Centric Focus**: Protect data, not just infrastructure
2. **Lifecycle Approach**: Creation → Storage → Use → Sharing → Archiving → Destruction
3. **Context Awareness**: Consider data sensitivity and business context

**Data States**:
- **Data at Rest**: Stored in databases, files, backups
- **Data in Transit**: Moving across networks
- **Data in Use**: Being processed by applications

**Threat Modeling Steps**:
```
1. Identify & Classify Data Assets
      ↓
2. Map Data Flows Across Lifecycle
      ↓
3. Identify Threats at Each Stage
      ↓
4. Assess Impact of Data Loss/Exposure
      ↓
5. Implement Controls Per Data Sensitivity
      ↓
6. Monitor & Review Continuously
```

---

## Framework Comparison {#comparison}

### Comparison Matrix

| Framework | Best For | Complexity | Focus Area | Team Size | Time Investment |
|-----------|----------|------------|------------|-----------|-----------------|
| **STRIDE** | General purpose, design phase | Medium | Comprehensive threat categories | 3-5 | 2-4 weeks |
| **PASTA** | Risk-centric, business alignment | High | Attack simulation, ROI | 5-10 | 4-8 weeks |
| **DREAD** | Prioritization, resource allocation | Low | Risk scoring | 2-3 | 1-2 weeks |
| **LINDDUN** | Privacy compliance, GDPR | Medium | Privacy threats | 3-5 | 2-4 weeks |
| **Attack Trees** | Visual communication, specific assets | Low-Medium | Attack path analysis | 2-4 | 1-3 weeks |
| **OWASP Top 10** | Web apps, developer education | Low | Common vulnerabilities | 2-3 | 1 week |
| **MITRE ATT&CK** | Threat intelligence, detection | High | Real-world adversary behavior | 4-8 | Ongoing |

### Framework Selection Guide

**Choose STRIDE when**:
- Starting threat modeling practice
- Need comprehensive coverage
- Working in design/architecture phase
- Team has mixed security expertise

**Choose PASTA when**:
- Need to demonstrate business value
- Want attacker-centric perspective
- Have mature security program
- Require detailed risk quantification

**Choose DREAD when**:
- Need quick threat prioritization
- Have limited time/resources
- Want quantitative risk scores
- Already identified threats (via STRIDE)

**Choose LINDDUN when**:
- Building privacy-sensitive systems
- Need GDPR/CCPA compliance
- Handling personal/sensitive data
- Privacy is competitive advantage

**Choose Attack Trees when**:
- Need executive communication
- Want to visualize attack scenarios
- Focusing on specific assets
- Performing cost-benefit analysis

**Choose OWASP Top 10 when**:
- Developing web applications
- Training developers
- Performing security reviews
- Need industry baseline

**Choose MITRE ATT&CK when**:
- Building detection capabilities
- Analyzing threat intelligence
- Conducting red team exercises
- Need adversary behavior insights

### Hybrid Approaches

Most organizations combine frameworks for comprehensive coverage:

**Common Combinations**:

1. **STRIDE + DREAD**
   - Use STRIDE to identify threats
   - Use DREAD to prioritize remediation
   - Best for resource-constrained teams

2. **PASTA + MITRE ATT&CK**
   - Use PASTA for structured analysis
   - Use ATT&CK for threat intelligence
   - Best for mature security programs

3. **STRIDE + LINDDUN**
   - Use STRIDE for security threats
   - Use LINDDUN for privacy threats
   - Best for privacy-regulated industries

4. **OWASP Top 10 + Attack Trees**
   - Use OWASP as checklist
   - Use Attack Trees to model specific scenarios
   - Best for web application security

---

## Implementation Guide {#implementation}

### Phase 1: Preparation (Week 1)

#### Step 1: Assemble the Team

**Core Team Members**:
- **Security Architect**: Leads threat modeling sessions
- **Software Architects**: Provide system design expertise
- **Developers**: Understand implementation details
- **Product Owner**: Represents business requirements
- **QA/Security Testing**: Validation perspective

**Extended Team** (as needed):
- Privacy Officer (for LINDDUN)
- Compliance Officer (for regulatory requirements)
- Network Engineer (for infrastructure threats)
- DevOps Engineer (for deployment threats)

#### Step 2: Select Framework(s)

**Decision Criteria**:
1. **System Type**: Web app, mobile app, IoT, cloud service?
2. **Regulatory Requirements**: GDPR, HIPAA, PCI-DSS?
3. **Team Maturity**: First threat model or experienced?
4. **Time Available**: Weeks or months?
5. **Stakeholder Needs**: Technical depth vs business communication?

**Recommendation Matrix**:
```
System Type          Primary Framework    Secondary Framework
───────────────────────────────────────────────────────────────
Web Application      STRIDE               OWASP Top 10
Mobile App           STRIDE               OWASP Mobile Top 10
Cloud Service        STRIDE + PASTA       MITRE ATT&CK
IoT Device           STRIDE               Attack Trees
Financial System     PASTA                DREAD
Healthcare System    STRIDE               LINDDUN
E-commerce           STRIDE + DREAD       PCI-DSS Requirements
```

#### Step 3: Gather Documentation

**Required Materials**:
- Architecture diagrams
- Network topology
- Data flow diagrams
- API specifications
- Authentication/authorization flows
- Third-party integrations
- Compliance requirements
- Previous security assessments

### Phase 2: System Modeling (Week 2-3)

#### Step 1: Create Architecture Diagram

**Key Elements to Document**:
```
┌─────────────────────────────────────────────────────────────┐
│                System Architecture Template                  │
└─────────────────────────────────────────────────────────────┘

1. External Entities (Users, Systems)
   └─ Users, Partners, Third-party APIs

2. Processes (Application Components)
   └─ Web servers, Application servers, Background jobs

3. Data Stores (Databases, Caches)
   └─ Primary DB, Read replicas, Redis, S3 buckets

4. Data Flows (Communication Paths)
   └─ APIs, Message queues, File transfers

5. Trust Boundaries
   └─ DMZ, Internal network, Cloud regions
```

**Example: Banking Application**
```
                     Internet
                        │
                        ↓
        ┌───────────────────────────────┐
        │     Trust Boundary 1: DMZ     │
        │                               │
        │  ┌─────────────────────────┐  │
        │  │  Web Application        │  │
        │  │  (React + Node.js)      │  │
        │  └─────────────────────────┘  │
        │            │                  │
        └────────────┼──────────────────┘
                     │
        ┌────────────┼──────────────────┐
        │  Trust Boundary 2: Internal   │
        │            ↓                  │
        │  ┌─────────────────────────┐  │
        │  │  API Gateway            │  │
        │  │  (Authentication)       │  │
        │  └─────────────────────────┘  │
        │            │                  │
        │     ┌──────┼──────┐           │
        │     ↓      ↓      ↓           │
        │  ┌────┐ ┌────┐ ┌────┐         │
        │  │Core│ │Pay-│ │Fraud│         │
        │  │Svc │ │ment│ │Det. │         │
        │  └────┘ └────┘ └────┘         │
        │     │      │      │            │
        └─────┼──────┼──────┼────────────┘
              ↓      ↓      ↓
        ┌─────────────────────────────┐
        │ Trust Boundary 3: Data      │
        │                             │
        │  ┌────────┐  ┌──────────┐   │
        │  │Customer│  │Transaction│   │
        │  │  DB    │  │    DB    │   │
        │  └────────┘  └──────────┘   │
        └─────────────────────────────┘
```

#### Step 2: Document Data Flows

**Data Flow Template**:
| Flow ID | Source | Destination | Data Elements | Protocol | Authentication | Encryption |
|---------|--------|-------------|---------------|----------|----------------|------------|
| DF-01 | User Browser | Web Server | Credentials | HTTPS | None (login page) | TLS 1.3 |
| DF-02 | Web Server | API Gateway | Auth token | HTTPS | JWT | TLS 1.3 |
| DF-03 | API Gateway | Core Service | User profile | Internal | mTLS | TLS 1.3 |
| DF-04 | Payment Svc | External Gateway | Card data | HTTPS | API key | TLS 1.3 + Tokenization |

#### Step 3: Identify Trust Boundaries

**Trust Boundary Checklist**:
- [ ] Internet to DMZ
- [ ] DMZ to internal network
- [ ] Between microservices
- [ ] Application to database
- [ ] Different cloud accounts/regions
- [ ] Integration with third parties
- [ ] User devices to backend
- [ ] Admin vs regular user access

### Phase 3: Threat Identification (Week 3-4)

#### Using STRIDE Methodology

**Systematic Approach for Each Component**:

**Component**: User Authentication Service

| STRIDE | Question | Threat Identified | Severity |
|--------|----------|-------------------|----------|
| **S**poofing | Can someone impersonate a user? | Session hijacking via XSS | High |
| **T**ampering | Can someone modify authentication data? | JWT token manipulation | High |
| **R**epudiation | Can users deny their actions? | Missing audit logs for login attempts | Medium |
| **I**nformation Disclosure | Can credentials be exposed? | Passwords in logs | Critical |
| **D**enial of Service | Can the service be overwhelmed? | Brute force attacks on login | High |
| **E**levation of Privilege | Can users gain unauthorized access? | Insecure direct object references | Critical |

**Threat Documentation Template**:
```
Threat ID: T-001
Title: Session Hijacking via XSS
STRIDE Category: Spoofing
Component: Web Application
Description: Attacker injects malicious JavaScript that steals session tokens
Attack Vector: Stored XSS in user profile comments
Preconditions: 
  - User input not properly sanitized
  - No Content Security Policy
Impact: Account takeover, unauthorized transactions
Likelihood: High (common vulnerability, easy to exploit)
Risk Score: 9/10 (Critical)
Existing Controls: None
Recommended Mitigations:
  1. Implement input validation and output encoding
  2. Deploy Content Security Policy
  3. Use HttpOnly and Secure flags on cookies
  4. Implement XSS detection in WAF
```

#### Using PASTA Methodology

**Stage 4 Threat Analysis Example**:

**Threat Actor Profile: Financially Motivated Cybercriminal**
```
Profile ID: TA-001
Actor Type: External, Organized Crime
Motivation: Financial gain
Skill Level: Intermediate to Advanced
Resources: Automated tools, purchased exploits, botnet access
Preferred TTPs:
  - Credential stuffing
  - SQL injection
  - Ransomware
  - Data exfiltration for sale
Historical Targets: E-commerce, financial services, healthcare
```

**Attack Scenario**:
```
Scenario ID: AS-001
Title: Credential Stuffing Leading to Account Takeover
Actor: TA-001 (Financially Motivated Cybercriminal)

Attack Steps:
1. Attacker obtains leaked credentials from dark web (100M records)
2. Develops bot to automate login attempts
3. Bypasses basic rate limiting using distributed IPs
4. Successfully compromises 2% of accounts (2M accounts)
5. Uses compromised accounts for:
   - Fraudulent purchases
   - Money laundering
   - Selling access to other criminals

Business Impact:
  - Direct Financial Loss: $5-10M
  - Customer Trust: Significant damage
  - Regulatory Fines: $2-5M (GDPR violations)
  - Recovery Costs: $3-5M
  - Total Estimated Impact: $10-30M

Likelihood: High (common attack, proven success rate)
Risk Score: CRITICAL
```

### Phase 4: Risk Assessment & Prioritization (Week 5)

#### Risk Scoring with DREAD

**Complete Risk Assessment Example**:

| Threat ID | Threat | D | R | E | A | D | Risk | Priority |
|-----------|--------|---|---|---|---|---|------|----------|
| T-001 | XSS Session Hijacking | 8 | 9 | 8 | 7 | 8 | 8.0 | P0 |
| T-002 | SQL Injection | 10 | 8 | 7 | 9 | 6 | 8.0 | P0 |
| T-003 | Credential Stuffing | 7 | 9 | 8 | 9 | 7 | 8.0 | P0 |
| T-004 | Insecure API Endpoint | 6 | 7 | 6 | 8 | 5 | 6.4 | P1 |
| T-005 | Weak Password Policy | 5 | 8 | 7 | 9 | 6 | 7.0 | P1 |
| T-006 | Missing CSRF Protection | 5 | 7 | 6 | 6 | 5 | 5.8 | P2 |
| T-007 | Information Leakage | 3 | 9 | 8 | 4 | 7 | 6.2 | P2 |
| T-008 | Outdated Dependencies | 6 | 5 | 4 | 7 | 3 | 5.0 | P2 |

**Risk Heat Map**:
```
        Impact
          ↑
Critical  │ ░░ T2  T1  T3
    9     │           
          │           
High      │     T5  T4
    6     │           
          │ T8  T6  T7
Medium    │           
    3     │           
          │           
Low       │           
    0     └─────────────────────→
          0   3   6   9   Likelihood

P0 (Critical): Immediate action (1-2 weeks)
P1 (High): Short-term action (1-2 months)
P2 (Medium): Medium-term action (3-6 months)
```

### Phase 5: Mitigation Planning (Week 6)

#### Mitigation Strategy Template

**For Each High/Critical Threat**:

**Threat T-001: XSS Session Hijacking**

| Mitigation | Type | Effort | Cost | Timeline | Owner | Status |
|------------|------|--------|------|----------|-------|--------|
| Input validation library | Preventive | Medium | Low | 2 weeks | Dev Team | Planned |
| Output encoding | Preventive | High | Low | 3 weeks | Dev Team | Planned |
| Content Security Policy | Preventive | Low | None | 1 week | Security | In Progress |
| HttpOnly cookies | Preventive | Low | None | 1 week | Dev Team | Planned |
| WAF XSS rules | Detective | Medium | Medium | 2 weeks | Security | Not Started |
| Security training | Preventive | High | Medium | Ongoing | HR/Security | Planned |

**Implementation Roadmap**:
```
Week 1-2: Quick Wins (Low Effort, High Impact)
  ├─ Enable HttpOnly and Secure cookie flags
  ├─ Deploy Content Security Policy
  └─ Activate WAF basic rules

Week 3-6: Core Mitigations
  ├─ Implement input validation framework
  ├─ Add output encoding to all user inputs
  ├─ Configure advanced WAF rules
  └─ Update session management

Week 7-12: Long-term Improvements
  ├─ Developer security training
  ├─ Automated security testing in CI/CD
  ├─ Regular penetration testing
  └─ Security code review process
```

#### Defense in Depth Strategy

**Layered Security Approach**:
```
┌──────────────────────────────────────────────────────────┐
│  Layer 7: Security Awareness & Training                  │
│  └─ User education, phishing simulations, secure coding  │
├──────────────────────────────────────────────────────────┤
│  Layer 6: Application Security                           │
│  └─ Input validation, authentication, authorization      │
├──────────────────────────────────────────────────────────┤
│  Layer 5: Data Security                                  │
│  └─ Encryption at rest, in transit, tokenization         │
├──────────────────────────────────────────────────────────┤
│  Layer 4: Infrastructure Security                        │
│  └─ Network segmentation, firewalls, IDS/IPS            │
├──────────────────────────────────────────────────────────┤
│  Layer 3: Perimeter Security                            │
│  └─ WAF, DDoS protection, VPN, load balancers          │
├──────────────────────────────────────────────────────────┤
│  Layer 2: Detection & Response                          │
│  └─ SIEM, logging, monitoring, incident response       │
├──────────────────────────────────────────────────────────┤
│  Layer 1: Physical Security                             │
│  └─ Data center access, device security                │
└──────────────────────────────────────────────────────────┘
```

### Phase 6: Documentation & Review (Week 7)

#### Required Documentation

**1. Threat Model Report**
```
Executive Summary
  ├─ System overview
  ├─ Key findings
  ├─ Risk summary
  └─ Recommended actions

Detailed Analysis
  ├─ Architecture diagrams
  ├─ Data flow diagrams
  ├─ Threat inventory (all threats identified)
  ├─ Risk assessment results
  └─ Mitigation strategies

Appendices
  ├─ Framework methodology used
  ├─ Team members and roles
  ├─ References and standards
  └─ Version history
```

**2. Risk Register**
- Living document tracking all identified threats
- Updated as threats are mitigated or new threats emerge
- Reviewed quarterly

**3. Mitigation Tracking Dashboard**
```
Status Overview:
  ┌─────────────┬────────┐
  │ Completed   │  45%   │
  │ In Progress │  30%   │
  │ Planned     │  20%   │
  │ Deferred    │   5%   │
  └─────────────┴────────┘

By Priority:
  P0: ████████░░ 80% Complete
  P1: ████░░░░░░ 40% Complete
  P2: ██░░░░░░░░ 20% Complete
```

### Phase 7: Continuous Monitoring (Ongoing)

#### When to Re-run Threat Modeling

**Triggers for Updates**:
- [ ] Major feature releases
- [ ] Architecture changes
- [ ] New third-party integrations
- [ ] Security incidents
- [ ] New threat intelligence
- [ ] Regulatory changes
- [ ] Annual review (minimum)

**Continuous Threat Modeling Process**:
```
    ┌─────────────────────────────────────────┐
    │   Continuous Threat Modeling Cycle      │
    └─────────────────────────────────────────┘
    
    Monitor → Detect → Assess → Update → Implement
       ↑                                      │
       └──────────────────────────────────────┘
       
Monitor:
  - Threat intelligence feeds
  - Vulnerability disclosures
  - Security incidents
  - System changes

Detect:
  - New threats applicable to system
  - Changes impacting threat model
  - Emerging attack patterns

Assess:
  - Impact of new threats
  - Effectiveness of controls
  - Risk score changes

Update:
  - Threat model documentation
  - Risk register
  - Mitigation plans

Implement:
  - New controls
  - Enhanced monitoring
  - Process improvements
```

---

## Real-World Use Cases {#use-cases}

### Use Case 1: E-Commerce Platform (STRIDE + DREAD)

**Company**: MegaShop Inc.
**System**: Cloud-based e-commerce platform
**Users**: 5 million customers
**Revenue**: $500M annually

#### Context

MegaShop is preparing for Black Friday and wants to ensure their platform can handle both traffic spikes and sophisticated attacks. They've experienced credential stuffing attacks in the past.

#### Threat Modeling Approach

**Framework Selection**: STRIDE for identification, DREAD for prioritization

**System Overview**:
```
        User Devices
             │
        ┌────┴────┐
        ↓         ↓
    Web App   Mobile App
        │         │
        └────┬────┘
             ↓
        CloudFlare CDN
             │
             ↓
        AWS ALB (Load Balancer)
             │
        ┌────┴────┬────────┬────────┐
        ↓         ↓        ↓        ↓
    Frontend  Product  Cart    Payment
    Service   Service  Service Service
        │         │        │        │
        └────┬────┴────┬───┴────┬───┘
             ↓         ↓        ↓
          Aurora    Redis    Stripe
           DB      Cache     API
```

#### Key Threats Identified

**1. Credential Stuffing (STRIDE: Spoofing)**
```
DREAD Score:
  Damage: 8 (Account takeover, fraudulent orders)
  Reproducibility: 10 (Automated attacks common)
  Exploitability: 9 (Tools readily available)
  Affected Users: 9 (All users with weak passwords)
  Discoverability: 8 (Login endpoint is obvious)
  Risk: 8.8 - CRITICAL
```

**Mitigations Implemented**:
- CAPTCHA after 3 failed attempts
- Device fingerprinting
- Anomaly detection (impossible travel, unusual patterns)
- Mandatory MFA for high-value accounts
- Integration with HaveIBeenPwned API
- Rate limiting: 5 attempts per IP per minute

**Results**: 94% reduction in successful account takeovers

**2. Payment Card Scraping (STRIDE: Information Disclosure)**
```
DREAD Score:
  Damage: 10 (PCI-DSS violation, massive liability)
  Reproducibility: 3 (Requires sophisticated attack)
  Exploitability: 4 (Requires finding XSS vulnerability)
  Affected Users: 10 (All paying customers)
  Discoverability: 5 (Payment flow is secure)
  Risk: 6.4 - HIGH
```

**Mitigations Implemented**:
- Stripe.js (no card data touches servers)
- Subresource Integrity (SRI) for all scripts
- Content Security Policy (CSP)
- Regular penetration testing
- Bug bounty program

**Results**: Zero card data breaches in 2 years

**3. DDoS During Black Friday (STRIDE: Denial of Service)**
```
DREAD Score:
  Damage: 9 (Lost revenue, reputation damage)
  Reproducibility: 7 (DDoS-for-hire services available)
  Exploitability: 6 (Requires resources)
  Affected Users: 10 (All users affected)
  Discoverability: 10 (Public-facing site)
  Risk: 8.4 - CRITICAL
```

**Mitigations Implemented**:
- CloudFlare DDoS protection
- Auto-scaling infrastructure (100 → 500 instances)
- Rate limiting per endpoint
- Queue-based order processing
- Graceful degradation (disable non-critical features)
- Multi-region deployment

**Results**: 99.98% uptime during Black Friday, handled 50x normal traffic

#### Business Impact

**Before Threat Modeling**:
- 3-5 security incidents per quarter
- $2M annual losses from fraud
- 2-week downtime from attacks
- Customer trust issues

**After Threat Modeling**:
- 0-1 security incidents per quarter
- $200K annual losses (90% reduction)
- Zero unplanned downtime
- NPS score increased 15 points
- **ROI**: 1,200% (considering prevented losses)

---

### Use Case 2: Healthcare Patient Portal (PASTA + LINDDUN)

**Company**: MediCare Health System
**System**: Patient portal with EHR integration
**Users**: 500,000 patients
**Compliance**: HIPAA, HITECH

#### Context

MediCare needs to comply with HIPAA while providing convenient patient access to medical records. They're particularly concerned about insider threats and privacy violations.

#### Threat Modeling Approach

**Framework Selection**: PASTA for risk-centric analysis, LINDDUN for privacy

**PASTA Stage 4: Threat Analysis**

**Threat Actor 1: Malicious Insider (Employee)**
```
Motivation: Financial (selling patient records)
Capability: Privileged access to systems
Historical Examples: 
  - 2023: Hospital employee sold 100K records for $50K
  - 2022: Nurse accessed celebrity patient records
Likelihood: MEDIUM
Impact: CATASTROPHIC
```

**Threat Actor 2: Ransomware Groups**
```
Motivation: Financial (ransomware payment + data sale)
Capability: Advanced persistent threat
Historical Examples:
  - Universal Health Services: $67M loss
  - Scripps Health: $113M loss
Likelihood: HIGH
Impact: CRITICAL
```

**PASTA Stage 6: Attack Modeling**

**Attack Scenario 1: Insider Data Exfiltration**
```
                Insider Threat Attack Tree
                          │
          ┌───────────────┼───────────────┐
          │               │               │
    Physical Access   Logical Access   Social
          │               │               │
    ┌─────┴─────┐   ┌─────┴─────┐   ┌───┴───┐
    │           │   │           │   │       │
  Steal    After  Abuse    Query  Collude Deceive
  Device   Hours  Priv.    Tool   w/Peer   User

Chosen Path: Abuse Privileged Access
Steps:
  1. Legitimate nurse logs in (authorized)
  2. Queries patient records outside assigned patients
  3. Photographs screens with personal phone
  4. Exfiltrates data over time to avoid detection
  5. Sells records on dark web

Detection Probability: 30% (without controls)
Expected Gain for Attacker: $25-50 per record
```

**LINDDUN Privacy Analysis**

**L - Linkability**: Medical records linked across different appointments
- *Risk*: Patient history reconstruction
- *Mitigation*: Pseudonymization for research purposes

**I - Identifiability**: Patient names visible in logs
- *Risk*: Unauthorized identification from audit trails
- *Mitigation*: Hash patient IDs in logs, encryption

**N - Non-repudiation**: All actions permanently logged
- *Risk*: Excessive audit trail violates privacy expectations
- *Mitigation*: Log retention policy (7 years legal requirement)

**D - Detectability**: Access patterns reveal sensitive conditions
- *Risk*: Analyzing access logs reveals HIV clinic visits
- *Mitigation*: Access obfuscation, policy controls

**D - Disclosure**: PHI exposed in multiple locations
- *Risk*: Unencrypted backups, logs with PHI
- *Mitigation*: End-to-end encryption, DLP

**U - Unawareness**: Patients don't know who accessed records
- *Risk*: Lack of transparency
- *Mitigation*: Access notification system

**N - Non-compliance**: HIPAA violations
- *Risk*: Fines up to $1.5M per violation
- *Mitigation*: Compliance framework, audits

#### Mitigations Implemented

**1. Zero Trust Architecture**
```
Traditional: Trust internal network
New Model: Verify every access

Implementation:
  ├─ Micro-segmentation of network
  ├─ Identity-based access (not network-based)
  ├─ Continuous authentication
  ├─ Least privilege access
  └─ Assume breach mentality
```

**2. User Behavior Analytics (UBA)**
```
Baseline Normal Behavior:
  - Nurse A: Accesses 15-20 patients/shift
  - Typical pattern: Sequential by room number
  - Access time: 2-5 minutes per record

Alert Triggers:
  - Accessing >50 patients in shift (3x normal)
  - Accessing patients not assigned
  - Accessing records outside shift hours
  - Accessing VIP/celebrity patients
  - Copy/paste or export actions
```

**3. Patient Access Notifications**
```
Implementation:
  - Email/SMS when record accessed
  - Details: Who, when, department
  - "Was this expected?" one-click reporting
  - Automated investigation if reported

Results:
  - 15 unauthorized access incidents detected in first month
  - 2 employees terminated
  - Deterrent effect: 80% reduction in policy violations
```

**4. Data Loss Prevention (DLP)**
```
Controls:
  - Block USB devices on workstations
  - Monitor clipboard copy of PHI
  - Watermark screens with user ID
  - Prevent screenshots (technical control)
  - Email scanning for PHI
  - Encrypted communication channels only
```

#### Business Impact

**Compliance Results**:
- Passed HIPAA audit with zero findings
- OCR (Office for Civil Rights) examination: Satisfactory
- Zero reportable breaches in 2 years

**Privacy Impact**:
- Patient satisfaction with privacy: 92%
- Patient access to their own records: 300% increase
- Privacy complaints: Reduced from 25/year to 3/year

**Financial Impact**:
- Avoided potential HIPAA fines: $1.5M+
- Insurance premium reduction: $250K/year
- Breach prevention savings: $4-7M (industry average breach cost)

---

### Use Case 3: Fintech Mobile Banking App (STRIDE + OWASP + MITRE ATT&CK)

**Company**: NeoBank Digital
**System**: Mobile-first banking application
**Users**: 2 million customers
**Assets**: $5 billion under management

#### Context

NeoBank is a digital-only bank targeting millennials. Recent increase in mobile banking fraud prompted comprehensive security review.

#### Threat Modeling Approach

**Framework Combination**:
- STRIDE: Identify threats
- OWASP Mobile Top 10: Mobile-specific vulnerabilities
- MITRE ATT&CK Mobile: Real-world attack techniques

**System Architecture**:
```
┌──────────────────────────────────────────────────────┐
│              Mobile App (iOS/Android)                 │
│  ┌────────────┬─────────────┬──────────────────┐     │
│  │ UI Layer   │Auth Module  │Transaction Module│     │
│  └────────────┴─────────────┴──────────────────┘     │
└──────────────────────────────────────────────────────┘
                        │ HTTPS + Certificate Pinning
                        ↓
┌──────────────────────────────────────────────────────┐
│                   API Gateway (AWS)                   │
│  • Rate Limiting   • JWT Validation  • WAF            │
└──────────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ↓               ↓               ↓
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│   Account   │ │  Payment    │ │   Fraud     │
│   Service   │ │  Service    │ │  Detection  │
└─────────────┘ └─────────────┘ └─────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        ↓
              ┌──────────────────┐
              │  PostgreSQL DB   │
              │  (Encrypted)     │
              └──────────────────┘
```

#### STRIDE Analysis

**Critical Threat: Man-in-the-Middle Attack**

**S - Spoofing**: Attacker impersonates banking API
- *Attack*: Fake WiFi hotspot + proxy
- *Impact*: Credentials stolen
- *Mitigation*: Certificate pinning

**T - Tampering**: Transaction amount modified in transit
- *Attack*: Intercept and modify API calls
- *Impact*: Fraudulent transfers
- *Mitigation*: TLS + request signing

**I - Information Disclosure**: Account balance revealed
- *Attack*: Network traffic interception
- *Impact*: Financial information exposed
- *Mitigation*: End-to-end encryption

#### OWASP Mobile Top 10 Analysis

**M1: Improper Platform Usage**
```
Finding: App stores sensitive data in iOS/Android logs
Risk: CRITICAL
Evidence: Transaction amounts visible in crash logs
Mitigation:
  - Disable logging in production
  - Scrub sensitive data from logs
  - Implement custom log filters
```

**M2: Insecure Data Storage**
```
Finding: PIN stored in SharedPreferences (Android) unencrypted
Risk: CRITICAL
Evidence: Rooted device can access plaintext PIN
Mitigation:
  - Use Android Keystore for cryptographic keys
  - Encrypt all sensitive local data
  - Implement Android SafetyNet/iOS jailbreak detection
```

**M3: Insecure Communication**
```
Finding: Certificate pinning not implemented
Risk: HIGH
Evidence: Traffic interceptable with Burp Suite
Mitigation:
  - Implement SSL pinning
  - Use TLS 1.3
  - Monitor for certificate changes
```

**M4: Insecure Authentication**
```
Finding: JWT tokens don't expire
Risk: CRITICAL
Evidence: Tokens valid indefinitely if not manually logged out
Mitigation:
  - Set token expiry: 15 minutes
  - Implement refresh token rotation
  - Add device binding to tokens
```

**M8: Code Tampering**
```
Finding: No anti-tampering protection
Risk: HIGH
Evidence: App repackaged with keylogger on 3rd-party store
Mitigation:
  - Code obfuscation
  - Integrity checks at runtime
  - Detect repackaging
```

#### MITRE ATT&CK Mobile Analysis

**Mapped Techniques**:

| ID | Technique | Detection | Mitigation |
|----|-----------|-----------|------------|
| MOB-T1398 | Phishing | User reporting | Security awareness training |
| MOB-T1411 | Access Call Log | Permission check | Minimize permissions |
| MOB-T1412 | Capture SMS | SMS not used for 2FA | Use authenticator app |
| MOB-T1429 | Capture Audio | Microphone permission monitoring | Minimize permissions |
| MOB-T1430 | Location Tracking | Location access logging | Request only when needed |
| MOB-T1447 | Delete Device Data | Backup verification | Cloud backup + device backup |
| MOB-T1448 | Carrier Billing Fraud | Monitor billing APIs | Rate limiting + alerts |
| MOB-T1456 | Modify System Partition | Root/jailbreak detection | Block rooted devices |
| MOB-T1461 | Lockscreen Bypass | Biometric + PIN | Device encryption |

#### Attack Scenario: SIM Swap Attack

**MITRE ATT&CK Mapping**:
```
Initial Access (MOB-T1398: Phishing)
    ↓
Social Engineering carrier support
    ↓
SIM swap executed
    ↓
Persistence (MOB-T1408: Access Stored Application Data)
    ↓
SMS-based 2FA intercepted
    ↓
Impact (MOB-T1471: Data Encrypted for Impact)
    ↓
Account takeover, fraudulent transfers
```

**Detection & Response**:
```
Detection Signals:
  1. New device login from different geolocation
  2. SIM card change detected (carrier API)
  3. Multiple failed 2FA attempts
  4. Sudden change in phone number usage patterns
  5. Customer service call requesting account changes

Automated Response:
  ├─ Freeze account immediately
  ├─ Send push notification to registered device
  ├─ Email alert with incident details
  ├─ Require video verification to unfreeze
  └─ Flag account for manual review
```

#### Comprehensive Mitigations

**1. Multi-Layered Authentication**
```
Layer 1: Knowledge Factor
  └─ PIN (6 digits minimum)

Layer 2: Possession Factor
  └─ Device binding (unique device ID)

Layer 3: Inherence Factor
  └─ Biometric (Face ID/Touch ID)

Layer 4: Behavior Factor
  └─ Typing patterns, swipe behaviors

Layer 5: Location Factor
  └─ GPS + IP validation

High-Risk Transaction:
  Requires 3+ factors + out-of-band confirmation
```

**2. Runtime Application Self-Protection (RASP)**
```
Implemented Protections:
┌─────────────────────────────────────────┐
│ Runtime Threat Detection                │
├─────────────────────────────────────────┤
│ ✓ Jailbreak/Root detection              │
│ ✓ Debugger detection                    │
│ ✓ Emulator detection                    │
│ ✓ Hook framework detection              │
│ ✓ Screen capture prevention             │
│ ✓ Keyboard logger detection             │
│ ✓ Memory tampering detection            │
│ ✓ SSL pinning bypass detection          │
└─────────────────────────────────────────┘

Action on Detection: 
  - Block app launch on compromised device
  - Alert security team
  - Require re-authentication
```

**3. Transaction Risk Scoring**
```
Risk Score Calculation:
┌─────────────────────────────────────────┐
│ Factor              Weight    Value     │
├─────────────────────────────────────────┤
│ Transaction Amount    30%     0-100     │
│ Recipient New?        20%     0/100     │
│ Time of Day          10%     0-100     │
│ Location Change      15%     0-100     │
│ Device Trust         15%     0-100     │
│ Velocity (daily)     10%     0-100     │
└─────────────────────────────────────────┘

Risk Levels:
  0-30:  Auto-approve
  31-60: Additional verification (push notification)
  61-80: Step-up authentication (biometric + PIN)
  81-100: Manual review + video call verification

Example:
  $10,000 to new recipient at 3 AM from new location
  = 30 + 20 + 10 + 15 = 75 (Step-up auth required)
```

**4. Secure Development Lifecycle Integration**
```
Development Phase → Security Activity
─────────────────────────────────────────
Requirements      → Security requirements from threat model
                   → Abuse case analysis

Design           → Security architecture review
                   → Threat modeling sessions

Development      → Secure coding standards
                   → Static analysis (SAST)
                   → Dependency scanning

Testing          → Dynamic analysis (DAST)
                   → Penetration testing
                   → Mobile security testing (MSTG)

Deployment       → Security configuration validation
                   → Certificate management

Maintenance      → Vulnerability monitoring
                   → Incident response
                   → Quarterly threat model updates
```

#### Results

**Before Threat Modeling**:
- Mobile banking fraud: $2.5M/year
- Account takeover incidents: 150/month
- Customer support fraud calls: 40% of volume
- App store rating: 3.2 stars (security concerns)

**After Threat Modeling (12 months)**:
- Mobile banking fraud: $180K/year (93% reduction)
- Account takeover incidents: 8/month (95% reduction)
- Customer support fraud calls: 5% of volume
- App store rating: 4.7 stars
- **ROI**: Investment $1.2M, Savings $2.3M = 92% ROI

**Awards & Recognition**:
- "Most Secure Mobile Banking App" - InfoSec Magazine
- Increased customer trust score by 45%
- Featured case study by OWASP

---

### Use Case 4: IoT Smart Home Platform (Attack Trees + STRIDE)

**Company**: SmartLiving Inc.
**System**: IoT hub connecting smart home devices
**Users**: 800,000 homes
**Connected Devices**: 12 million

#### Context

SmartLiving's IoT platform controls door locks, cameras, thermostats, and alarm systems. A security breach could have serious physical safety implications.

#### Threat Modeling Approach

**Framework Selection**: Attack Trees for visualization, STRIDE for comprehensive coverage

**System Architecture**:
```
┌─────────────────────────────────────────────────────┐
│           Smart Home Ecosystem                       │
└─────────────────────────────────────────────────────┘

User's Home:
┌──────────────────────────────────────────┐
│  Smart Hub (Local Controller)           │
│  ├─ Door Lock (Z-Wave)                  │
│  ├─ Camera (WiFi)                       │
│  ├─ Thermostat (Zigbee)                 │
│  ├─ Alarm System (Proprietary)          │
│  └─ Motion Sensors (Zigbee)             │
└──────────────────────────────────────────┘
            │
            │ Internet
            ↓
┌──────────────────────────────────────────┐
│  Cloud Platform (AWS)                    │
│  ├─ Device Management Service            │
│  ├─ User Authentication Service          │
│  ├─ Automation Engine                    │
│  └─ Mobile API Gateway                   │
└──────────────────────────────────────────┘
            │
            ↓
┌──────────────────────────────────────────┐
│  Mobile App (iOS/Android)                │
│  └─ Remote control and monitoring        │
└──────────────────────────────────────────┘
```

#### Attack Tree Analysis

**Primary Goal: Gain Unauthorized Access to Home**

```
                    Unlock Front Door Remotely
                            |
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   Compromise          Exploit IoT         Physical
    Cloud API          Vulnerability        Attack
        |                   |                   |
   ┌────┴────┐         ┌────┴────┐        ┌────┴────┐
   │         │         │         │        │         │
Steal    Exploit   Z-Wave   Hub     Bypass   Clone
Creds    API Bug   Replay   Exploit  Lock    RFID

Cost Analysis:
┌─────────────────┬──────┬──────┬─────────┬──────────┐
│ Attack Path     │ Cost │ Time │ Skill   │ Detection│
├─────────────────┼──────┼──────┼─────────┼──────────┤
│ Steal Creds     │ $    │ Days │ Low     │ Medium   │
│ Exploit API     │ $   │ Weeks│ High    │ Low      │
│ Z-Wave Replay   │ $$  │ Hours│ Medium  │ Very Low │
│ Hub Exploit     │ $$ │ Months│ Expert │ Very Low │
│ Physical Bypass │ $   │ Minutes│ Low   │ High     │
│ Clone RFID      │ $    │ Minutes│ Low   │ Medium   │
└─────────────────┴──────┴──────┴─────────┴──────────┘

Most Likely Attack: Z-Wave Replay Attack
  - Low detection probability
  - Medium skill requirement
  - Effective against 70% of smart locks
  - Equipment: $300 SDR (Software Defined Radio)
```

**Secondary Goal: Surveillance (Camera Access)**

```
                    Access Home Camera Feed
                            |
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    Compromise          Intercept            Network
    User Account        WiFi Traffic         Pivot
        |                   |                   |
   ┌────┴────┐         ┌────┴────┐        ┌────┴────┐
   │         │         │         │        │         │
Phishing Credential  Evil   WiFi   Compromise  Lateral
Email    Stuffing   Twin   Decrypt  Router     Movement

Risk Assessment:
  Z-Wave Replay: CRITICAL (Physical security compromise)
  Camera Access: HIGH (Privacy violation)
  Credential Theft: HIGH (Access to all devices)
  WiFi Interception: MEDIUM (Requires proximity)
```

#### STRIDE Analysis by Component

**Component 1: Smart Lock**

| STRIDE | Threat | Risk | Mitigation |
|--------|--------|------|------------|
| **S** | Attacker spoofs unlock command | Critical | Mutual authentication, command signing |
| **T** | Replay attack unlocks door | Critical | Rolling codes, timestamp validation, nonce |
| **R** | User denies unlocking door | Medium | Immutable audit log with signatures |
| **I** | Lock status exposed to neighbors | Low | Encrypted status updates |
| **D** | Jamming prevents remote unlock | High | Local backup (physical key), multiple protocols |
| **E** | Attacker gains admin access to lock | Critical | Secure boot, firmware signing, hardware security module |

**Component 2: Camera**

| STRIDE | Threat | Risk | Mitigation |
|--------|--------|------|------------|
| **S** | Fake camera added to system | High | Device certificate validation |
| **T** | Video feed manipulated | High | End-to-end encryption, integrity checks |
| **R** | Deny motion detection triggered | Medium | Tamper-evident logs |
| **I** | Video feed accessed by unauthorized party | Critical | TLS 1.3, role-based access |
| **D** | Camera overwhelmed with requests | Medium | Rate limiting, DoS protection |
| **E** | Camera firmware hacked for root access | Critical | Secure boot, automatic security updates |

**Component 3: Hub**

| STRIDE | Threat | Risk | Mitigation |
|--------|--------|------|------------|
| **S** | Rogue device impersonates hub | Critical | Hardware security module, attestation |
| **T** | Hub firmware modified | Critical | Secure boot chain, signed updates |
| **R** | Hub admin denies configuration change | Low | Comprehensive audit logs |
| **I** | Hub stores credentials in plaintext | Critical | Hardware-backed encryption |
| **D** | Hub crashes due to malformed packet | High | Input validation, watchdog timer |
| **E** | Attacker gains root access to hub | Critical | Principle of least privilege, SELinux |

#### Implemented Mitigations

**1. Defense in Depth for Door Lock**

```
Layer 1: Cloud Authentication
  ├─ OAuth 2.0 with PKCE
  ├─ Device certificate validation
  └─ Geofencing (deny unlock from >50 miles)

Layer 2: Command Authorization
  ├─ Signed unlock commands (HMAC-SHA256)
  ├─ Timestamp validation (±5 minute window)
  └─ Nonce to prevent replay

Layer 3: Device Security
  ├─ Rolling code (changes every command)
  ├─ Rate limiting (max 5 unlock attempts/hour)
  └─ Local anomaly detection

Layer 4: Physical Security
  ├─ Tamper detection sensor
  ├─ Battery backup
  └─ Physical key override

Layer 5: Monitoring & Alerting
  ├─ All unlock events logged immutably
  ├─ Push notification on every unlock
  └─ Alert on unusual patterns
```

**2. Secure Communication Architecture**

```
Mobile App ←→ Cloud ←→ Hub ←→ Devices

Mobile to Cloud:
  Protocol: HTTPS + Certificate Pinning
  Auth: JWT (15 min expiry) + Refresh Token
  Encryption: TLS 1.3

Cloud to Hub:
  Protocol: MQTT over TLS
  Auth: Client certificate + API key
  Encryption: TLS 1.3 + Payload encryption (AES-256-GCM)

Hub to Devices:
  Protocol: Device-specific (Z-Wave, Zigbee, WiFi)
  Auth: Device pairing keys
  Encryption: Protocol-native encryption + app-layer encryption

End-to-End Encryption:
  Camera video: Not accessible by SmartLiving cloud
  Encrypted on device, decrypted only on user's phone
  Key exchange: ECDH with perfect forward secrecy
```

**3. IoT-Specific Security Features**

```
Secure Boot Chain:
  ROM → Bootloader → Kernel → Application
  (signed) → (signed) → (signed) → (signed)

Firmware Updates:
  ├─ Delta updates (reduce attack surface)
  ├─ A/B partitioning (rollback on failure)
  ├─ Automatic security patches
  └─ User can defer feature updates

Device Provisioning:
  ├─ Factory certificate unique per device
  ├─ Secure pairing (SRP protocol)
  ├─ Owner attestation
  └─ Device can be factory reset only by owner

Network Isolation:
  ├─ IoT devices on separate VLAN
  ├─ Firewall rules: deny device-to-device by default
  ├─ Hub acts as gateway (no direct internet for devices)
  └─ Regular vulnerability scanning
```

**4. Incident Response for Physical Security**

```
Alert Levels:

Level 1: INFO (Normal Operation)
  - Door unlocked by authorized user during normal hours
  - Action: Log event

Level 2: WARNING (Unusual Pattern)
  - 3+ unlock attempts in 10 minutes
  - Unlock from unusual location
  - Action: Push notification to user

Level 3: ALERT (Suspicious Activity)
  - Unlock attempt after 3 failures
  - Command from unrecognized IP
  - Action: Require step-up authentication

Level 4: CRITICAL (Active Attack)
  - Replay attack detected
  - Device firmware modified
  - Tamper sensor triggered
  - Action: 
    ├─ Lock device immediately
    ├─ Send SMS + Push + Email
    ├─ Contact local authorities (if enabled)
    ├─ Activate alarm system
    └─ Notify neighbors (if Smart Neighborhood enabled)
```

#### Real Incident: Z-Wave Replay Attack Prevention

**Attack Detected**: August 2023
```
Timeline:
00:00 - Hub detects Z-Wave unlock command
00:01 - Timestamp validation fails (command from 5 hours ago)
00:01 - Nonce validation fails (nonce already used)
00:01 - REPLAY ATTACK DETECTED
00:02 - Door remains locked
00:02 - Alert sent to homeowner
00:02 - Device blacklisted temporarily
00:02 - Incident reported to security team
00:15 - Security team confirms attack
01:00 - Firmware update deployed to all hubs
12:00 - Post-incident review completed

Attack Vector:
  - Attacker captured unlock command with $300 SDR
  - Attempted to replay command 5 hours later
  - Prevented by timestamp + nonce validation
```

**Response Effectiveness**:
- Attack blocked successfully
- Zero unauthorized physical access
- Firmware update pushed within 1 hour
- User trust maintained

#### Business Impact

**Security Metrics (Year 1)**:
```
Attempted Attacks: 1,247
Successful Breaches: 0
Detection Rate: 99.8%
False Positive Rate: 0.3%
Mean Time to Detect: 1.2 seconds
Mean Time to Response: 15 seconds
```

**Customer Impact**:
- Customer trust score: 89% (industry avg: 62%)
- Premium tier adoption: 34% (+$15M ARR)
- Churn rate: 3.2% (industry avg: 12%)
- NPS score: 68 (industry avg: 35)

**Regulatory Compliance**:
- California IoT Security Law (SB-327): Compliant
- ETSI EN 303 645 (IoT security standard): Certified
- UL 2900-2-3 (IoT cybersecurity): Certified
- First consumer IoT platform with all three certifications

---

### Use Case 5: SaaS Enterprise Collaboration Platform (PASTA + MITRE ATT&CK)

**Company**: CollabSpace Enterprise
**System**: Cloud-based collaboration and file sharing
**Users**: 50,000 enterprise customers (15M end users)
**Data**: 500 petabytes

#### Context

CollabSpace serves Fortune 500 companies with sensitive intellectual property. Recent supply chain attacks in the industry prompted comprehensive threat modeling.

#### Threat Modeling Approach

**Framework Selection**: PASTA for business risk focus, MITRE ATT&CK for adversary behaviors

**PASTA Stage 1: Business Objectives**

```
Primary Objectives:
┌─────────────────────────────────────────────────────┐
│ 1. Protect customer intellectual property           │
│ 2. Maintain 99.99% availability (SOC 2 Type II)     │
│ 3. GDPR, SOC 2, ISO 27001 compliance                │
│ 4. Enable secure external collaboration             │
│ 5. Prevent insider threats and data exfiltration    │
└─────────────────────────────────────────────────────┘

Business Impact of Breach:
  Direct Costs: $50-100M (fines, remediation)
  Customer Churn: 20-40% (loss of trust)
  Revenue Impact: $200-400M annually
  Brand Damage: Irreparable
  Legal Liability: Class action lawsuits
```

**PASTA Stage 4: Threat Actor Analysis**

**Threat Actor 1: Advanced Persistent Threat (APT) - Nation State**
```
Capability: EXPERT
Resources: Unlimited
Motivation: Espionage, IP theft
Target: Defense, aerospace, pharmaceutical customers
TTPs: Supply chain compromise, zero-day exploits
Historical Examples:
  - SolarWinds supply chain attack
  - Microsoft Exchange zero-days
  - Cloud infrastructure compromise

Risk to CollabSpace: CRITICAL
```

**Threat Actor 2: Organized Cybercrime (Ransomware)**
```
Capability: ADVANCED
Resources: Significant
Motivation: Financial (ransomware + data extortion)
Target: Any customer willing to pay
TTPs: Phishing, exploiting vulnerabilities, data exfiltration
Historical Examples:
  - Accellion FTA breach (100+ organizations)
  - MOVEit Transfer vulnerability
  - Ransomware double extortion

Risk to CollabSpace: CRITICAL
```

**Threat Actor 3: Malicious Insider**
```
Capability: VARIES
Resources: Privileged access
Motivation: Financial, revenge, ideology
Target: Specific customer data or platform access
TTPs: Abuse of legitimate access, data exfiltration
Historical Examples:
  - Uber breach (via compromised contractor)
  - Twitter insider data access
  - GitHub private repo exposure

Risk to CollabSpace: HIGH
```

**PASTA Stage 6: Attack Modeling with MITRE ATT&CK**

**Supply Chain Compromise Scenario**

```
MITRE ATT&CK Enterprise Matrix Mapping:

[Initial Access]
T1195.001 - Supply Chain Compromise: Compromise Software Dependencies
  └─ Attacker compromises npm package used by CollabSpace
     Impact: Malicious code in production environment

[Execution]
T1059.007 - Command and Scripting Interpreter: JavaScript
  └─ Malicious package executes in Node.js backend

[Persistence]
T1505.003 - Server Software Component: Web Shell
  └─ Backdoor installed in application server

[Privilege Escalation]
T1078.004 - Valid Accounts: Cloud Accounts
  └─ Compromised AWS credentials from environment variables

[Defense Evasion]
T1027 - Obfuscated Files or Information
  └─ Malicious code obfuscated to evade detection

[Credential Access]
T1552.001 - Unsecured Credentials: Credentials In Files
  └─ Database credentials extracted from config files

[Discovery]
T1580 - Cloud Infrastructure Discovery
  └─ Map out AWS infrastructure and services

[Lateral Movement]
T1021.007 - Remote Services: Cloud Services
  └─ Move between AWS accounts using compromised credentials

[Collection]
T1530 - Data from Cloud Storage Object
  └─ Exfiltrate customer files from S3 buckets

[Exfiltration]
T1567.002 - Exfiltration Over Web Service: To Cloud Storage
  └─ Upload stolen data to attacker-controlled cloud storage

[Impact]
T1486 - Data Encrypted for Impact
  └─ Encrypt customer data for ransom
```

**Attack Flow Visualization**:
```
Week 1: Compromise npm package (maintainer phished)
   ↓
Week 2: Malicious code merged into CollabSpace dependency
   ↓
Week 3: Deployed to production (automated CI/CD)
   ↓
Week 4: Backdoor activated, reconnaissance begins
   ↓
Week 5-8: Lateral movement, credential harvesting
   ↓
Week 9: Mass data exfiltration (500 GB/day, under radar)
   ↓
Week 10: Ransomware deployed, extortion demand ($50M)
```

#### Comprehensive Mitigations (Defense in Depth)

**1. Supply Chain Security**

```
Software Composition Analysis (SCA):
┌──────────────────────────────────────────┐
│ Dependency Management                    │
├──────────────────────────────────────────┤
│ ✓ Automated vulnerability scanning       │
│ ✓ License compliance checking            │
│ ✓ Known malicious package detection      │
│ ✓ Dependency pinning (exact versions)    │
│ ✓ Private npm registry mirror            │
│ ✓ Two-person approval for dep updates    │
│ ✓ SBOM (Software Bill of Materials)      │
└──────────────────────────────────────────┘

Build Pipeline Security:
┌──────────────────────────────────────────┐
│ Secure CI/CD                             │
├──────────────────────────────────────────┤
│ ✓ Ephemeral build environments           │
│ ✓ Code signing for all artifacts         │
│ ✓ Container image scanning               │
│ ✓ Infrastructure as Code scanning        │
│ ✓ Secrets scanning (pre-commit)          │
│ ✓ SLSA Level 3 compliance                │
└──────────────────────────────────────────┘

Example Detection:
  Event: Dependency update proposed
  Action:
    1. Automated scan detects suspicious code patterns
    2. Alert security team
    3. Manual code review required
    4. Package reputation check
    5. Approve or reject with documented justification
```

**2. Zero Trust Architecture**

```
Architecture Principles:
┌─────────────────────────────────────────────────────┐
│ Never Trust, Always Verify                          │
├─────────────────────────────────────────────────────┤
│ 1. Verify explicitly                                │
│    └─ Authenticate & authorize every request        │
│                                                      │
│ 2. Use least privilege access                       │
│    └─ Just-in-time & just-enough-access (JIT/JEA)   │
│                                                      │
│ 3. Assume breach                                    │
│    └─ Minimize blast radius, segment access         │
└─────────────────────────────────────────────────────┘

Implementation:
┌─────────────────────────────────────────┐
│ Identity & Access Management            │
├─────────────────────────────────────────┤
│ • MFA for all accounts (no exceptions)  │
│ • Passwordless (FIDO2, WebAuthn)        │
│ • Conditional access policies           │
│ • Continuous authentication             │
│ • Privileged Access Workstations (PAW)  │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Network Micro-Segmentation              │
├─────────────────────────────────────────┤
│ • Service-to-service mTLS               │
│ • Network policies (deny by default)    │
│ • Application-layer authorization       │
│ • East-west traffic inspection          │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Data Protection                         │
├─────────────────────────────────────────┤
│ • Encryption at rest (AES-256)          │
│ • Encryption in transit (TLS 1.3)       │
│ • Customer-managed keys (BYOK)          │
│ • Data loss prevention (DLP)            │
│ • Classification & labeling             │
└─────────────────────────────────────────┘
```

**3. Insider Threat Program**

```
Technical Controls:
┌────────────────────────────────────────────────┐
│ User & Entity Behavior Analytics (UEBA)       │
├────────────────────────────────────────────────┤
│ Baseline Normal Behavior:                     │
│   - Files accessed per day                    │
│   - Typical work hours                        │
│   - Geographic locations                      │
│   - Data download volumes                     │
│                                                │
│ Anomaly Detection:                             │
│   - Mass file downloads (>100 in 1 hour)      │
│   - Access to unrelated departments           │
│   - Activity outside normal hours             │
│   - Use of personal cloud storage             │
│   - Failed access attempts                    │
│   - Privilege escalation attempts             │
└────────────────────────────────────────────────┘

Administrative Controls:
┌────────────────────────────────────────────────┐
│ Privileged Access Management                   │
├────────────────────────────────────────────────┤
│ • Break-glass procedures                       │
│ • Four-eyes principle for sensitive ops        │
│ • Session recording for privileged access      │
│ • Time-limited elevated permissions            │
│ • Regular access reviews (quarterly)           │
│ • Background checks for privileged roles       │
└────────────────────────────────────────────────┘

Real Incident Detected:
  Employee: DevOps Engineer (authenticated access)
  Anomaly: Downloaded 5,000 customer files in 2 hours
           (Normal: 10-20 files per day)
  Action Taken:
    1. Automatic access revocation (2 minutes)
    2. Alert security operations center
    3. Manager notification
    4. Investigation initiated
  Result: 
    - Departing employee attempting data theft
    - Terminated immediately
    - Data recovery: 100% (never left network)
    - Legal action: Pursued
```

**4. Advanced Threat Detection & Response**

```
Security Stack:
┌─────────────────────────────────────────────────────┐
│ Detection Layer 1: Endpoint Detection & Response    │
│ └─ CrowdStrike on all endpoints & servers           │
│    • Behavioral analysis                            │
│    • Threat intelligence integration                │
│    • Automated response & isolation                 │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Detection Layer 2: Network Detection & Response     │
│ └─ Darktrace for anomaly detection                  │
│    • ML-based normal behavior modeling              │
│    • Autonomous response (Antigena)                 │
│    • Visualization of threats                       │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Detection Layer 3: Cloud Security Posture Mgmt      │
│ └─ Prisma Cloud for AWS/GCP/Azure                   │
│    • Misconfiguration detection                     │
│    • Compliance monitoring                          │
│    • Container & serverless security                │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ Detection Layer 4: SIEM & Security Orchestration    │
│ └─ Splunk + SOAR                                    │
│    • Log aggregation & correlation                  │
│    • Custom detection rules                         │
│    • Automated incident response                    │
│    • Forensic investigation                         │
└─────────────────────────────────────────────────────┘

Incident Response Playbooks (96 playbooks):
  - Ransomware detection & containment
  - Data exfiltration response
  - Account compromise response
  - DDoS mitigation
  - Supply chain incident
  - Insider threat investigation
```

**5. Customer-Facing Security Features**

```
Transparency & Control:
┌─────────────────────────────────────────────────────┐
│ Security Dashboard (Customer Portal)                 │
├─────────────────────────────────────────────────────┤
│ • Real-time security posture score                  │
│ • Login history & anomalies                         │
│ • Data access audit logs                            │
│ • Third-party app permissions                       │
│ • Security recommendations                          │
│ • Compliance reports (SOC 2, ISO 27001)             │
└─────────────────────────────────────────────────────┘

Advanced Features:
┌─────────────────────────────────────────────────────┐
│ Customer Data Control                                │
├─────────────────────────────────────────────────────┤
│ • Data residency selection (EU, US, APAC)           │
│ • Customer-managed encryption keys (BYOK)           │
│ • Data retention policies                           │
│ • Right to erasure (GDPR compliance)                │
│ • Advanced DLP rules                                │
│ • External sharing controls                         │
│ • Watermarking for sensitive documents              │
└─────────────────────────────────────────────────────┘
```

#### Results & Business Impact

**Security Metrics (Annual)**:
```
Incidents Detected: 47,892
False Positives: 2.1%
Mean Time to Detect (MTTD): 3.2 minutes
Mean Time to Respond (MTTR): 12 minutes
Mean Time to Contain (MTTC): 45 minutes

High-Severity Incidents: 142
  ├─ Prevented breaches: 138
  ├─ Contained breaches: 4 (no data loss)
  └─ Successful breaches: 0

Customer Impact: ZERO security-related churn
```

**Compliance & Certifications**:
- SOC 2 Type II: Compliant (annual audit)
- ISO 27001: Certified
- ISO 27017: Certified (cloud security)
- ISO 27018: Certified (cloud privacy)
- GDPR: Fully compliant
- HIPAA BAA: Available for healthcare customers
- FedRAMP: In progress (Moderate baseline)

**Financial Impact**:
```
Security Investment (Annual): $28M
  ├─ Personnel (40 FTE): $12M
  ├─ Tools & Technology: $8M
  ├─ Training & Awareness: $2M
  ├─ External Audits: $3M
  └─ Threat Intelligence: $3M

Prevented Losses (Estimated): $250M+
  ├─ Breach costs avoided: $100M
  ├─ Regulatory fines avoided: $50M
  ├─ Customer churn prevented: $80M
  └─ Reputation protection: $20M

ROI: 893% (Security as business enabler)
```

**Competitive Advantage**:
- Enterprise deal closure rate: 85% (vs 45% industry avg)
- Security as primary buying factor: 67% of customers
- Premium pricing justified by security: +22% vs competitors
- Customer references citing security: 89%

**Awards**:
- Gartner Peer Insights: 4.8/5 (security mentioned in 92% of reviews)
- "Best Enterprise Security" - SC Awards
- "Top 10 Most Secure SaaS" - CSO Magazine
- "Customers' Choice" - Gartner (3 years running)

---

## Conclusion

### Key Takeaways

1. **No Single Framework is Perfect**
   - Combine frameworks based on needs
   - STRIDE + DREAD is popular combination
   - PASTA for business risk focus
   - MITRE ATT&CK for threat intelligence

2. **Threat Modeling is Continuous**
   - Not a one-time exercise
   - Update on architecture changes
   - Monitor threat landscape
   - Regular reviews (quarterly minimum)

3. **People Matter Most**
   - Cross-functional teams essential
   - Training and awareness critical
   - Executive sponsorship needed
   - Culture of security

4. **Document Everything**
   - Architecture diagrams
   - Data flows
   - Threat inventory
   - Mitigation plans
   - Decisions and rationale

5. **Measure Success**
   - Track risk reduction
   - Monitor KPIs
   - Calculate ROI
   - Demonstrate business value

### Implementation Checklist

**Month 1: Foundation**
- [ ] Form threat modeling team
- [ ] Select framework(s)
- [ ] Gather documentation
- [ ] Create architecture diagrams
- [ ] Define threat modeling process

**Month 2-3: Analysis**
- [ ] Identify threats systematically
- [ ] Assess risks
- [ ] Prioritize based on business impact
- [ ] Document findings
- [ ] Present to stakeholders

**Month 4-6: Mitigation**
- [ ] Develop mitigation strategies
- [ ] Create implementation roadmap
- [ ] Allocate resources
- [ ] Begin implementation
- [ ] Track progress

**Month 7-12: Operationalization**
- [ ] Complete high-priority mitigations
- [ ] Integrate into SDLC
- [ ] Establish review cadence
- [ ] Measure effectiveness
- [ ] Continuous improvement

### Resources

**Tools**:
- Microsoft Threat Modeling Tool (free)
- OWASP Threat Dragon (free, open source)
- ThreatModeler (commercial)
- IriusRisk (commercial)
- Threagile (open source)

**Training**:
- OWASP Threat Modeling Training
- SANS Secure DevOps courses
- Threat Modeling Manifesto (threatmodelingmanifesto.org)
- Books: "Threat Modeling" by Adam Shostack

**Communities**:
- OWASP Threat Modeling Project
- Threat Modeling Community (Slack)
- Security BSides conferences
- Local OWASP chapters

### Final Thoughts

Threat modeling is not just a security activity—it's a business enabler. Organizations that invest in proactive threat modeling experience:

- **Fewer security incidents** (60-90% reduction)
- **Lower remediation costs** (fixes are 60-100x cheaper in design phase)
- **Faster time to market** (security is not a bottleneck)
- **Higher customer trust** (demonstrable security posture)
- **Competitive advantage** (security as a differentiator)

The key is to start small, iterate, and build security into your DNA rather than bolting it on later.

Remember: **"The best time to start threat modeling was yesterday. The second-best time is today."**

---

## Appendix: Quick Reference

### STRIDE Cheat Sheet
```
S - Spoofing → Authentication
T - Tampering → Integrity
R - Repudiation → Non-repudiation
I - Information Disclosure → Confidentiality
D - Denial of Service → Availability
E - Elevation of Privilege → Authorization
```

### DREAD Scoring Guide
```
0-3:  Low Risk → P3 (6-12 months)
4-6:  Medium Risk → P2 (3-6 months)
7-8:  High Risk → P1 (1-3 months)
9-10: Critical Risk → P0 (immediate)
```

### PASTA Stages
```
1. Define Objectives (DO)
2. Define Technical Scope (DTS)
3. Application Decomposition (AD)
4. Threat Analysis (TA)
5. Vulnerability Analysis (VA)
6. Attack Modeling (AM)
7. Risk & Impact Analysis (RIA)
```

### Common Mitigations
```
Authentication: MFA, SSO, biometrics
Authorization: RBAC, ABAC, least privilege
Encryption: TLS 1.3, AES-256
Input Validation: Allowlist, sanitization
Logging: SIEM, immutable logs
Monitoring: UEBA, anomaly detection
Network: Segmentation, zero trust
Updates: Patch management, auto-updates
```

---

**Document Version**: 1.0
**Last Updated**: November 2024
**Authors**: Security Engineering Team and Purushotham Muktha
**Review Cycle**: Quarterly

*This guide is a living document. Contributions and feedback welcome.*