# My Cybersecurity Journey — Documentation Hub 🛡️

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Documentation-blue) 
![Updated](https://img.shields.io/badge/Updated-2025-green) 
![License](https://img.shields.io/badge/License-MIT-orange)

## 🤝 Let’s connect and make the change.

<p align="center">
  <a href="https://purushothammuktha.com" target="_blank"><img src="https://img.shields.io/badge/Website-purushothammuktha.com-%23000000?style=for-the-badge"></a>
  <a href="https://linkedin.com/in/mpurushotham" target="_blank"><img src="https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin"></a>
  <a href="mailto:purushotham.muktha@gmail.com"><img src="https://img.shields.io/badge/Email-Contact%20Me-red?style=for-the-badge&logo=gmail"></a>
  <a href="https://wa.me/+46764561036" target="_blank"><img src="https://img.shields.io/badge/WhatsApp-Chat%20Now-25D366?style=for-the-badge&logo=whatsapp"></a>
</p>


## 📖 Overview

Welcome to my comprehensive cybersecurity documentation repository! This living knowledge base contains **hands-on learning notes, practical tutorials, and reproducible lab playbooks** covering modern cybersecurity domains.

### 🎯 Purpose
- **Study Reference**: Structured learning materials for cybersecurity concepts
- **Lab Playbooks**: Reproducible exercises and experiments
- **Portfolio Projects**: Demonstrable skills across security domains
- **Career Preparation**: Role-specific guidance for 2026+ cybersecurity landscape

---

## 🚀 Quick Access

| Resource | Link |
|----------|------|
| **📚 Live Documentation** | `./index.html` |
| **🧭 Navigation Sidebar** | `./_sidebar.md` |
| **🐙 GitHub Repository** | [Repository Link](https://github.com/mpurushotham/my-cybersecurity-journey) |

---

## 📚 Documentation Structure

### 🔰 Foundation
- **`0-Linux/`**
  - `Linux-Lab.md` - 🐧 Canonical Linux lab guide
  - `Computers-Networking.md` - 🌐 Networking fundamentals

### ☁️ Cloud Security
- **`1-Cloud-Security/`**
  - **AWS**: `IAM-Security.md` - 🔑 AWS Identity & Access Management
  - **Azure**: `Entra-ID-Security.md` - 🏢 Azure Entra ID security
  - **GCP**: `IAM-Security.md` - ☁️ Google Cloud IAM
  - **Kubernetes**: `K8s-Architecture.md` - ⛵ Container security fundamentals

### 🔐 Identity & Zero Trust
- **`2-Identity-Access-ZeroTrust/`**
  - `IAM-Fundamentals.md` - 🏗️ Core identity concepts
  - `SSO-Federation.md` - 🔗 Single Sign-On & federation

### 🤖 AI Security & ML Safety
- **`3-AI-Security-ML-Safety/`**
  - `Adversarial-ML.md` - ⚔️ Machine learning attacks & defenses
  - `LLM-Threats.md` - 🧠 Large Language Model security

### ⚙️ Security Automation & Engineering
- **`4-Security-Automation-And-Engineering/`**
  - `Automated-IR-Playbooks.md` - 🤖 Automated incident response

### 🔴 Offensive Security
- **`5-Offensive-Security/`**
  - `Web-Pentesting.md` - 🌐 Web application penetration testing

### 🔍 Detection Engineering
- **`6-Detection-Engineering/`**
  - `Microsoft-Sentinel.md` - 📊 SIEM detection rules
  - `Threat-Hunting.md` - 🎯 Proactive threat hunting

### 🎯 Vulnerability Management
- **`7-Vulnerability-Management/`**
  - `CVE-Analysis.md` - 📋 CVE analysis and vulnerability assessment

### 🛠️ DevSecOps
- **`8-DevSecOps/`**
  - `Secure-Coding.md` - 💻 Secure development practices

### 📊 Data Science & Security Analytics
- **`9-Data-Science-Security-Analytics/`**
  - `Intro-Data-Science.md` - 📈 Data science for security analytics

### 📋 GRC, Risk & Compliance
- **`10-GRC-Risk-Compliance/`**
  - `NIST-CSF.md` - 🏛️ NIST Cybersecurity Framework
  - `ISO-27001-27002.md` - 📜 ISO 27001/27002 standards
  - `CIS-Controls.md` - 🛡️ CIS Critical Security Controls
  - `GDPR-NIS2-DORA.md` - 🌍 Privacy & regulatory frameworks
  - `Risk-Assessments.md` - 📊 Risk assessment methodologies
  - `Business-Continuity.md` - 🔄 Business continuity planning

### 🚨 Incident Response & Forensics
- **`11-Incident-Response-Forensics/`**
  - `IR-Playbooks.md` - 📋 Incident response procedures
  - `DFIR-Tools.md` - 🛠️ Digital forensics tools

### 💬 Professional Skills
- **`12-Soft-Skills-Professional/`**
  - `Communication-for-Security.md` - 🗣️ Security communication skills

### 💼 Career Development
- **`13-Job-Roles-2026+-Career/`**
  - `AI-Security-Engineer.md` - 🤖 Emerging AI security roles
  - `IR-Forensics-Specialist.md` - 🔍 Incident response career path

---

## 🖥️ Local Development Preview

### Option 1: Docsify (Recommended) 📖
```bash
# Install Docsify globally
npm install -g docsify-cli

# Serve documentation locally
cd docs
docsify serve .

# Access at: http://localhost:3000
```

### Option 2: Python Simple Server 🐍
```bash
# From docs directory
python3 -m http.server 8000

# Access at: http://localhost:8000/index.html
```

---

## 🤝 Contribution Guidelines

### 📝 Adding Content
- Place `.md` files in appropriate top-level folders
- Update `./_sidebar.md` to maintain navigation accuracy
- Use relative links between pages (e.g., `../11-Incident-Response-Forensics/IR-Playbooks.md`)

### ✍️ Writing Standards
- **Clear headings** and structured content
- **Short theory sections** followed by practical applications
- Include **"Practice" or "Lab"** sections with executable commands
- Use fenced code blocks for commands and configurations

### 🔒 Security Best Practices
- ❌ Never embed secrets or credentials
- ✅ Keep examples reproducible on disposable environments
- ✅ Include references and suggested next steps

---

## 🛠️ Maintenance

### 🔄 Synchronization
- Keep `_sidebar.md` updated with new pages
- Backup major changes (e.g., `filename.md.bak`) before rewrites
- Regular review and update of external references

### 📋 Commit Convention
```bash
git commit -m "docs: add K8s RBAC lab"
git commit -m "fix: correct AWS IAM policy examples"
git commit -m "feat: new threat hunting techniques"
```

---

## 📄 License & Support

- **License**: See `LICENSE` file in repository root
- **Issues & PRs**: [GitHub Issues](https://github.com/mpurushotham/my-cybersecurity-journey/issues)
- **Contributions**: Welcome! Please follow contribution guidelines

---

## 📞 Contact

- **GitHub**: [@mpurushotham](https://github.com/mpurushotham)
- **Issues**: For corrections or content requests, please open an issue
- **Pull Requests**: Direct contributions are welcome

---

<div align="center">

**🚀 Continuous Learning | 🔒 Practical Security | 🌐 Community Knowledge**

*Building cybersecurity expertise, one document at a time*

</div>