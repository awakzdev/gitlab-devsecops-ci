# 📘 GitLab DevSecOps CI/CD  
### Automated SAST, Secrets, OWASP DAST & Unified HTML Security Report

This repository demonstrates a fully automated **DevSecOps pipeline** on GitLab using GitLab-provided security templates combined with a custom OWASP DAST job and a unified HTML Security Report generator.

The pipeline includes:

- **SAST** (Semgrep)  
- **Secret Detection**  
- **OWASP ZAP DAST** (authenticated)  
- **Custom consolidated HTML Security Report**  

All scans run **only when the commit message contains `initiate-scan`**, to avoid running heavy security jobs on every push.

📄 **Live example:**  
👉 [View the final HTML report](https://awakzdev.github.io/gitlab-devsecops-ci/security-report.html)

---

# 🚀 Pipeline Overview

```yaml
stages:
  - test
  - secret-detection
  - owasp-dast
  - report
  - build

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
```

---

# 🔐 Environment Variables

| Variable | Description |
|---------|-------------|
| `GIT_DEPTH=0` | Required for SAST to run properly |
| `SECRET_DETECTION_HISTORIC_SCAN=true` | Enables full repository deep secret scan |
| `DAST_WEBSITE` | Base URL for DAST targeting |
| `DAST_AUTH_URL` | Authentication URL for ZAP |
| `DAST_USERNAME_FIELD` | CSS selector for username field |
| `DAST_PASSWORD_FIELD` | CSS selector for password input |
| `DAST_SUBMIT_FIELD` | CSS selector for login submit |
| `DAST_FULL_SCAN_ENABLED` | Enables spider + active scanning |
| `SECURE_LOG_LEVEL=debug` | Enables verbose debugging logs |
| `DAST_USERNAME=admin` | Login page credentials (Should be provided via CICD) |
| `DAST_PASSWORD=1234` | Login page credentials (Should be provided via CICD) |


---

# 🛡 Security Jobs

## ▶️ 1. **SAST (Semgrep)**  
Runs only when commit message contains **initiate-scan**

```yaml
semgrep-sast:
  rules:
    - if: '$CI_COMMIT_MESSAGE =~ /initiate-scan/i'
```

---

## 🕵️ 2. **Secret Detection**

```yaml
secret_detection:
  stage: secret-detection
  rules:
    - if: '$CI_COMMIT_MESSAGE =~ /initiate-scan/i'
```

---

## 🧪 3. **OWASP ZAP Authenticated DAST**

```yaml
owasp-dast:
  stage: owasp-dast
  image: registry.gitlab.com/security-products/dast:latest
  rules:
    - if: '$CI_COMMIT_MESSAGE =~ /initiate-scan/i || $CI_COMMIT_MESSAGE =~ /initiate-owasp/i'
  variables:
    DAST_WEBSITE: "https://example.com"
    DAST_AUTH_URL: "https://example.com/login"
    DAST_USERNAME_FIELD: 'css:input[name="email"]'
    DAST_PASSWORD_FIELD: 'css:input[name="password"]'
    DAST_SUBMIT_FIELD:   'css:button[type="submit"]'
    DAST_FULL_SCAN_ENABLED: "true"
    SECURE_LOG_LEVEL: "debug"
    DAST_AUTH_REPORT: "true"
    DAST_PAGE_MAX_RESPONSE_SIZE_MB: "50"
    DAST_PAGE_DOM_READY_TIMEOUT: "15s"
    DAST_PAGE_ELEMENT_READY_TIMEOUT: "20s"
  script:
    - /analyze
```

Artifacts include:

- `gl-dast-report.json`
- `gl-dast-debug-auth-report.html`

---

# 📊 4. **Unified HTML Security Report**

```yaml
security_report_html:
  image: python:3.12-alpine
  stage: report
  needs:
    - semgrep-sast
    - secret_detection
    - owasp-dast
  script:
    - python3 security/report.py         --sast gl-sast-report.json         --secrets gl-secret-detection-report.json         --dast gl-dast-report.json         --out security-report.html         --project "$CI_PROJECT_PATH"         --commit "$CI_COMMIT_SHORT_SHA"
  artifacts:
    paths:
      - security-report.html
    expose_as: "Security Report HTML"
```

---

# 🧩 Triggering Scans

Add **any** of these phrases to your commit message:

- `initiate-scan` → Runs all scans  
- `initiate-owasp` → Runs only OWASP DAST  

---

# 📁 Artifacts Generated

| File | Description |
|------|-------------|
| `gl-sast-report.json` | Static analysis results |
| `gl-secret-detection-report.json` | Secret detector findings |
| `gl-dast-report.json` | DAST vulnerability results |
| `gl-dast-debug-auth-report.html` | Login debugging page |
| `security-report.html` | Consolidated HTML security dashboard |

---
