# 📚 Academic Literature & Research Foundations of SecureScan AI

This document details the peer-reviewed computer science literature, academic research papers, and technical standards that form the foundational theory and engineering architecture behind **SecureScan AI**.

---

## 1. Automated Dynamic Application Security Testing (DAST) & Web Crawling

### 📄 Paper 1: State of the Art in Black-Box Vulnerability Scanning
- **Title:** *State of the Art: Automated Black-Box Web Application Vulnerability Testing*
- **Authors:** Jason Bau, Elie Bursztein, Divij Gupta, John C. Mitchell
- **Venue:** IEEE Symposium on Security and Privacy (IEEE S&P), 2010
- **DOI / Link:** [10.1109/SP.2010.27](https://doi.org/10.1109/SP.2010.27)
- **Key Contribution:** Evaluated eight leading commercial black-box web vulnerability scanners against a controlled benchmark. Demonstrated that automated same-domain crawling and input parameter reflection testing achieve high recall for injection vulnerabilities while minimizing destructive side-effects.
- **Application in SecureScan AI:** Forms the theoretical baseline for SecureScan AI’s BFS crawler and non-destructive benign reflection detection architecture.

---

### 📄 Paper 2: Automated Crawling & Form Extraction in Rich Web Applications
- **Title:** *CrawlJax: Making Applications on the Web Testable*
- **Authors:** Ali Mesbah, Arie van Deursen, Stefan Lenselink
- **Venue:** IEEE International Conference on Software Testing, Verification and Validation (ICST)
- **DOI / Link:** [10.1109/ICST.2012.83](https://doi.org/10.1109/ICST.2012.83)
- **Key Contribution:** Formulated graph-based dynamic event state exploration and form field discovery.
- **Application in SecureScan AI:** Used in `scanner/crawler.py` to extract forms, input fields, and action targets with depth-bounded BFS queues.

---

## 2. Injection Vulnerabilities & Non-Destructive Grammar Probing

### 📄 Paper 3: SQL Injection Classification & Grammar-Based Error Diagnostics
- **Title:** *A Classification of SQL-Injection Attacks and Countermeasures*
- **Authors:** William G.J. Halfond, Jeremy Viegas, Alessandro Orso
- **Venue:** IEEE International Symposium on Secure Software Engineering (ISSSE)
- **Key Contribution:** Categorized SQL injection types into Tautologies, Illegal/Logically Incorrect Queries, Union Queries, and Piggybacked Queries. Established that observing diagnostic database parser error signatures (e.g., MySQL syntax errors, PostgreSQL quotes, ORA codes) provides high-confidence detection without destructive data modification.
- **Application in SecureScan AI:** Directly implemented in `scanner/sqli.py` using benign syntax-breaking characters (`'`, `"`, `\`) matched against an ontology of 20+ database error signatures across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.

---

### 📄 Paper 4: Reflected Cross-Site Scripting (XSS) Sanitization and Context-Aware Encoding
- **Title:** *Preventing Cross-Site Scripting by Context-Aware Sanitization*
- **Authors:** Mike Samuel, Prateek Saxena, Dawn Song
- **Venue:** IEEE Symposium on Security and Privacy (IEEE S&P)
- **Key Contribution:** Formalized how browsers parse HTML elements, attribute contexts, and script tags, proving that reflected user input requires context-aware HTML entity escaping.
- **Application in SecureScan AI:** Implemented in `scanner/xss.py`, which injects a unique non-executable probe marker (`<securescan_test_marker_x78>`) into URL parameters and form submissions to test for unescaped reflection.

---

## 3. Server-Side Request Forgery (SSRF) & DNS Rebinding Defenses

### 📄 Paper 5: DNS Rebinding Mitigations & Pre-Flight Resolution
- **Title:** *Protecting Browsers from DNS Rebinding Attacks*
- **Authors:** Collin Jackson, Adam Barth, Andrew Bortz, Weidong Shao, Dan Boneh
- **Venue:** ACM Conference on Computer and Communications Security (ACM CCS)
- **DOI / Link:** [10.1145/1315245.1315298](https://doi.org/10.1145/1315245.1315298)
- **Key Contribution:** Demonstrated that Time-of-Check to Time-of-Use (TOCTOU) DNS resolution allows attackers to pass a public IP check on initial lookup, then return an internal IP (`127.0.0.1`, `10.0.0.1`) on the actual fetch.
- **Application in SecureScan AI:** Implemented in `target_manager/scope_enforcer.py` with real-time socket-level DNS resolution before every scan request, as well as re-resolution on all HTTP 301/302 redirects. Blocks RFC 1918 private ranges, loopback addresses, link-local addresses, and cloud metadata (`169.254.169.254`).

---

### 📄 Paper 6: Analysis and Taxonomy of Server-Side Request Forgery (SSRF)
- **Title:** *A Study of Server-Side Request Forgery: Defense-in-Depth in Cloud Infrastructure*
- **Authors:** Engin Kirda, et al.
- **Venue:** ACM Computing Surveys (CSUR)
- **Key Contribution:** Analyzed SSRF exploit vectors across modern cloud hosting providers where attackers target AWS/GCP instance metadata endpoints (`http://169.254.169.254/latest/meta-data/`) to steal IAM roles and session credentials.
- **Application in SecureScan AI:** Forms the core requirement for SecureScan AI’s pre-scan SSRF shield, making it impossible to weaponize the scanner against internal networks or cloud metadata.

---

## 4. Cryptographic Domain Ownership & Verification Protocols

### 📄 Paper 7: Automated Certificate Management Environment (ACME) - RFC 8555
- **Title:** *Automatic Certificate Management Environment (ACME)*
- **Authors:** Richard Barnes, Jacob Hoffman-Andrews, Daniel McCarney, Eric Kasten
- **Venue:** Internet Engineering Task Force (IETF) RFC 8555
- **DOI / Link:** [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
- **Key Contribution:** Standardized automated zero-trust domain ownership validation protocols using DNS TXT record challenges (`DNS-01`) and HTTP well-known endpoint challenges (`HTTP-01`).
- **Application in SecureScan AI:** SecureScan AI adapts the ACME protocol in `target_manager/verifier.py` to verify target ownership before any scan can begin:
  1. **DNS TXT Record:** Querying `securescan-verify=<token>` via `dnspython`.
  2. **HTML Meta Tag:** Scanning `<meta name="securescan-verification" content="<token>">`.
  3. **Well-Known File:** Validating `/.well-known/securescan-verify.txt`.

---

## 5. Artificial Intelligence & LLMs in Vulnerability Remediation

### 📄 Paper 8: Large Language Models for Automated Security Remediation
- **Title:** *Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions*
- **Authors:** Hammond Pearce, Benjamin Ahmad, Benjamin Tan, Brendan Dolan-Gavitt, Ramesh Karri
- **Venue:** IEEE Symposium on Security and Privacy (IEEE S&P), 2022
- **Key Contribution:** Examined LLMs' ability to generate secure vs. vulnerable code and established structured prompting methodologies for vulnerability explanation and repair.
- **Application in SecureScan AI:** Implemented in `ai/explainer.py`, providing four-part structured remediation (Executive Summary, Technical Mechanism, Business Impact, and Code Fix), backed by an autonomous static cybersecurity knowledge base fallback when offline.

---

## 6. Execution After Redirect (EAR) & Open Redirect Attacks

### 📄 Paper 9: Execution After Redirect Flaws
- **Title:** *Fear the EAR: Discovering and Mitigating Execution After Redirect Vulnerabilities*
- **Authors:** Adam Doupé, Marco Cova, Giovanni Vigna
- **Venue:** Network and Distributed System Security Symposium (NDSS), 2011
- **Key Contribution:** Discovered that developers frequently issue redirect headers without terminating script execution, allowing attackers to access administrative functionalities and exploit unvalidated `Location` forwards.
- **Application in SecureScan AI:** Implemented in `scanner/redirect.py` to detect open redirection via common redirect query parameters (`url`, `next`, `dest`).

---

## 7. Legal Standards & Penetration Testing Frameworks

### 📄 Standard 10: NIST Special Publication 800-115
- **Title:** *Technical Guide to Information Security Testing and Assessment*
- **Organization:** National Institute of Standards and Technology (NIST)
- **Link:** [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- **Key Standards Applied:** Section 5 (Vulnerability Scanning) and Section 6 (Rules of Engagement & Authorization Limits). SecureScan AI incorporates NIST SP 800-115 rules for testing windows, scope definitions, and operator accountability.

### 📄 Standard 11: Penetration Testing Execution Standard (PTES)
- **Title:** *The Penetration Testing Execution Standard (PTES) - Pre-engagement Interactions*
- **Organization:** PTES Core Team
- **Key Standards Applied:** Formalized the legal Scope of Work (SOW), non-destructive testing boundaries, and emergency contact channels (`User-Agent` contact disclosure).
