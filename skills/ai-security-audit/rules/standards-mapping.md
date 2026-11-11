<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Standards mapping

Every confirmed and needs-validation record carries a CWE and the matching OWASP IDs. Use the most specific CWE that fits. Do not stretch a mapping to look complete; leave a list empty when nothing fits.

## OWASP Top 10:2025 (web applications)

| ID | Name | Common CWEs |
|---|---|---|
| A01:2025 | Broken Access Control | 284, 285, 639 (IDOR), 862, 863, 918 (SSRF), 352 (CSRF) |
| A02:2025 | Security Misconfiguration | 16, 611, 942 (CORS), 1004, 614 |
| A03:2025 | Software Supply Chain Failures | 1104, 1357, 829, 506 |
| A04:2025 | Cryptographic Failures | 327, 328, 330, 338, 798 (hardcoded credentials), 321 |
| A05:2025 | Injection | 79 (XSS), 89 (SQLi), 78 (OS command), 94, 917, 1336 |
| A06:2025 | Insecure Design | 840, 841, 799, 770 |
| A07:2025 | Authentication Failures | 287, 306, 307, 384, 613, 640, 1390 |
| A08:2025 | Software or Data Integrity Failures | 345, 347, 502 (deserialization), 494 |
| A09:2025 | Security Logging and Alerting Failures | 778, 117, 532 (secrets in logs) |
| A10:2025 | Mishandling of Exceptional Conditions | 209, 248, 636 (fail-open), 755 |

## OWASP API Security Top 10:2023

| ID | Name |
|---|---|
| API1:2023 | Broken Object Level Authorization (BOLA / IDOR) |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization (mass assignment, excessive data exposure) |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization (BFLA) |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

## OWASP Top 10 for LLM Applications 2025

| ID | Name |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

## Mobile (OWASP Mobile Top 10:2024)

M1 Improper Credential Usage, M2 Inadequate Supply Chain Security, M3 Insecure Authentication/Authorization, M4 Insufficient Input/Output Validation, M5 Insecure Communication, M6 Inadequate Privacy Controls, M7 Insufficient Binary Protections, M8 Security Misconfiguration, M9 Insecure Data Storage, M10 Insufficient Cryptography.

## Regulation (only when the data in scope makes it relevant)

| Regulation | Use when | Typical reference |
|---|---|---|
| India DPDP Act 2023 and DPDP Rules 2025 | Personal data of people in India | Section 8(5) reasonable security safeguards; Rule 6 security measures; Rule 7 breach intimation. For a full DPDP review run `/ai-dpdp-audit` |
| IT Act 2000 | Indian body corporate holding sensitive personal data | Section 43A |
| GDPR | EU residents' data | Article 32 security of processing |
| PCI DSS v4.0 | Card data stored, processed or transmitted | Req. 3, 4, 6, 7, 8 |

Regulation lines say what the confirmed finding puts at risk. They are not legal advice and never claim the organisation is "non-compliant" as a legal conclusion. Write "puts at risk compliance with" instead.
