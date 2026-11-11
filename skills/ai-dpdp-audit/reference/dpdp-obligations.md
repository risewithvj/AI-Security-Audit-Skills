<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
  Engineering reading of the DPDP Act 2023 and DPDP Rules 2025. Not legal
  advice. Check the official texts on meity.gov.in before relying on any
  reference.
-->

# DPDP obligations: what to look for in code

One hunter per group below. Each group lists the legal reference, the questions to answer from source, what a confirmed gap looks like, and what stays outside the code. Use `pii-inventory.json` as the starting map.

---

## G1. Notice (Act s.5; Rule 3)

**Ask:** At every place personal data is collected (signup, onboarding, job application, KYC upload, forms, chatbots, mobile permissions), does the flow show or link a notice before or at collection? Does it name the personal data, the purpose, how to withdraw consent, how to exercise rights and how to complain to the Board? Is it available in English and the languages the product supports?

**Confirmed gap:** a collection form or API flow with no notice shown or linked (cite the component and the submit handler); a notice that omits the data actually collected (compare form fields with notice text in the repo).

**Outside code:** the full published privacy policy page if hosted elsewhere.

## G2. Consent and withdrawal (Act s.6, s.7; Rules 3, 4)

**Ask:** Where consent is the basis, is it recorded (who, what, when, version of notice)? Is it specific to each purpose or one bundled checkbox? Are checkboxes pre-ticked? Can it be withdrawn, and is withdrawal **as easy as giving it** (s.6(4))? After withdrawal, does processing actually stop (marketing jobs, analytics, SMS/WhatsApp campaigns read the flag)? Is processing that relies on legitimate uses (s.7, e.g. employment purposes) separated from consent-based processing?

**Confirmed gap:** consent stored as a single boolean with no record; pre-ticked consent in UI code; no withdrawal endpoint or UI; withdrawal sets a flag that the campaign job ignores (cite the job query).

## G3. Purpose limitation and minimisation (Act s.4, s.5, s.6(1))

**Ask:** Is every collected field used for a stated purpose? Are fields collected "just in case" (full Aadhaar where last 4 digits would do, date of birth where age band would do, precise location where city would do)? Is data collected for one purpose reused for another (recruitment data used for marketing, employee data sent to an LLM for unrelated analysis)?

**Confirmed gap:** a field collected and stored but never read by any code path other than storage (grep proof); full Aadhaar stored when only verification is needed; personal data passed to an analytics or LLM call unrelated to the stated purpose.

## G4. Accuracy and correction (Act s.8(3), s.12)

**Ask:** Can a Data Principal see and correct their data (profile edit, correction request)? Is data used for decisions (payroll, background checks, credit) kept complete and accurate, with a path to fix errors?

**Confirmed gap:** personal data the user can never view or correct and no request path exists.

## G5. Reasonable security safeguards (Act s.8(5); Rule 6)

Rule 6 sets minimum measures. Check each in code and IaC; reuse the security checklists:

| Rule 6 measure | Look for | Typical confirmed gap |
|---|---|---|
| Encryption, obfuscation, masking or virtual tokens | Field-level encryption, KMS, pgcrypto, encrypted columns, masking in API responses and UI, tokenised Aadhaar (Aadhaar Data Vault pattern) | Aadhaar, PAN, bank, health stored and returned in plain text; masking only in the frontend |
| Access control | Authorization on every endpoint that returns personal data ([api-authorization.md](../../ai-security-audit/checklists/api-authorization.md)) | IDOR on documents; directory API returning PII to all users |
| Visibility of access through logs, monitoring and review | Audit log of who read or changed personal data | No access logging for document or profile reads |
| Continued processing when data is compromised (backups) | Backup configuration in IaC or scripts | No backup config visible (often `needs_validation`) |
| Retention of logs and personal data for one year to detect and investigate unauthorised access (Rule 6(1)(e)) | Log retention settings (CloudWatch, Loki, ELK, app config), log rotation | Retention set below one year (e.g. 7 or 30 days) in IaC or config |
| Security clauses in Data Processor contracts | Not in code | `unverifiable`: list under not verifiable |
| Technical and organisational measures for the above | Security tests, CI checks | Note only |

Any confirmed security vulnerability exposing personal data (from a security audit run or found here) is also a G5 gap. Link it by finding ID rather than repeating it.

## G6. Breach readiness (Act s.8(6); Rule 7)

Rule 7 requires intimation to each affected Data Principal without delay, and to the Board without delay with a detailed report within 72 hours.

**Ask:** Can the system tell **who** was affected by an incident (access logs tied to users and records)? Is there any incident or breach workflow, alerting on anomalous access, or a way to contact affected users at scale?

**Confirmed gap:** no logging that would identify which records were read (cite the data-access layer); no alerting on mass reads of personal data. The procedure itself is outside code.

## G7. Retention and erasure (Act s.8(7), s.8(8), s.12(3); Rule 8, Third Schedule)

**Ask:** For each data type and each class of person (employees after exit, rejected candidates, inactive customers), is there a defined retention period in code or config, and an erasure job that runs? Does erasure reach every copy: replicas, search indexes, caches, object storage, analytics, backups, logs, LLM vector stores, third parties? Where the Third Schedule applies (large e-commerce, online gaming and social media platforms), is inactive-account erasure implemented with the 48-hour advance notice? Is the one-year minimum retention of personal data, traffic data and processing logs (Rule 8(3)) respected before deletion?

**Confirmed gap:** no delete path for a personal-data table (grep shows no delete, soft delete only with no purge); "delete account" removes the user row but leaves documents in storage or rows in other tables (cite both); retention never enforced (no TTL, no job).

## G8. Data Principal rights (Act s.11 to s.14; Rules 14)

**Ask:** Are there working paths (UI or request endpoint) for: a summary of personal data processed and the processing activities (s.11), the identities of Data Fiduciaries and Processors it was shared with, correction, completion, updating and erasure (s.12), grievance redressal with a contact (s.13, s.8(10)), and nomination (s.14)? Does the request flow verify identity before acting?

**Confirmed gap:** no export or access path; erasure request endpoint that deletes without verifying the requester (also a security finding); no grievance contact anywhere in the app.

## G9. Children and persons with disability (Act s.9; Rules 10 to 12)

**Ask:** Can a child (under 18) use the service (LMS, education, gaming, family features, dependants in HR)? Is age captured, and is verifiable parental consent obtained before processing (Rule 10)? On child-facing surfaces, are there trackers, behavioural monitoring or targeted advertising (prohibited by s.9(3))? For persons with disability, is consent obtained from a lawful guardian where needed (Rule 11)?

**Confirmed gap:** no age gate on a product open to minors; analytics, ad or session-replay SDKs loaded on children's pages (cite the import); dependant (child) data collected without any guardian flow.

## G10. Processors, third parties and cross-border transfer (Act s.8(1), s.8(2), s.16; Rule 15)

**Ask:** Which third parties receive personal data (`pii-inventory.json` → `third_party_recipients`): analytics, chat widgets, SMS/WhatsApp gateways, email, payment, KYC/BGV vendors, LLM APIs, error trackers? What data is sent (full payloads, PII in event properties, user identifiers)? Where is data stored and processed (cloud regions in IaC)? Is anything sent to a country or entity the Government restricts under s.16 (check the latest notification; the code only shows destinations)?

**Confirmed gap:** PII sent in analytics event properties or error-tracker breadcrumbs; full employee records sent to an LLM API with no minimisation; personal data in a third-party call not mentioned in the in-app notice. Restrictions on specific countries are `needs_validation` against the latest Government notification.

## G11. Significant Data Fiduciary (Act s.10; Rule 13)

Only if the organisation is or may be notified as an SDF. Code can show algorithmic processing of personal data (risk scores, automated hiring filters) that the DPIA and audit should cover. Everything else (DPO, independent auditor, annual DPIA) is outside code.

## G12. Contact and accountability (Act s.8(9), s.8(10))

**Ask:** Is the business contact of the DPO or the person who answers privacy questions shown in the app or site code? Is there a grievance path?

---

## Ready-made data types to name in findings

Aadhaar number, Aadhaar image, PAN, passport, voter ID, driving licence, bank account, IFSC, UPI ID, salary, payslip, Form 16, PF/UAN, ESIC, health record, insurance claim, biometric template, photo, signature, date of birth, phone, email, address, precise location, children's data, caste, religion, device identifiers, IP address, credentials.
