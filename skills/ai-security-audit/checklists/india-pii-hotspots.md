<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# India PII hotspots (HR, payroll, KYC, fintech)

Load when the app stores or processes personal data of people in India: HRMS, payroll, attendance, recruitment, LMS, staffing, KYC, lending, insurance, health. These are the places real Indian VAPT reports most often find critical issues. For a full DPDP Act review, run `/ai-dpdp-audit`; this file is the security slice.

## Data that raises severity

Aadhaar number or image, masked Aadhaar done wrong (full number in API, mask only in UI), PAN, passport, voter ID, driving licence, bank account and IFSC, UPI ID, salary and CTC, Form 16 / TDS, PF (UAN) and ESIC numbers, medical and insurance records, background-verification reports, biometric attendance templates, photos and signatures, children's data (dependants), caste or religion fields, precise location.

## Where to look

| Hotspot | What goes wrong |
|---|---|
| Payslip, Form 16, offer and relieving letter downloads | IDOR by employee ID or document ID; sequential IDs; token in URL reused across users |
| Employee directory and org chart APIs | Returning full records (salary, PAN, bank, DOB) to every employee; search that reveals hidden fields |
| Bulk export (Excel, CSV, PDF) | Any manager or employee can export the whole company; exports stored in a shared public folder; links that never expire |
| Attendance and leave APIs | `employeeId` from the request; managers reaching employees outside their team; geo-location data exposed |
| KYC and onboarding uploads | Aadhaar/PAN images in public buckets; file names containing the number; OCR text stored unencrypted and logged |
| Aadhaar handling | Full 12-digit number stored where only the last 4 are needed; unmasked in API responses or logs; Aadhaar used as a primary key or in URLs |
| Bank details change flow | No re-authentication or approval before payout account changes (payroll diversion fraud) |
| Payroll run and approval | Maker-checker bypass; a user approving their own reimbursement; state replay of approved runs |
| Candidate and recruitment portals | Resumes in public storage; candidate PII readable by other candidates; open search of applicants |
| Integrations (biometric devices, PF/ESIC portals, banks, SMS/OTP gateways, WhatsApp APIs) | Credentials in code; callbacks without signature verification; OTP gateways without rate limits |
| Multi-tenant HR SaaS | `orgId`/`companyId` from the request; cross-company reads; shared caches keyed without tenant |
| Logs and analytics | Aadhaar, PAN, phone, OTP, salary written to logs, error trackers (Sentry), or analytics events |

## Checks to add to the hunter's unit

1. Build the authorization matrix for every endpoint that touches the data above (see [api-authorization.md](api-authorization.md)).
2. For each data type, record where it is stored, whether it is encrypted at rest, who can read it in the API, and whether it appears in logs. This also feeds the DPDP audit.
3. Look for masking done only in the frontend.
4. Check document storage ACLs and URL lifetimes.
5. Check approval and maker-checker flows for self-approval and replay.

## Impact wording

Name the data types and the scale the code allows ("any of the company's employees", "every tenant"). Do not quantify records you did not see; source review shows what is reachable, not how many rows exist. Mention that the confirmed issue puts at risk compliance with Section 8(5) of the DPDP Act 2023 (reasonable security safeguards) and, where a breach is likely to have occurred, the breach-intimation duty; not a legal conclusion.
