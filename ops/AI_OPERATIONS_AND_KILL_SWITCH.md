# FinFamily AI Operations, Abuse Controls & Emergency Kill-Switch

## 1. Overview
FinFamily integrates an AI financial coach (`FinBuddy 🤖` for children, `Coach Nour` for parents).
To protect user privacy, family funds, and operational budgets, the system implements multi-tiered controls:
1. **Emergency Kill-Switch**: Disables AI service globally in under 5 seconds.
2. **Family & User Daily Quotas**: Enforces daily caps on AI chat requests.
3. **Monthly Spend Ceiling**: Alerts and caps estimated upstream provider spend.
4. **Zero-PII Logging**: Guarantees sensitive data is excluded from application logs.

---

## 2. Emergency Kill-Switch Procedure

If unexpected model behavior, an upstream outage, or a security vulnerability is identified:

### Immediate Activation
Set either of the following environment variables in the production environment:
```bash
AI_ENABLED="false"
# or
AI_KILL_SWITCH="true"
```

### Impact & Client Behavior
- The backend immediately bypasses external provider calls and returns:
  ```json
  {
    "reply": "خدمة المساعد الذكي معطلة مؤقتاً للصيانة والتحديث. سنعود قريباً!",
    "status": "emergency_disabled",
    "request_id": "<uuid>"
  }
  ```
- The mobile application displays a friendly maintenance notice bubble without breaking the user experience.

---

## 3. Quota Management & Spend Ceilings

### Configuration Parameters
- `AI_DAILY_FAMILY_QUOTA`: Default `100` requests/day per family.
- `AI_DAILY_USER_QUOTA`: Default `50` requests/day per user.
- `AI_SPEND_CEILING_USD`: Default `$50.00` monthly budget ceiling.

### Exceeded Quota Response
When a family exhausts their daily quota:
```json
{
  "reply": "تم الوصول للحد اليومي المسموح به لمحادثات المساعد الذكي للأسرة. يُرجى المحاولة غداً.",
  "status": "quota_exceeded",
  "request_id": "<uuid>"
}
```

---

## 4. Privacy & Zero-PII Log Auditing

### Logging Guardrails
- **No Request Bodies**: Full prompt text and user chat messages are never logged at INFO or WARNING levels.
- **Redaction Verification**: Any logged contextual data passes through `redact_sensitive_text`, stripping Egyptian phone numbers, National IDs, credit cards, and credentials.
- **No Stack Traces**: Public HTTP 500 error responses return generic error messages with `request_id`, omitting internal stack traces, SQL strings, and file paths.
