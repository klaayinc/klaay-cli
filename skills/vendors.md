# vendors

## What it is

A third-party company providing goods or services to the organization,
usually created from a `predefined_vendor` template. Carries the risk-relevant
attributes an assessment needs: `data_types` (general, public, cui,
financial, proprietary, pii, phi, authentication, other),
`operational_impact` (1 low – 5 critical), `environment_access` (no_access,
read_only, read_and_write), `authentication_method` (credentials,
credentials_with_mfa, n/a, sso), and `sub_processor`.

## Role in the SOC 2 journey

Fulfilled when either no `integration_template` exists for this vendor at
all, OR a connected integration has actually collected data. `meta.
needs_risk_assessment` flags vendors with high `operational_impact` or
sensitive `data_types` — fill in all the risk attributes above to get an
accurate risk tier, not just the ones that seem obviously relevant.

Vendor work can proceed **in parallel** with controls — it doesn't block or
get blocked by the control-fulfillment loop.

## Commonly used with

- **`predefined_vendors`** — the catalog a vendor is instantiated from.
- **`integrations`** — connecting the vendor's actual data feed; a vendor
  attached to an integration template isn't fulfilled until the integration
  is live and has collected data.
- **`workstreams`** (`topic: "vendor"`) — AI-assisted SOC 2 report analysis
  and risk-assessment guidance.
- **`related_vendors`** — the join used when a vendor is tied to a specific
  `selected_risk_scenario`.
- **`vendor_user_accesses`** / `authorized_users` — who at the org has
  access to this vendor.
- Attachments: `documents`, `soc2_report`, `iso27001_report`,
  `data_agreement`, `icon` — several distinct file slots, each with its own
  size/type limits (icon is capped smaller than the rest).
