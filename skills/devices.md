# devices

## What it is

An employee's endpoint (laptop, phone, server, etc.) tracked for asset
inventory and posture (encryption, patch status), primarily fed by the
Klaayguard desktop agent's data collection.

## Role in the SOC 2 journey

Fulfilled when the device is not a laptop (servers, phones, etc. auto-pass —
no action needed), OR it is a laptop that has received Klaayguard-reported
data. This area resolves naturally as Klaayguard is rolled out to the
org — there isn't much direct API work here beyond monitoring
`compliance_stats`' `devices` area as installs land.

## Commonly used with

- **`account_users`** — whose device this is.
- Klaayguard's own data-collection endpoints live under a separate
  `klaayguard` namespace, not this JSON:API resource surface.
