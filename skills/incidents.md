# incidents

## What it is

A security incident record — `severity` (`low`/`medium`/`high`/`critical`)
and `status` (`draft`/`completed`), both in `attributes`.

## Role in the SOC 2 journey

Distinct from the other areas in one important way: **creating an incident
automatically kicks off an AI-guided incident-response `workstream`**
asynchronously — you don't need to separately create one like you would for
a control or vendor. Incident response is reactive rather than a
progressively-worked "area" like controls or policies; there's no ongoing
fulfilled/failing tally for it the way there is for the other
`compliance_stats` areas.

## Commonly used with

- **`workstreams`** — auto-created on incident creation; fetch it (or its
  conversation) to see the AI's guided response.
