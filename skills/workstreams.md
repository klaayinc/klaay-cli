# workstreams

## What it is

An AI-assisted conversation anchored to one compliance subject — a
`selected_control`, `vendor`, `policy`, `selected_risk_scenario`,
`incident`, `device`, `domain`, `task`, `onboarding`, or others (the
`subject` relationship is polymorphic).

## Role in the SOC 2 journey

This is **the** way to get AI help on any resource in the compliance
program — explaining what a control requires, drafting policy content,
analyzing a vendor's SOC 2 report, guiding incident response, etc. Creating
one with a `topic`+`subject` pair that already has a workstream returns the
**existing** one rather than creating a duplicate, so it's safe to call
repeatedly without checking first.

The full loop: create (or reuse) the workstream → read
`relationships.conversation.data.id` off the response → send a
`user_messages` on that conversation → poll the conversation (not the
message) until the AI's reply reaches `meta.state: "completed"`.

## Commonly used with

- **`conversations`** — the message thread itself; `include=messages` when
  fetching a workstream, or fetch the conversation directly.
- **`user_messages`** / **`ai_messages`** — sending and receiving in that
  conversation (both are STI subtypes of `messages`).
- Whatever the `subject` is — `selected_controls`, `vendors`, `policies`,
  `selected_risk_scenarios`, `incidents`, etc.
