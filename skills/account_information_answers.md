# account_information_answers

## What it is

An answer to a company-profile question (e.g. basic organizational facts,
"do you have a written security policy") for this account.

## Role in the SOC 2 journey

The "quick win" area: most answers are auto-crawled during onboarding
already, and just need a human to confirm them. `manual` answer source means
a user actually reviewed and confirmed it — that's when it counts as
fulfilled, not merely having a crawled value present. Because most of the
work is already done by the time you look at this area, it's the fastest way
to get an area to 100% and build early momentum in the compliance journey.

This area is mostly handled through the onboarding workstream (AI walks the
user through reviewing/confirming each answer) rather than direct,
one-by-one API calls.

## Commonly used with

- **`account_information_questions`** — the question catalog these answers
  respond to.
- **`workstreams`** (`topic: "onboarding"`) — the primary way this area
  actually gets worked.
