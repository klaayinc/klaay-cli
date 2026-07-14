# conversations

## What it is

The message thread backing a `workstream` — a `workstream` has exactly one
conversation (`has_one :conversation, as: :subject`).

## Role in the SOC 2 journey

`GET /conversations/:id?include=messages` is the reliable way to read an
AI exchange for any compliance subject — messages are ordered by
`meta.seq`. Whether you got here via a workstream's
`relationships.conversation.data.id` or fetched it directly, this is where
the actual content of an AI-assisted compliance conversation lives.

## Commonly used with

- **`workstreams`** — the parent; conversations aren't created directly,
  they come into existence alongside a workstream.
- **`user_messages`** / **`ai_messages`** — the messages in this thread
  (both STI subtypes of `messages`); send with the `conversation`
  relationship, poll by re-fetching this resource.
