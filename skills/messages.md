# messages

## What it is

One message in a `conversation`. This is an STI base resource — always
create the specific subtype: **`user_messages`** (what you send) or
**`ai_messages`** (what comes back); **`summary_messages`** are
auto-generated recaps, not something you create.

## Role in the SOC 2 journey

The unit of exchange in every AI-assisted workflow (control troubleshooting,
policy drafting, vendor review, incident response). Sending is
straightforward — `POST /user_messages` with `content` and the
`conversation` relationship, which returns `meta.seq` and `meta.state`.
Receiving is async: an `ai_messages` reply moves through
`meta.state`: `pending` → `streaming` → `completed` (or `failed`). The
reliable way to see it land is to **poll the conversation**
(`GET /conversations/:id?include=messages`), not to poll the message
directly. A failed AI message can be retried with
`PATCH /ai_messages/:id/retry`.

## Commonly used with

- **`conversations`** — the thread this message belongs to.
- **`workstreams`** — the compliance subject this whole exchange is about.
