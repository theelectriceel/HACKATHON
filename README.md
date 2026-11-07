# PROMPTGUARD

### Control the action. Keep the evidence.

PROMPTGUARD is security middleware for AI applications and agents. It inspects untrusted content, authorizes tool calls before execution, and records what happened.

Its central principle is simple: **a model requesting an action does not make that action authorized.**

PROMPTGUARD combines local prompt-injection detection with explicit permissions, stateful tool-sequence restrictions, and policies shared across different agents.

## The demo

The application has three parts:

| Part | Purpose |
|---|---|
| **RAG without PROMPTGUARD** | Runs
