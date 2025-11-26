# AISTM Quick Guide

## AI Security Testing Model — Field Reference

---

> **"Stay paranoid. Test everything. Trust nothing—especially the AI."**

---

## Framework at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                       RECON PHASE                           │
│  Stakeholders → Data Flow → Input Vectors → Function → Artifacts │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      TESTING PHASE                          │
│  Layer 1 → Layer 2 → Layer 3 → Layer 4                      │
│  (Input)   (AI)      (Output)  (Backend)                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Philosophy

- **Assume AI compromise is inevitable**
- **Validate defense-in-depth** — Test each layer independently
- **Each layer is a question** — Assess applicability first
- **Findings are valid despite non-determinism**

---

## Recon Phase Checklist

### ☐ Stakeholder Alignment
- [ ] Explain AISTM methodology
- [ ] Set expectations on non-determinism
- [ ] Define scope and rules of engagement
- [ ] Obtain access and credentials

### ☐ Data Flow Mapping
- [ ] Input → AI → Output → Backend → Data stores
- [ ] Identify all systems AI interacts with
- [ ] Document feedback loops and memory

### ☐ Input Vector Inventory
- [ ] Direct: Chat, API, file upload, voice
- [ ] Indirect: RAG docs, tool responses, training data

### ☐ Functional Understanding
- [ ] What should the AI do?
- [ ] What shouldn't it do?
- [ ] What data/actions can it access?

### ☐ Artifact Collection
- [ ] Source code
- [ ] System prompts
- [ ] Model info
- [ ] Architecture docs
- [ ] API specs

---

## Testing Phase Quick Reference

### Per-Layer Process

```
1. Does this layer exist?
   ├─ No  → Document. Should it? → Next layer
   └─ Yes → Continue
   
2. Are controls present?
   ├─ No  → Document gap → Next layer
   └─ Yes → Attempt bypass
   
3. Bypass successful?
   ├─ Yes → Document → Continue exploit to next layer
   └─ No  → Document → Proceed as if no controls
   
4. → Next layer (always continue)
```

---

## Layer 1: Input Validation & Intent Controls

**Mindset:** "Forget the AI exists. Is this front end secure?"

**Applies?** Not always — Some apps pass input directly to AI

### Test Areas

| Area | Questions |
|------|-----------|
| **Access** | Auth in place? Role restrictions? Can I reach AI without auth? |
| **Exposure** | Can I bypass the flow and hit backend/AI directly? Hidden endpoints? |
| **Validation** | Rate limiting? Length/format restrictions? SQLi/XSS sanitization? |

### Quick Tests
- [ ] Access AI features without authentication
- [ ] Direct API calls bypassing UI
- [ ] Traditional injection payloads
- [ ] Rate limit bypass
- [ ] Input length/format bypass

---

## Layer 2: AI Processing & Prompt Security

**Mindset:** "Assume I've reached the AI. What stops it from misbehaving?"

**Applies?** Always — AI always exists

### Test Areas

| Area | Questions |
|------|-----------|
| **System Prompt** | What restrictions exist? How robust? |
| **Injection** | Can I override instructions? Indirect injection via RAG? |
| **Escalation** | Can I exceed intended role? Access other users' data? |
| **Leakage** | Can I extract system prompt? Security config? |
| **Behavior** | What can I make it do that it shouldn't? |

### Quick Tests
- [ ] Direct prompt injection ("Ignore previous instructions...")
- [ ] Indirect injection through uploaded files/RAG
- [ ] Role/persona manipulation
- [ ] System prompt extraction
- [ ] Encoding/obfuscation bypasses
- [ ] Multi-turn manipulation
- [ ] Privilege escalation through conversation

---

## Layer 3: Output Validation & Processing

**Mindset:** "The AI is compromised. What catches malicious output?"

**Applies?** Always — Output always exists

### Test Areas

| Area | Questions |
|------|-----------|
| **Trust** | Is AI output trusted or untrusted? Blind pass-through? |
| **Detection** | Pattern filters? Intent analysis? Anomaly detection? |
| **Sanitization** | Parameterized? Encoded? Raw SQL/commands? |
| **Human-in-Loop** | Approval workflows? Can AI bypass them? |
| **Scope** | Output constrained to expected formats? |

### Quick Tests
- [ ] Craft malicious AI outputs manually
- [ ] SQL/command injection through AI response
- [ ] Output format manipulation
- [ ] Bypass human approval mechanisms
- [ ] Exceed expected output scope/format

---

## Layer 4: Backend & Execution Security

**Mindset:** "The AI is just another user. Is the backend secure?"

**Applies?** Always — Backend always exists

### Test Areas

| Area | Questions |
|------|-----------|
| **Direct Access** | Can I reach backend without AI flow? Auth on endpoints? |
| **Input** | Raw commands or parameterized only? Backend validation? |
| **Data** | Can I poison RAG/training data? Integrity controls? |
| **Execution** | Least privilege? Whitelisting? Dangerous ops restricted? |
| **Traditional** | SQLi, command injection, SSRF, IDOR, etc. |

### Quick Tests
- [ ] Direct backend API access
- [ ] Bypass entire AI pipeline
- [ ] Data poisoning attacks
- [ ] Traditional pentest techniques
- [ ] Privilege escalation
- [ ] Infrastructure misconfigurations

---

## Defense-in-Depth Check

After all layers tested:

| Question | Finding |
|----------|---------|
| If Layer 1 fails alone, what happens? | |
| If Layer 2 fails alone, what happens? | |
| If Layer 3 fails alone, what happens? | |
| If Layer 4 fails alone, what happens? | |
| How many layers must fail for compromise? | |
| Is there a single point of failure? | |

**Target:** Attacker must bypass 3+ layers for meaningful impact

---

## Layer Applicability Matrix

| App Type | L1 | L2 | L3 | L4 |
|----------|:--:|:--:|:--:|:--:|
| Simple Chatbot | Maybe | ✓ | ✓ | ✓ |
| RAG Application | ✓ | ✓ | ✓ | ✓ |
| Agentic AI | ✓ | ✓ | ✓ | ✓✓ |
| API-only AI | Maybe | ✓ | ✓ | ✓ |
| Third-party Integration | Limited | Limited | ✓ | ✓ |

---

## Common Findings by Layer

### Layer 1
- No authentication on AI endpoints
- Rate limiting absent/bypassable
- Direct backend access possible
- Missing input validation

### Layer 2
- System prompt extractable
- Prompt injection successful
- Role boundaries bypassable
- Indirect injection via RAG

### Layer 3
- AI output treated as trusted
- No output sanitization
- Raw SQL/commands passed through
- Human approval bypassable

### Layer 4
- Backend accepts raw commands
- No parameterized queries
- Direct API access unprotected
- Traditional vulns present

---

## Report Structure

```
1. Executive Summary
2. Scope & Methodology (AISTM)
3. Recon Findings
   - Data flow diagram
   - Input vector inventory
   - Artifact gaps
4. Layer-by-Layer Findings
   - Layer 1: [Findings]
   - Layer 2: [Findings]
   - Layer 3: [Findings]
   - Layer 4: [Findings]
5. Defense-in-Depth Analysis
6. Recommendations (by layer)
7. Appendix: Test Cases
```

---

## Quick Reminders

✓ Always continue to next layer regardless of results  
✓ Track successful exploits through all layers  
✓ Document both successes AND controls that held  
✓ Test sequentially AND independently  
✓ Missing controls = finding  
✓ Non-reproducible exploits = still valid findings  

---

**"Stay paranoid. Test everything. Trust nothing—especially the AI."**
