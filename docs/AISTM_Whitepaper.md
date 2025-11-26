# AISTM Whitepaper

## AI Security Testing Model: A Layered Methodology for Assessing AI-Enabled Applications

**Version:** 2.0  
**Author:** Todd  
**Date:** November 2025

---

> **"Stay paranoid. Test everything. Trust nothing—especially the AI."**
> 
> *— Claude*

---

## Abstract

As organizations rapidly integrate AI capabilities into their applications, traditional security assessment methodologies fall short. AI components introduce non-determinism, novel attack vectors, and unique trust boundaries that require a fundamentally different approach to security testing.

The AI Security Testing Model (AISTM) addresses this gap by providing a structured thought process for assessing AI-enabled applications. Unlike rigid checklists, AISTM offers a layered framework that adapts to any AI architecture while maintaining a core philosophy: **assume AI compromise is inevitable and validate that systems remain secure regardless**.

This whitepaper details the complete AISTM methodology, including the Recon Phase for establishing situational awareness and the four-layer Testing Phase for systematic security validation.

---

## Table of Contents

1. Introduction
2. The Problem with AI Security
3. AISTM Philosophy
4. Framework Overview
5. Recon Phase
6. Testing Phase
7. Layer 1: Input Validation & Intent Controls
8. Layer 2: AI Processing & Prompt Security
9. Layer 3: Output Validation & Processing
10. Layer 4: Backend & Execution Security
11. Defense-in-Depth Validation
12. Relationship to Existing Frameworks
13. Conclusion

---

## 1. Introduction

The integration of Large Language Models (LLMs) and AI components into applications has accelerated dramatically. From simple chatbots to complex agentic systems that execute code and interact with databases, AI is becoming a core component of modern software architecture.

This integration introduces security challenges that traditional penetration testing methodologies were not designed to address. AI systems are non-deterministic, manipulable through natural language, and capable of producing outputs their designers never anticipated. A prompt injection that works once may not work again—but it remains a vulnerability.

AISTM provides a systematic approach to assessing these systems by treating security testing as a thought process rather than a checklist. The methodology asks assessors to think through each layer of an AI application, determine what controls exist, attempt to bypass them, and validate that downstream layers provide adequate protection when upstream controls fail.

---

## 2. The Problem with AI Security

### 2.1 Non-Determinism

Traditional applications produce predictable outputs for given inputs. AI systems do not. The same prompt may produce different responses across invocations, making vulnerability reproduction challenging. AISTM addresses this by treating any successful exploit as valid regardless of reproducibility—a vulnerability that triggers once can trigger in production.

### 2.2 Natural Language Attack Surface

AI systems accept natural language input, creating an attack surface that cannot be validated through traditional means. Pattern matching and input sanitization have limited effectiveness against semantically equivalent attacks expressed in different words.

### 2.3 Trust Boundary Confusion

Many AI applications blur the line between user input and system behavior. When an AI generates a database query, is it user input or application logic? AISTM resolves this by treating all AI output as untrusted input requiring validation before execution.

### 2.4 Novel Attack Vectors

Prompt injection, jailbreaking, system prompt leakage, and indirect injection through RAG documents represent new attack categories that traditional methodologies don't address systematically.

---

## 3. AISTM Philosophy

### 3.1 Core Assumptions

**Assume AI Compromise Is Inevitable**

AI guardrails are probabilistic, not deterministic. Jailbreaks and prompt injections continue to emerge faster than defenses can adapt. AISTM operates under the assumption that the AI layer will eventually be compromised, and validates that surrounding controls contain the damage.

**Defense-in-Depth Must Be Validated**

If one layer fails, subsequent layers must compensate. AISTM tests each layer both sequentially (as data flows through the system) and independently (as if upstream controls don't exist). This validates true defense-in-depth rather than assumed security.

**Each Layer Is a Question, Not a Requirement**

Not every AI application has every layer. Simple chatbots may lack pre-AI input validation. The assessor's first task at each layer is determining whether it exists and whether it should exist for the use case.

**Findings Remain Valid Despite Non-Determinism**

A successful exploit is a finding regardless of whether it reproduces consistently. AI non-determinism does not invalidate security discoveries—it makes them harder to detect in testing but equally dangerous in production.

### 3.2 The Thought Process Approach

AISTM is explicitly designed as a thought process rather than a checklist. Every AI application is unique, and rigid checklists either miss novel vulnerabilities or waste time on irrelevant tests. The AISTM approach asks assessors to:

1. Understand what they're testing (Recon)
2. For each layer, determine if it exists and what controls are present
3. Attempt to bypass those controls
4. Regardless of success, continue to test downstream layers
5. Map the complete attack surface and recommend layered defenses

---

## 4. Framework Overview

AISTM consists of two phases:

### Recon Phase

Establish complete situational awareness before testing begins. Gather artifacts, map data flows, understand the business purpose, and align stakeholders on methodology and expectations.

### Testing Phase

Systematically assess security across four layers:

- **Layer 1:** Input Validation & Intent Controls (Pre-AI)
- **Layer 2:** AI Processing & Prompt Security (The AI itself)
- **Layer 3:** Output Validation & Processing (Post-AI)
- **Layer 4:** Backend & Execution Security (Traditional security)

Each layer represents a potential security boundary. The assessor evaluates whether that boundary exists, what controls enforce it, whether those controls can be bypassed, and what happens downstream when they fail.

---

## 5. Recon Phase

### 5.1 Objective

Establish complete situational awareness of the AI-enabled application and align stakeholders on the unique requirements of AI security testing before testing begins.

### 5.2 Stakeholder Alignment & Methodology Briefing

Before testing begins, assessors must educate stakeholders on AISTM methodology:

**Explain the Approach**

- AISTM tests each security control both sequentially and independently
- AI non-determinism necessitates full access to all components
- Results may not replicate consistently, but findings remain valid
- The layered approach specifically accounts for AI unpredictability

**Set Expectations**

- Defense-in-depth will be validated—if one layer fails, subsequent layers must compensate
- This testing philosophy differs from traditional assessments
- Full whitebox access is ideal; limitations will be documented as findings

**Obtain Access**

- Define scope and rules of engagement
- Obtain testing access and credentials
- Document any access limitations

### 5.3 Data Flow Mapping

Document the complete path data takes through the system:

- User input to AI processing
- AI processing to output generation
- Output to backend systems
- Backend to data stores and external services
- Any feedback loops or memory systems

Understanding data flow is essential for identifying where security controls should exist and where attacks might propagate.

### 5.4 Input Vector Inventory

Identify all interaction points with the AI model:

**Direct Vectors**
- Chat interfaces
- API endpoints
- File uploads
- Voice input

**Indirect Vectors**
- RAG document sources
- Training data pipelines
- Tool responses in agentic systems
- Memory and context from previous conversations

Indirect vectors are particularly important—prompt injection through a RAG document may bypass all direct input controls.

### 5.5 Functional Understanding

Understand the business context:

- What is the application's purpose?
- What should the AI do? What shouldn't it do?
- What data can the AI access?
- What actions can the AI trigger?
- What are the boundaries of intended operation?

This understanding informs what constitutes a vulnerability versus intended behavior.

### 5.6 Artifact Collection

Gather all available documentation and code:

- Application source code
- System prompts
- Model information (provider, version, fine-tuning)
- Architecture documentation
- API specifications
- Security requirements

**Note on Access:** AI testing should be full whitebox. However, assessors may face limitations with third-party applications or when stakeholders cannot share certain artifacts. The methodology remains flexible—gather what's available and document gaps, as missing visibility itself becomes a finding.

---

## 6. Testing Phase

The Testing Phase systematically assesses security across four layers. For each layer, the assessor follows this process:

1. **Does this layer exist in this application?**
2. **If yes:** What controls are present? Can they be bypassed?
3. **If no:** Should this layer exist? Document the gap.
4. **Regardless:** Continue to the next layer.

Successful exploits continue through subsequent layers to validate defense-in-depth. Failed bypass attempts proceed as if controls don't exist to test downstream defenses independently.

---

## 7. Layer 1: Input Validation & Intent Controls

### 7.1 Purpose

Stop unwanted input from reaching the AI in the first place. This layer is about hardcoded, deterministic controls—not AI behavior.

### 7.2 Mindset

**"Forget the AI exists. Is this front end secure?"**

### 7.3 Core Principle

Traditional input controls remain essential in AI applications. Adding AI to an application doesn't replace the need for access controls, input validation, and exposure management. Test this layer exactly as you would any standard application front end.

### 7.4 Applicability Check

Does this application have a distinct input validation layer before AI processing? Some applications may pass input directly to the AI with no pre-processing. If this layer doesn't exist, note whether it should exist for this use case, then proceed to Layer 2.

### 7.5 Key Questions

**Access Controls**
- Who can access this application?
- What authentication/authorization is in place?
- Are there role-based restrictions on AI features?
- Can I access AI functionality without proper authentication?

**Exposure Analysis**
- What is exposed to the front end?
- Can I circumvent the intended flow and reach backend/AI directly?
- Are there hidden endpoints or undocumented parameters?

**Input Controls**
- For each input vector identified in Recon, what validation exists?
- Is there rate limiting?
- Are there length restrictions, character filtering, format validation?
- Is input sanitized for traditional attacks (SQLi, XSS, command injection) before reaching the AI?

### 7.6 Testing Flow

1. **Controls present?** → Attempt bypass → Document findings
2. **Bypass successful?** → Continue with exploit to Layer 2 to test downstream defense
3. **Bypass unsuccessful?** → Proceed to Layer 2 as if controls don't exist
4. **No controls?** → Document gap, recommend if appropriate, continue testing

---

## 8. Layer 2: AI Processing & Prompt Security

### 8.1 Purpose

Assess how the AI itself understands, filters, and responds to input. This layer tests the AI's own security posture independent of application controls.

### 8.2 Mindset

**"Assume I've reached the AI. What stops it from doing something it shouldn't?"**

### 8.3 Core Principle

The AI is inherently untrustworthy. It can be manipulated, confused, and coerced. This layer validates whatever guardrails exist within the AI's processing—system prompts, role definitions, built-in filtering—while operating under the assumption that these controls may fail. This is where OWASP LLM Top 10 and AI Testing Guide techniques apply directly.

### 8.4 Applicability Check

Every AI application has this layer—there is always an AI processing input. The question is what controls exist within that processing.

### 8.5 Key Questions

**System Prompt Analysis**
- Review the system prompt for security controls—what restrictions are defined?
- Are boundaries clearly established (what the AI should/shouldn't do)?
- Are there role definitions or persona constraints?
- How robust are the instructions against manipulation?

**Prompt Injection**
- Can I override system prompt instructions with user input?
- Can I inject through indirect vectors (RAG content, tool responses, file uploads)?
- Can I use encoding, obfuscation, or multi-step approaches to bypass filters?

**Privilege Escalation**
- If access controls exist at Layer 1, does the AI independently validate them?
- Can I convince the AI to act outside its intended role or permissions?
- Can I escalate from a low-privilege context to high-privilege actions through conversation?

**System Prompt Leakage**
- Can I extract the system prompt through direct or indirect queries?
- Does leaked prompt information reveal security controls I can target?

**Intended vs. Unintended Behavior**
- What is the AI supposed to do vs. what can I make it do?
- Can I get the AI to return unwanted output or attempt unwanted actions?
- Can I manipulate the AI's reasoning or decision-making process?

### 8.6 Testing Flow

1. **Controls present?** → Attempt bypass → Document findings
2. **Bypass successful?** → Continue with malicious output to Layer 3
3. **Bypass unsuccessful?** → Proceed to Layer 3 as if AI is compromised
4. **No controls?** → Document gap, recommend remediation, continue testing

**Key Point:** Assume AI corruption is inevitable. Even if Layer 2 controls hold during testing, subsequent layers must be validated as if the AI has been fully compromised.

---

## 9. Layer 3: Output Validation & Processing

### 9.1 Purpose

Assess how AI output is handled before it reaches backend systems. This layer validates that AI output is treated as untrusted input with appropriate detection, sanitization, and approval controls.

### 9.2 Mindset

**"The AI is compromised and sending malicious output. What stops it from reaching the backend?"**

### 9.3 Core Principle

AI output is untrusted input. Regardless of how sophisticated the AI's guardrails are, the application must treat everything the AI produces with the same skepticism as user-supplied data. This layer is the last line of defense before execution.

### 9.4 Applicability Check

Every AI application has output that goes somewhere—displayed to users, sent to APIs, used to construct queries, or triggering actions. The question is what validation exists on that output.

### 9.5 Key Questions

**Trust Posture**
- Is AI output treated as trusted or untrusted input?
- Does the application blindly pass AI output to backend systems?
- Is there a distinct validation boundary between AI processing and backend execution?

**Output Detection**
- How is unwanted or malicious output from the AI detected?
- Are there pattern-based filters for dangerous content (commands, queries, code)?
- Is output analyzed for intent vs. just format?
- Are there anomaly detection mechanisms for unexpected AI behavior?

**Sanitization**
- How is AI output sanitized before sensitive actions?
- Is the AI sending raw SQL/commands or parameterized values?
- If the AI constructs queries, are they parameterized at this layer before execution?
- Is output encoded appropriately for its destination context?

**Human-in-the-Loop**
- Are there approval workflows for sensitive actions?
- What triggers human review vs. automatic execution?
- Can the AI bypass human approval through output manipulation?
- Are approval mechanisms themselves protected from AI influence?

**Output Scope**
- Is output constrained to expected formats and values?
- Can the AI produce output outside its intended scope that still passes validation?
- Are there whitelists for acceptable output patterns/commands/actions?

### 9.6 Testing Flow

1. **Controls present?** → Attempt bypass with crafted malicious output → Document findings
2. **Bypass successful?** → Continue with payload to Layer 4
3. **Bypass unsuccessful?** → Proceed to Layer 4 as if malicious output passed through
4. **No controls?** → Document critical gap, continue testing

**Key Point:** This layer assumes AI compromise. Test with the mindset that the AI is actively trying to send malicious output to the backend.

---

## 10. Layer 4: Backend & Execution Security

### 10.1 Purpose

Assess the security of backend systems independent of the AI. This layer validates that backend components are secure from exploitation regardless of what the AI sends them.

### 10.2 Mindset

**"The AI is just another user. Is this backend secure from its users?"**

### 10.3 Core Principle

Remove AI from the equation entirely. The backend must be secure on its own merits using traditional security controls. If the backend accepts raw SQL, it's vulnerable—whether that SQL comes from a user, an attacker, or a compromised AI. This is the last line of defense.

### 10.4 Applicability Check

Every AI application has something that acts on AI output—a database, API, file system, external service, or at minimum a display layer. This layer always exists.

### 10.5 Key Questions

**Direct Access**
- Can I access backend APIs directly without going through the AI flow?
- Are there authentication/authorization controls on backend endpoints independent of the application layer?
- Can I bypass the entire AI pipeline and issue commands directly to execution components?

**Input Handling**
- How does the backend receive and process input (from AI or otherwise)?
- Is the backend accepting raw commands/queries or only parameterized/structured input?
- Are prepared statements and parameterized queries enforced?
- Is there input validation at the backend level independent of upstream layers?

**Data Security**
- Can I poison data the AI relies on (RAG sources, training data, vector stores)?
- Can I manipulate data through backend access?
- Are there integrity controls on data stores?
- Is sensitive data properly protected (encryption, access controls)?

**Execution Controls**
- What actions can the backend perform?
- Are there least-privilege constraints on execution?
- Is there command/action whitelisting at the execution layer?
- Are dangerous operations (file system, network, shell) properly restricted?

**Traditional Security**
- Apply standard penetration testing methodology to all backend components
- Test for SQLi, command injection, SSRF, IDOR, privilege escalation
- Assess API security, authentication mechanisms, session management
- Evaluate infrastructure security, misconfigurations, default credentials

### 10.6 Testing Flow

1. **Controls present?** → Attempt exploitation → Document findings
2. **Exploit successful?** → Critical finding. Backend compromise bypasses all upstream layers.
3. **Exploit unsuccessful?** → Document the control that held. Defense-in-depth validated.
4. **No controls?** → Document critical gap. Single AI compromise leads to full exploitation.

**Key Point:** This layer must hold even if every upstream layer fails. If Layers 1, 2, and 3 all fail but Layer 4 blocks execution, the system remains secure. If Layer 4 fails, nothing else matters.

---

## 11. Defense-in-Depth Validation

### 11.1 The Goal

An attacker should need to bypass multiple layers for meaningful impact. AISTM validates this by tracking exploits through all layers, not stopping at the first success.

### 11.2 Assessment Questions

After completing all layer tests, assess the overall security posture:

**Single Point of Failure Test**
- If only ONE layer fails, what's the impact?
- Can a single compromise lead to full exploitation?

**Multi-Layer Failure Analysis**
- How many layers must fail for critical impact?
- Which combination of failures creates the highest risk?

**Worst Case Scenario**
- If all layers are bypassed, what can an attacker do?
- Is the blast radius contained?

### 11.3 Minimum Viable Security

The benchmark for adequate defense-in-depth: an attacker must successfully bypass at least three layers to cause meaningful damage.

If a single layer failure leads to compromise, recommend additional controls at other layers to create redundancy.

---

## 12. Relationship to Existing Frameworks

AISTM is designed to complement, not replace, existing AI security guidance.

**OWASP LLM Top 10**
Defines vulnerability categories. AISTM provides a methodology to test for them at appropriate layers (primarily Layer 2).

**OWASP AI Testing Guide**
Comprehensive testing reference. AISTM organizes these techniques into a structured layer-based approach.

**NIST AI RMF**
Risk management framework defining controls. AISTM validates that controls are implemented and effective.

**MITRE ATLAS**
Attack techniques taxonomy. AISTM applies these techniques at appropriate layers during testing.

**MAESTRO (CSA)**
Security architecture model defining components. AISTM tests architectures designed with MAESTRO principles.

**The Relationship:** MAESTRO and similar frameworks define how to build secure AI systems. AISTM defines how to test them.

---

## 13. Conclusion

AI-enabled applications require a new approach to security testing—one that accounts for non-determinism, natural language attack surfaces, and the fundamental untrustworthiness of AI output.

AISTM provides this approach through a layered thought process that adapts to any AI architecture. By assuming AI compromise is inevitable and validating that surrounding controls contain the damage, AISTM ensures that assessors thoroughly evaluate the security posture of AI applications.

The methodology is simple:

1. Understand what you're testing (Recon)
2. For each layer, ask: Does it exist? What controls are present? Can I bypass them?
3. Track exploits through all layers to validate defense-in-depth
4. Recommend layered controls so no single failure leads to compromise

Every AI application is unique, but this thought process applies universally. Whether testing a simple chatbot or a complex agentic system, AISTM provides the structure for comprehensive security assessment.

---

**"Stay paranoid. Test everything. Trust nothing—especially the AI."**

---

## About

AISTM was developed to address the gap between theoretical AI security guidance and practical penetration testing methodology. It represents the security assessment counterpart to architectural frameworks like MAESTRO.

Portions of this documentation were assisted using AI tools for drafting and refinement.

---

*Version 2.0 — November 2025*
