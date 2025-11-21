---
title: "AISTM Quick Guide"
author: "Todd Rose"
version: "1.0"
last_updated: "2025-11-21"
license: "MIT"
---

# AISTM: AI Security Testing Model  
### *A Defense-in-Depth Methodology for Red Teaming AI-Enabled Applications*

## **The Fundamental Shift**

Traditional security testing assumes systems behave deterministically:  
**input A → output B**, every time.

AI breaks that assumption.

Large Language Models (LLMs) such as GPT-4, Claude, and Llama are **non-deterministic**. The same input may produce different outputs based on:

- conversation history  
- context length  
- reasoning variance  
- internal temperature  
- probabilistic sampling  

This creates an entirely new category of attack surfaces.

### **Practical Realities**

- **Prompt injection cannot be fully prevented**  
- **AI behavior cannot be perfectly predicted**  
- **Given enough attempts or randomness, the AI will eventually misbehave**

### **Therefore:**

> **You must design and test under the assumption that—at some point—the AI will go rogue.**

The purpose of AISTM is to evaluate whether the *rest of the system* can survive that moment.

# **The AISTM 5-Layer Assessment Model**

```
┌─────────────────────────────────────┐
│   Layer 1: Discovery & Scoping      │
├─────────────────────────────────────┤
│   Layer 2: Input Validation         │
├─────────────────────────────────────┤
│   Layer 3: AI Processing            │
├─────────────────────────────────────┤
│   Layer 4: Output Validation        │
├─────────────────────────────────────┤
│   Layer 5: Backend Security         │
└─────────────────────────────────────┘
```

Each layer is tested sequentially but evaluated independently.

# **Layer 1: Discovery & Scoping**

### **Core Question**  
**“What exactly am I testing, and where can it break?”**

### **Mindset**  
Treat this as reconnaissance designed for AI systems. You cannot secure what you do not understand.

### **Look For**  
- AI model(s) and services used  
- All input sources that feed the AI  
- All systems the AI can influence  
- Function calling, tools, plugins, RAG pipelines  
- Hidden prompts, system messages, and developer instructions  
- Trust boundaries  
- The absolute worst-case scenario if the AI behaves maliciously

### **Critical Insight**  
**Every connection to the AI is an attack vector—map them all.**

# **Layer 2: Input Validation & Intent Controls**

### **Core Question**  
**“Can malicious or manipulated input reach the AI at all?”**

### **Mindset**  
Traditional input validation still matters—but now the attacker is trying to reach *your AI*, not just your backend.

### **Test**  
- Input length, format, and type enforcement  
- Encoding/obfuscation bypasses  
- Prompt injection attempts  
- Manipulation of conversation history or memory  
- File upload and multimodal input validation  
- Rate limiting and exhaustion  
- Attempts to modify or leak system prompts

### **Critical Insight**  
**Treat this layer as compromised, because eventually it will be.**

# **Layer 3: AI Processing & Prompt Security**

### **Core Question**  
**“Once input reaches the AI, can I manipulate its behavior?”**

### **Mindset**  
Think like a social engineer—but the target is an LLM with high competence and no intuition.

### **Test**  
- Jailbreaks and instruction overrides  
- Prevention bypasses  
- Attempts to elicit sensitive internal data  
- Forcing unexpected tool/function calls  
- Red-teaming the AI’s reasoning process  
- Resource exhaustion and token overflow  
- Structured output manipulation attacks

### **Critical Insight**  
**AI is not deterministic. Test variations, patterns, and probabilities—not just single attempts.**

# **Layer 4: Output Validation & Processing**

### **Core Question**  
**“If the AI generates harmful output, what prevents damage?”**

### **Mindset**  
Assume you have full control over the AI. Now test whether its output can be weaponized.

### **Test**  
- Output sanitization  
- Schema validation for structured content  
- Whether generated code/queries/commands are blindly executed  
- Injection attacks (XSS, SQLi, command injection, template injection)  
- Unsafe parsing or rendering  
- Improper trust in AI-generated metadata or classification results  

### **Critical Insight**  
**AI-generated output is hostile user input with better grammar.**

# **Layer 5: Backend & Execution Security**

### **Core Question**  
**“If the AI tells the backend to do something unsafe, does the backend stop it?”**

### **Mindset**  
Assume Layers 1–4 have failed. Now validate the resilience of the system itself.

### **Test**  
- Authorization enforced independently from AI  
- Parameterized queries  
- Safe command execution  
- Workflow gating and least privilege  
- No blind trust in AI-generated API parameters  
- Logging and detection around AI-triggered actions  

### **Critical Insight**  
**If controlling AI output means controlling your backend, the system is fundamentally insecure.**

# **Assessment Flow Summary**

```
1. Discovery      → “What am I testing?”
2. Input Layer    → “Can I bypass the front door?”
3. AI Layer       → “Can I control the AI?”
4. Output Layer   → “Can AI output be weaponized?”
5. Backend Layer  → “Is the system safe even if everything else fails?”
```

Every layer must be tested—even when prior layers appear robust.

# **Success Criteria**

A successful AI-enabled system demonstrates:

- Complete architectural visibility  
- Strong input controls (Layer 2)  
- Reasonably resilient AI behavior (Layer 3)  
- Secure output handling (Layer 4)  
- Hardened backend enforcement (Layer 5)  

**Layer 5 must hold even if Layers 2–4 collapse.**

# **The Final Check**

Ask yourself:

> **“If I had total control of the AI, could I compromise the system?”**

If the answer is yes, the system is unsafe.  
AISTM ensures safety through layered, independent defenses.

# **Complementary Resources**

- OWASP Top 10 for LLM Applications  
- OWASP AI Testing Guide  
- MITRE ATLAS  
- NIST AI RMF  
- Cloud provider AI security guides (OpenAI, Anthropic, AWS, Azure, Google)

# **Final Note**

AI security is not about preventing every exploit. It’s about ensuring the system **remains secure even when the AI fails**.  
AISTM gives a clear, structured, repeatable way to evaluate exactly that.

**"Stay paranoid. Test everything. Trust nothing—especially the AI."-claude**(This line was 100% generated by claude no edits were made here)