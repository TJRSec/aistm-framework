# Changelog

All notable changes to AISTM (AI Security Testing Model) will be documented in this file.



---

## [2.0.0] - 2025-11-26

### Changed
- **Major restructure:** Transitioned from 5-layer model to 2-phase approach
  - **Recon Phase:** Discovery & Scoping (formerly Layer 1)
  - **Testing Phase:** 4 layers (renumbered from original Layers 2-5)
- Layer numbering now aligns with natural attack flow description
  - Layer 1: Input Validation & Intent Controls
  - Layer 2: AI Processing & Prompt Security
  - Layer 3: Output Validation & Processing
  - Layer 4: Backend & Execution Security
- Reframed methodology as a "thought process" rather than checklist
- Enhanced Recon Phase to include stakeholder methodology briefing
- Added emphasis on explaining non-determinism and defense-in-depth validation to stakeholders

### Added
- Applicability checks for each layer (not all layers exist in all applications)
- Explicit guidance on continuing exploits through all layers
- Universal application guidance for different AI architectures
- Quick Guide for field reference during assessments
- Example test case (Fruit Sales Assistant) demonstrating full methodology
- Mermaid diagrams for GitHub rendering

### Clarified
- Relationship to OWASP AI Testing Guide (AISTM = structure, OWASP = techniques)
- Layer 2 is where OWASP LLM Top 10 and AI Testing Guide techniques apply
- Core philosophy: "Assume AI compromise is inevitable"

---

## [1.0.0] - 2025-11-20

### Added
- Initial 5-layer model release
  - Layer 1: Discovery & Scoping
  - Layer 2: Input Validation & Intent Controls
  - Layer 3: AI Processing & Prompt Security
  - Layer 4: Output Validation & Processing
  - Layer 5: Backend & Execution Security
- Core philosophy: Defense-in-depth validation for AI applications
- Whitepaper documentation
- Comparison to MAESTRO framework (architecture vs. assessment)

---

## Versioning Approach

- **Major (X.0.0):** Structural changes to the framework (layer reorganization, phase changes)
- **Minor (0.X.0):** New guidance, additional test cases, expanded layer content
- **Patch (0.0.X):** Clarifications, typo fixes, documentation improvements

---

## Roadmap

- [ ] Additional test cases (RAG application, agentic AI system)
- [ ] OWASP AI Testing Guide mapping to Layer 2
- [ ] Assessment report templates
- [ ] Scoring/maturity model for defense-in-depth
- [ ] Tool integrations and automation guidance
