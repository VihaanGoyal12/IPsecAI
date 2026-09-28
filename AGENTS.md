# AGENTS.md - IPsecAI Operational Rules & Constraints

## Core Philosophy
- **Enterprise Security Console Style**: Keep UI minimal, high-contrast, structured, and professional. Use a clean light neutral background (`#f8fafc` / `#ffffff`), dark navy text (`#0f172a`), restrained blue accent (`#2563eb`), subtle borders (`#e2e8f0`), and tabular layout.
- **No AI Clutter**: No flashy cards, no neon cyberpunk aesthetics, no glassmorphism, no fake glowing borders, no emojis, no excessive charts, and no decorative badges.
- **Strict Data Honesty**:
  - Never fake data as real.
  - Never claim payload decryption or breaking encryption; analysis is strictly derived from observable flow/packet metadata.
  - Clearly distinguish between **Observed**, **AI-Inferred**, and **Rule-Based Assessment**.
  - Clearly label the security score as a "Prototype heuristic score", not an official NTRO formula.
  - Demo mode must explicitly state: `DEMO DATA: Simulated capture for prototype demonstration`.
- **Zero-Friction Demo Mode**: The application must run without external dependencies (TShark, Zeek, Kafka, PostgreSQL). Graceful fallbacks must always be available.
- **Defensive Focus**: Operate exclusively on uploaded captures, testbed templates, and simulated demo flows. No intrusive scanning, exploitation, or external probing.
- **Testing & Verification**: Verify all backend calculations, rules, scoring, and endpoints with automated tests and verify UI rendering via browser checks.
