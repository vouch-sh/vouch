---
name: detail-rules
description: Checks code for violations of configured Detail rules. Use when asked to "scan for violations", "check for rule violations", "run rule scan", or "check rules". Reads rule definitions from references/, determines applicability, and reports concrete violations with evidence.
---

Check a target (a file, diff, or codebase) for violations of all configured Detail rules. Each rule is defined in the skill references (one `.md` file per rule). Return findings directly as output.

## Step 1: Load the active rules

List all `.md` files in the skill references. Each file defines one rule. Read each file. A rule file includes:

- **Rule slug**: the filename without `.md`
- **Rule name**: the name of the rule
- **Description**: what pattern the rule guards against
- **Scope**: which files or directories the rule applies to (optional)
- **What to look for**: specific violation patterns
- **Violation examples**: concrete bad code
- **Correct patterns**: what compliant code looks like

If the `references/` directory is empty or does not exist, respond that no rule violations were found.

## Step 2: Determine scope (which files each rule applies to)

For each rule, identify which files in the target fall within the rule's stated scope (using the file path, extension, directory, and module/package patterns described in the rule):

- **Single file**: a simple in/out check — does this file fall within the rule's scope?
- **Diff**: check each changed file against the rule's scope
- **Codebase**: identify the subset of files the rule applies to before checking any of them

Skip a rule entirely only if none of the files in the target are in scope. When scope is ambiguous, include the file rather than skip it.

## Step 3: Check for violations

For each rule, investigate each of its in-scope files thoroughly:

1. **Read the file**: understand its full contents and structure. If the target is a diff, focus on changed lines and their surrounding context.
2. **Explore context as needed**: read related files (base classes, interfaces, shared utilities, callers) when they are necessary to make an accurate judgment
3. **Apply the rule**: look for the specific patterns described in "What to look for"

### Investigation techniques

Use the technique appropriate for the rule:

- Static pattern (import, naming, structure): read + grep the file and related files
- Behavioral / runtime contract: read callers, implementations, and tests
- Integration point (API, DB, external service): trace the call chain; read handler and schema files
- Test coverage: glob for test files; check coverage of the relevant paths

Only report violations you can ground in specific code. Do not report speculative or style-only issues.

## Step 4: Return findings

Return a list of violations that you have found. Each violation must contain:
- **Rule slug**: The slug of the violated rule
- **Location**: File and line number of the violation
- **Description**: What the violation is and why it matters, in one or two sentences
- **Evidence**: The specific code snippet, line, or pattern that constitutes the violation
- **Recommended fix**: Concrete steps to fix this violation

Report every violation instance found. If the same pattern appears in multiple places, report each occurrence separately — do not collapse them. Be precise: one entry per concrete violation, not one entry per rule.

## Quality bar

Report only **HIGH confidence** findings:
- The violation pattern from the rule is clearly present in the target
- You have read enough context to rule out false positives
- The evidence field can be quoted directly from the code

Do not report:
- "This might be a violation" (omit if not certain)
- General style suggestions not covered by a rule