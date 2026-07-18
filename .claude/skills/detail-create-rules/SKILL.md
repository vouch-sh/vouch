---
name: detail-create-rules
description: Interactively create a new Detail rule for a repository — gather context, submit the creation request, wait for completion, review the results, and pull them locally. Use when asked to "create a rule", "add a rule", "propose rules", "create/propose a Detail rule", or similar.
---

# Create a Detail Rule

Guide the user through creating one or more new rules for their repository.

## Determining the Repository

The Detail CLI infers the repository from the git remote; if the user specifies a different repo, pass it explicitly to the CLI commands.

## Prerequisites

The Detail CLI must be installed. If it is not available, install it with:
```
curl --proto '=https' --tlsv1.2 -LsSf https://cli.detail.dev | sh
```

The user must be authenticated. Assume that the user is authed and run commands directly. If a command fails with an authentication error, run `detail auth login` and guide the user through the process.

## Step 1: Determine Intent

Ask the user what they want to do:

- **Create a specific rule**: the user has a concrete idea — a description of what the rule should enforce or catch, and optionally bug IDs (`bug_...`) or commit SHAs that illustrate the pattern.
- **Propose rules**: the user wants Detail to analyze the repository and suggest rules automatically.

## Step 2: Submit the Request

**For a specific rule**, build the command from whatever context the user provided. At least one of `--description`, `--bug-ids`, or `--commit-shas` is required:
```bash
detail rules create [--description "<description>"] [--bug-ids <id1,id2>] [--commit-shas <sha1,sha2>]
```

**For AI-proposed rules**:
```bash
detail rules propose
```

Both commands return a request ID (`rcr_...`). Save it — you will need it to poll for status.

## Step 3: Wait for Completion

Rule creation can take anywhere from a few minutes to roughly an hour. Poll the request status every 60 seconds until it is no longer pending:

```bash
detail rules requests show <request_id>
```

After each poll, show the user the current status. Keep polling until the status is `completed` or `failed`. If it fails, report the error to the user and stop.

## Step 4: Review the Rules

Once completed, the request output lists all rule IDs that were created. Show each one to the user:

```bash
detail rules show <rule_id>
```

Walk the user through each rule's name and content. Ask if they're satisfied or if they'd like to submit another request with additional context.

## Step 5: Pull All Rules Locally

Ask the user if they want to write the rule files to the repository. If yes, pull every rule that was created:

```bash
detail rules pull <rule_id>
```

Repeat for each rule ID. This writes files into `.claude/skills/detail-rules/` by default. Use `--output <dir>` if the user wants a different location.

Once all rules are pulled, confirm the files written and suggest committing them.
