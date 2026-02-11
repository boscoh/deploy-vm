# AGENT.md - Development Guide

Follow these instructions precisely for all sessions.

## Project Tools

## Python
- Use `uv` for package management and running scripts.
- use sphinx docstrings

## Markdown

- don't use emojis
- always format tables properly with aligned columns

## Code
- omit obvious comments
- omit obvious docstrings
- reuse existing functions if useful


## Beads Workflow (MANDATORY)

This project uses [Beads](https://github.com/steveyegge/beads) for issue tracking. **Use `bd` commands instead of markdown TODOs.**

### Session Start
1. Run `bd ready` to list unblocked issues
2. Select highest-priority matching issue
3. Claim it: `bd update <id> --status=in_progress`

### During Work
- Create issues: `bd create --title="..." --type=task --priority=2`
- Update progress: `bd update <id> --note="Progress..."`
- Add dependencies: `bd dep add <child> <blocks>`
- Types: task, bug, feature, epic, question, docs
- Priorities: P0 (critical) → P4 (backlog)

### After Each Task (MANDATORY)
1. Close the issue: `bd close <id> --reason="..."`
2. Stage and commit: `git add -A && git commit -m "Close <id>: description"`
3. If there is a relevant spec/migration md file, update that too
4. Only then move to the next task

This ensures atomic commits per task and clean git history.

### Session End
1. Close completed issues: `bd close <id>`
2. Create follow-up issues if needed
3. Run `bd sync` to commit/push
4. Leave git clean


## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
