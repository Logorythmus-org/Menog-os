# Day-1 Acceptance Criteria

## Repository
- [ ] correct remote configured
- [ ] default branch documented
- [ ] clean initial state
- [ ] no parallel canonical repo created accidentally
- [ ] package manager and runtime versions pinned

## Architecture
- [ ] baseline docs committed
- [ ] ADRs exist for language/runtime/package manager
- [ ] verb registry created
- [ ] algorithm registry created
- [ ] event schema created
- [ ] policy/capability contract created

## Runtime
- [ ] CLI starts
- [ ] workspace path resolves safely
- [ ] read-only inspect executes
- [ ] no shell interpolation
- [ ] timeout works
- [ ] process cleanup works
- [ ] stdout/stderr/exit captured

## Security
- [ ] path traversal denied
- [ ] symlink escape denied
- [ ] unauthorized write denied
- [ ] unauthorized command denied
- [ ] network not used by inspect
- [ ] malicious repository text cannot become runtime authority

## Ledger
- [ ] events append
- [ ] hashes verify
- [ ] no secrets in events
- [ ] failed actions are recorded

## Commit
- [ ] `git status` reviewed
- [ ] diff reviewed
- [ ] tests pass
- [ ] first commit is manual
- [ ] `DAY1_AUDIT.md` written
