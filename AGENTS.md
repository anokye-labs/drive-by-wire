# drive-by-wire

## Branch Protection Rules

The following rules are enforced on this repository's default branch:

- **Pull request required** — All changes must go through a pull request. Direct pushes to the default branch are blocked.
- **Review required** — At least 1 approving review is required before merging. Stale reviews are dismissed when new commits are pushed.
- **Conversation resolution required** — All PR review comments and conversations must be resolved before merging.
- **Force pushes blocked** — Force pushes to the default branch are not allowed.
- **Branch deletion blocked** — The default branch cannot be deleted.

### Workflow

1. Create a feature branch (use git worktrees when possible)
2. Make changes and commit
3. Open a pull request targeting the default branch
4. Address all review comments and resolve conversations
5. Get at least 1 approval
6. Merge via the PR (squash or merge commit)

Never commit directly to the default branch. Never force push.

## Issue-First Workflow

**Every pull request must trace back to a GitHub Issue.** No PRs without issues. No direct commits to protected branches.

1. **Create an Issue** describing the work
2. **Create a branch** to implement
3. **Open a PR** that references the issue
4. **Review and merge** the PR, which closes the issue

## Issue Types (Required)

**Every issue MUST have an Issue Type applied.** Use the organization-level issue types defined for `anokye-labs` — these are the actual GitHub Issue Type field, NOT labels and NOT title prefixes.

| Issue Type | Use When |
|------------|----------|
| **Epic** | Large initiatives spanning multiple features |
| **Feature** | User-facing capabilities or system components |
| **Task** | Concrete, actionable work items |
| **Bug** | Defects and fixes |

Labels are for metadata and categorization only. Never use labels or title prefixes like `[TASK]` or `[BUG]` as a substitute for issue types.

## Issue Relationships

### Parent-Child Hierarchy

Use GitHub's sub-issues to create parent-child relationships:

- **3-level:** Epic → Feature → Task (when work groups into features)
- **2-level:** Feature → Task or Epic → Task (when tasks are standalone)

Maximum nesting depth is 8 levels, maximum 100 sub-issues per parent.

### Blocking Relationships

Create `blocked-by` / `blocking` relationships between issues to track dependencies. Before starting work on any issue, verify its blocking dependencies are resolved.

### GraphQL Required

Use the GraphQL API for issue types, sub-issues, and relationship management. The REST API does not support these features. Include the `GraphQL-Features: sub_issues` header for sub-issue operations.

## Delegating Work to Copilot

**Assigning issues to `@copilot` is the preferred way to get work done.** To delegate:

1. Create the issue with proper type, description, and relationships
2. Edit the issue and assign it to `@copilot`
3. Copilot will pick up the issue and open a PR