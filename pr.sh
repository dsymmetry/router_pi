#!/bin/bash
# Simple Git PR script with scanf-style input

set -e

BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Prompt for PR title
echo -n "Enter PR Title: "
read PR_TITLE

# Prompt for PR summary (multi-line, end with Ctrl+D)
echo "Enter PR Summary (end with Ctrl+D on empty line):"
PR_BODY=$(</dev/stdin)

# Stage all changes
git add .

# Commit (if changes exist)
if ! git diff --cached --quiet; then
  git commit -m "$PR_TITLE" -m "$PR_BODY"
fi

# Push branch
git push -u origin "$BRANCH"

# Create or update PR with GitHub CLI
if ! gh pr view "$BRANCH" &>/dev/null; then
  gh pr create --base main --head "$BRANCH" --title "$PR_TITLE" --body "$PR_BODY"
else
  gh pr edit "$BRANCH" --title "$PR_TITLE" --body "$PR_BODY"
fi

echo "✅ PR updated/created for branch: $BRANCH"

