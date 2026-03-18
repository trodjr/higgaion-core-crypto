#!/bin/bash
while true; do
  resp=$(curl -s -4 -X PUT -H "Accept: application/vnd.github+json" \
    -H "Authorization: token $(gh auth token)" \
    https://api.github.com/repos/trodjr/higgaion-core-crypto/branches/main/protection \
    -d '{
      "required_status_checks": {
        "strict": true,
        "contexts": [
          "Analyze C100K Memory Physics",
          "Execute Flawfinder Bounds"
        ]
      },
      "enforce_admins": true,
      "required_pull_request_reviews": {
        "dismiss_stale_reviews": true,
        "require_code_owner_reviews": false,
        "required_approving_review_count": 1
      },
      "restrictions": null,
      "required_linear_history": true,
      "allow_force_pushes": false,
      "allow_deletions": false
    }')
  
  if echo "$resp" | grep -q "url"; then
    echo "Branch protection physically enforced."
    break
  fi
  sleep 2
done
