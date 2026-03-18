#!/bin/bash
repos=(
  "actions/setup-python v5"
  "codecov/codecov-action v3"
  "ossf/scorecard-action v2.3.1"
  "actions/upload-artifact v4"
)
for repo_tag in "${repos[@]}"; do
  r=$(echo $repo_tag | awk '{print $1}')
  t=$(echo $repo_tag | awk '{print $2}')
  while true; do
    out=$(git -c core.ipv6=false ls-remote "https://github.com/$r.git" "refs/tags/$t^{}" 2>/dev/null)
    if [ -n "$out" ]; then
      echo "$r@$t -> $(echo "$out" | awk '{print $1}')"
      break
    fi
    out=$(git -c core.ipv6=false ls-remote "https://github.com/$r.git" "refs/tags/$t" 2>/dev/null)
    if [ -n "$out" ]; then
      echo "$r@$t -> $(echo "$out" | awk '{print $1}')"
      break
    fi
    sleep 1
  done
done
