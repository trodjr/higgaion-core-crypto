#!/bin/bash
JOB_ID=$(curl -s -4 -H "Authorization: token $(gh auth token)" -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/trodjr/higgaion-core-crypto/actions/runs/23256031763/jobs | jq -r '.jobs[] | select(.conclusion=="failure") | .id')
if [ -n "$JOB_ID" ]; then
  curl -s -4 -L -H "Authorization: token $(gh auth token)" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/trodjr/higgaion-core-crypto/actions/jobs/$JOB_ID/logs" | tail -n 50
else
  echo "No failed job found"
fi
