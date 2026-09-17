#!/usr/bin/env python3
"""Posts the tail of a failed build log as a GitHub commit comment.

Exists because the Claude sandbox that develops this repo can fetch
GitHub API responses but not the Actions log blob-storage host that
`.../actions/jobs/{id}/logs` redirects to -- see PROGRESS.md's "CI
status" section. A commit comment, by contrast, is plain API content
and fully reachable, so failures can still be diagnosed from there
even without direct log access.

Usage: post_failure_log.py <job-name> <log-file>
Requires GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA in the
environment, which every GitHub Actions run sets automatically.
"""
import json
import os
import sys
import urllib.request

def main():
    job_name, log_path = sys.argv[1], sys.argv[2]
    tail = ""
    if os.path.exists(log_path):
        with open(log_path, "r", errors="replace") as f:
            tail = f.read()[-60000:]
    body = f"**{job_name}** build failed:\n\n```\n{tail}\n```"

    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    token = os.environ["GITHUB_TOKEN"]
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode(),
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"posted, status {resp.status}")
    except Exception as e:
        # Never fail the job over the diagnostic step itself.
        print(f"failed to post commit comment: {e}")

if __name__ == "__main__":
    main()
