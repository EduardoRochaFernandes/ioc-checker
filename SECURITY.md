# Security policy

- API keys are read from environment variables / a local `.env` (git-ignored). Never commit them.
- If you find a vulnerability or an accidentally committed secret in this repo, please open a
  [private security advisory](https://github.com/EduardoRochaFernandes/ioc-checker/security/advisories/new)
  rather than a public issue.
- Be aware that IOCs you submit are sent to VirusTotal and AbuseIPDB (third parties). Do not submit
  confidential data (internal hostnames, internal URLs, customer file hashes) unless your policy allows it.
