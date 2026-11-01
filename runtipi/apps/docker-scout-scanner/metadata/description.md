# Docker Scout Scanner

A vulnerability dashboard for the images on this server. It finds every local image, scans it with Trivy (Grype is optional), and shows what is affected, how bad it is, and which upgrade fixes the most.

## What you get

- Every image on the host scanned automatically, and new images scanned as they appear
- Findings ranked by severity, EPSS (chance of exploitation), CISA KEV (known to be exploited) and whether a container is running the image
- A fix plan per image: which package upgrade removes the most CVEs, and which Dockerfile line added it
- Accepted risks with a reason and an expiry date, exported as OpenVEX
- SBOM, SARIF, CSV and JSON exports, webhooks (ntfy, Discord, Slack, generic) and Prometheus metrics
- Two-factor sign-in and API tokens

## After installing

Sign in with the admin username and password you entered. Turn on two-factor sign-in under **Settings**.

The first scan starts on its own. Downloading the vulnerability database takes a minute or two the first time.

## Admin panel

Scanner settings, users, accepted risks and the audit log live in a separate admin panel. It only listens on `127.0.0.1` of the Runtipi host (port 8444 by default). From your computer:

```
ssh -L 8444:127.0.0.1:8444 you@runtipi-host
```

Then open https://127.0.0.1:8444 and accept the self-signed certificate.

## Docker access

The app reads the Docker API through its own read-only filter. It can list and export images and see which containers run them. It can't start, stop or exec into anything.
