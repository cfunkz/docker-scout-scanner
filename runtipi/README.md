# Runtipi app

`apps/docker-scout-scanner/` contains the files Runtipi needs to run Docker Scout Scanner as an app:

```
apps/docker-scout-scanner/
├── config.json          name, port, install form (admin user and password)
├── docker-compose.yml   the three containers (Runtipi dynamic compose, schema v2)
└── metadata/
    ├── description.md   shown on the app page
    └── logo.jpg
```

The official Runtipi app store no longer accepts new apps, so you add this through your own app store, which is just a public Git repository with an `apps/` folder at the top.

## Add it to Runtipi

1. Make the images public. Push a version tag (`git tag v1.0.0 && git push origin v1.0.0`) so the release workflow publishes them to `ghcr.io`. Then, on GitHub, go to **Packages** and set both `docker-scout-scanner` and `docker-scout-scanner-web` to public.
2. Create a public repository, for example `runtipi-appstore`, and copy the `apps/` folder from here into it:
   ```bash
   git clone https://github.com/<you>/runtipi-appstore
   cp -r docker-scout-scanner/runtipi/apps runtipi-appstore/
   cd runtipi-appstore && git add apps && git commit -m "Add Docker Scout Scanner" && git push
   ```
3. In Runtipi, open **Settings → App stores → Add app store**, paste the repository URL and save.
4. Find **Docker Scout Scanner** in the app store and install it. Enter an admin password (12+ characters).

You can also submit the folder to one of the [community app stores](https://github.com/runtipi/runtipi/discussions/categories/app-stores).

## How it runs under Runtipi

- Runtipi's Traefik handles HTTPS and forwards plain HTTP to the web container on port 8080 (`HTTP_MODE=proxy`). Open the app from the Runtipi dashboard, on its port or on your domain if you expose it.
- Session cookies are marked `Secure` only when you're actually on HTTPS, so signing in works on `http://<runtipi-ip>:8790` too.
- The admin panel is published on `127.0.0.1:8444` of the Runtipi host. Reach it with `ssh -L 8444:127.0.0.1:8444 you@runtipi-host`.
- Data lives in Runtipi's app-data folder (`data/scanner` and `data/certs`), so Runtipi backups include it.
- The scanner container runs as root here, because Runtipi creates the app-data folders as root. All capabilities are dropped and the filesystem is read-only, so root inside the container can't do more than write its own data folder.

## Updating the app

When you release a new version, change the image tags in `docker-compose.yml` and `version` in `config.json`, raise `tipi_version` by one, set `updated_at` to the current time in milliseconds, and push to your app store repository. Runtipi then offers the update.
