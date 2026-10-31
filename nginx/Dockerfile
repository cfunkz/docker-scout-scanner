# syntax=docker/dockerfile:1
ARG NGINX_IMAGE=nginx:alpine
FROM ${NGINX_IMAGE}
# Upgrade OS packages to the latest fixes (set APK_UPGRADE=false for offline builds).
ARG APK_UPGRADE=true
# Slim the stock image down to what serving static files + a reverse proxy
# needs. curl (and with it libcurl and brotli) and the optional modules pull
# in most of the image's CVEs and are never used here; the healthcheck uses
# busybox wget.
RUN apk del --no-network --purge curl \
      nginx-module-acme nginx-module-geoip nginx-module-image-filter nginx-module-njs nginx-module-xslt \
 && if [ "$APK_UPGRADE" = "true" ]; then apk upgrade --no-cache; fi \
 && rm -rf /var/cache/apk/* /etc/nginx/conf.d/default.conf /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh \
 && mkdir -p /etc/nginx/generated \
 && chown -R nginx:nginx /var/cache/nginx
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/security-headers.conf /etc/nginx/security-headers.conf
COPY nginx/40-scanner.sh /docker-entrypoint.d/40-scanner.sh
COPY web/ /usr/share/nginx/html/
EXPOSE 8080 8443 8444
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/api/health || exit 1
