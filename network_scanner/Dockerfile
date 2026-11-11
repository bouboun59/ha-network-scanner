ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 nmap nmap-scripts iproute2 tzdata

# s6-overlay v3 vide l'environnement du CMD par défaut : garder SUPERVISOR_TOKEN et TZ
ENV S6_KEEP_ENV=1

COPY app /app

CMD ["python3", "-u", "/app/main.py"]
