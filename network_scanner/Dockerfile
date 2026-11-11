ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 nmap nmap-scripts iproute2 tzdata

COPY app /app

CMD ["python3", "-u", "/app/main.py"]
