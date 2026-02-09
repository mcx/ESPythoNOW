FROM python:3.11-alpine AS build

RUN apk add --no-cache gcc musl-dev libpcap-dev git linux-headers

WORKDIR /app

RUN git clone --depth 1 --branch main https://github.com/ChuckMash/ESPythoNOW.git /tmp/repo && \
    cp /tmp/repo/ESPythoNOW.py /tmp/repo/requirements.txt /app/ && \
    rm -rf /tmp/repo

FROM python:3.11-alpine

RUN apk add --no-cache \
    libpcap \
    libpcap-dev \
    gcc \
    musl-dev \
    iw \
    iproute2 \
    bash

WORKDIR /app
COPY --from=build /app /app

RUN pip install --no-cache-dir -r requirements.txt && \
    rm /app/requirements.txt
