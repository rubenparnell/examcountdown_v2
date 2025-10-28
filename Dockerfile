FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Pass token into build
ARG MYEXAMSDB_TOKEN
ENV MYEXAMSDB_TOKEN=${MYEXAMSDB_TOKEN}

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY . .
