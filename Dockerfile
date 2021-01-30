FROM ubuntu:focal

RUN apt-get update -qy && apt-get install -qy wget curl git jq bash vim nano && apt-get clean -qy

VOLUME /app
WORKDIR /app

COPY . /app


