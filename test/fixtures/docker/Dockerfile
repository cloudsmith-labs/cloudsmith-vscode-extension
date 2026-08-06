ARG BASE_IMAGE=python:3.11-slim
FROM --platform=linux/amd64 $BASE_IMAGE AS base
FROM base AS test
FROM scratch AS export
FROM alpine:3.19
