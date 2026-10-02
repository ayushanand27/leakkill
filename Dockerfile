# leakkill as a container: docker run --rm -v "$PWD:/scan" ghcr.io/ayushanand27/leakkill
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL org.opencontainers.image.source="https://github.com/ayushanand27/leakkill" \
      org.opencontainers.image.description="Find leaked secrets, check if they're live, revoke them, and guard AI coding agents." \
      org.opencontainers.image.licenses="MIT"

# git is needed for --history and --staged; mounted repos belong to another user, so trust them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'

# leakkill is pure Python with no dependencies: copying the package is the whole install.
COPY src/leakkill /usr/local/lib/python3.12/site-packages/leakkill

WORKDIR /scan
ENTRYPOINT ["python", "-m", "leakkill"]
