FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

ENV DEBIAN_FRONTEND=noninteractive

COPY requirements.txt requirements-dev.txt pyproject.toml README.md /tmp/legalserver_microsoft/
COPY legalserver_microsoft /tmp/legalserver_microsoft/legalserver_microsoft

# The base devcontainer image can include a Yarn apt source. If that upstream
# signing key is unavailable, unrelated apt operations fail during build.
RUN rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.list.save

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
    && mkdir -p /etc/apt/keyrings \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor \
        > /etc/apt/keyrings/microsoft.gpg \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && AZ_DIST_CODENAME=$( . /etc/os-release && printf '%s' "$VERSION_CODENAME" ) \
    && printf 'deb [arch=%s signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ %s main\n' "$(dpkg --print-architecture)" "$AZ_DIST_CODENAME" \
        > /etc/apt/sources.list.d/azure-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends azure-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip \
    && python -m pip install /tmp/legalserver_microsoft

WORKDIR /workspace
