FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates coreutils procps \
    && useradd --create-home --uid 1001 agent \
    && rm -rf /var/lib/apt/lists/*

USER agent
CMD ["sleep", "infinity"]
