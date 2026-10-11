FROM debian:trixie-slim AS compile
RUN apt-get update && apt-get install -y --no-install-recommends \
    make fp-compiler fp-units-fcl fp-units-net libcurl4-openssl-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY Makefile ./
COPY src/ ./src/
COPY tests/test_suite.lpr ./tests/test_suite.lpr
RUN make all test && strip bin/sentinel

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libcurl4t64 libsodium23 tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --home-dir /app --shell /usr/sbin/nologin sentinel
WORKDIR /app
COPY --from=compile --chown=10001:10001 /source/bin/sentinel /app/sentinel
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/app/sentinel"]
CMD ["--serve", "/app/config.json"]
