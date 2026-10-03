FROM python:3.12-slim
LABEL org.opencontainers.image.title="cryptomigrate" \
      org.opencontainers.image.description="SDLC-driven DES/3DES to AES-GCM migration toolkit" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /opt/cryptomigrate
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 migrator
USER migrator
WORKDIR /work
ENTRYPOINT ["cryptomigrate"]
CMD ["--help"]
