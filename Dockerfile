FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin flowpipe

USER 10001
EXPOSE 2055/udp
ENTRYPOINT ["flowpipe"]
CMD ["collect"]
