# Pinned base — bump deliberately (same policy as the deployment repo).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

# Non-root: nothing here needs privileges.
RUN useradd --create-home shim
USER shim

EXPOSE 8080
# healthcheck lives in the compose file (python stdlib probe — image has no curl/wget)
CMD ["uvicorn", "logsink_shim.app:app", "--host", "0.0.0.0", "--port", "8080"]
