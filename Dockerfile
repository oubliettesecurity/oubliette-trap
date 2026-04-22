FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

EXPOSE 8080

# Bind to 0.0.0.0 inside the container (port is published via `docker run -p`).
# The container is expected to sit behind a firewall / authenticating ingress;
# see HIGH-6 in the 2026-04-22 red-team audit for deployment guidance.
CMD ["oubliette", "serve", "--transport", "sse", "--host", "0.0.0.0", "--port", "8080"]
