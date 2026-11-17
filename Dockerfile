FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENTRYPOINT ["python", "mcp_server.py"]
