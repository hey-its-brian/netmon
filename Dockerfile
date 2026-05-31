FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
# Bake the template as the default; the real settings.yaml is bind-mounted at runtime.
COPY settings.example.yaml ./settings.yaml

VOLUME /data

EXPOSE 514/udp

CMD ["python", "-m", "src.main"]
