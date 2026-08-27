FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    UNINET_API_HOST=0.0.0.0 \
    UNINET_API_PORT=8000

WORKDIR /app
COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY src ./src
COPY config ./config

RUN pip install --no-cache-dir -e .

COPY . .

EXPOSE 8000
# Single command: trains the model on first boot, runs the pipeline, serves the dashboard.
CMD ["uninet", "--no-open"]
