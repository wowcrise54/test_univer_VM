FROM node:20-alpine AS frontend

WORKDIR /app
COPY package.json package-lock.json* vite.config.js index.html ./
COPY src ./src
RUN npm ci && npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=frontend /app/app/static ./app/static
COPY host_software_vulnerabilities_10.104.103.0_24.csv ./host_software_vulnerabilities_10.104.103.0_24.csv

RUN mkdir -p data exports

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
