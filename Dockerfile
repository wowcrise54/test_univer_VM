FROM node:26-alpine AS frontend

ARG NPM_REGISTRY=http://nexus.utmn.ru/repository/npm-proxy/

WORKDIR /app
COPY package.json package-lock.json* vite.config.js index.html ./
COPY src ./src
RUN npm config set registry "${NPM_REGISTRY}" \
    && npm ci \
    && npm run build

FROM python:3.14-slim

ARG PIP_INDEX_URL=https://nexus.utmn.ru/repository/pypi-proxy/simple

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" -r requirements.txt

COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
COPY app ./app
COPY --from=frontend /app/app/static ./app/static
COPY host_software_vulnerabilities_10.104.103.0_24.csv ./host_software_vulnerabilities_10.104.103.0_24.csv

RUN mkdir -p data exports

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
