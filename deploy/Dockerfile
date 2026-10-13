FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sso_bff ./sso_bff
COPY demo ./demo
RUN pip install --no-cache-dir .

EXPOSE 8800
CMD ["uvicorn", "sso_bff.main:app", "--host", "0.0.0.0", "--port", "8800"]
