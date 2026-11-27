FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY . .
RUN useradd --system --uid 10001 --user-group --create-home phishguard \
    && mkdir -p /app/visualizations \
    && chown -R phishguard:phishguard /app/data /app/visualizations

USER phishguard

CMD ["python", "main.py"]
