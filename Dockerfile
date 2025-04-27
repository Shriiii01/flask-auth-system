FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

ENV FLASK_APP=flask_auth
ENV FLASK_ENV=development
ENV FLASK_PORT=5001

EXPOSE 5001

CMD ["gunicorn", "-b", "0.0.0.0:5001", "--workers", "4", "--timeout", "120", "run:app"]