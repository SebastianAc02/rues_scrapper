FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY . .

ENV MAX_CONCURRENT_REQUESTS=20
ENV PAGE_POOL_SIZE=10

EXPOSE 8000

CMD ["gunicorn", "index:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "4", "--bind", "0.0.0.0:8000"]
