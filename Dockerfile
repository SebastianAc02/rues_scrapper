FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY . .

ENV MAX_CONCURRENT_REQUESTS=3
ENV PAGE_POOL_SIZE=3

EXPOSE 8000

# Un solo worker: cada worker de gunicorn levanta su propio Chromium en el
# lifespan de FastAPI. Con -w 4 y PAGE_POOL_SIZE=10 quedaban hasta 40 paginas
# de Chromium vivas al mismo tiempo en el contenedor, y eso reventaba la
# memoria del plan de Render (causa del 502 permanente). La concurrencia ya
# la maneja el semaphore + el pool de paginas dentro de un solo proceso.
CMD ["gunicorn", "index:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "1", "--bind", "0.0.0.0:8000", "--timeout", "120"]
