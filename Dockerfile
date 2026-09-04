FROM python:3.12-slim

WORKDIR /app

# Instalar dependencias del sistema necesarias para Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt primero para aprovechar caché
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Instalar navegadores de Playwright (esto es lo que faltaba)
RUN playwright install --with-deps chromium

# Copiar el resto del código
COPY . .

EXPOSE 8000

# Usar gunicorn con uvicorn workers (1 worker para evitar sobrecarga de memoria con Chromium)
CMD ["gunicorn", "index:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "1", "--bind", "0.0.0.0:8000", "--timeout", "120"]
