FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Ya no hay navegador que levantar (index.py dejó de usar Playwright: la
# consulta de representante legal ahora le pega al dataset abierto de
# Confecámaras, no a rues.org.co). Varios workers ya no cuestan memoria de
# Chromium, así que puede correr con más de uno sin riesgo de OOM.
CMD ["gunicorn", "index:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "--bind", "0.0.0.0:8000", "--timeout", "60"]
