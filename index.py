# index.py
from fastapi import FastAPI
from bgp_tools import app as bgp_app
from rues_scraper import app as rues_app

# Crear la aplicación principal
app = FastAPI(title="OnePay Scraper - Unified")

@app.get("/")
async def root():
    return {
        "message": "OnePay Scraper Unified",
        "endpoints": {
            "bgp": "/bgp/get-bgp-whois/{as_number}",
            "rues": "/rues/get-representatives/{nit}"
        }
    }

# Montar las apps en subrutas
app.mount("/bgp", bgp_app)
app.mount("/rues", rues_app)
