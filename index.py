from fastapi import FastAPI
from bgp_tools import app as bgp_app
from rues_scraper import app as rues_app
from rues_scraper_full import app as rues_full_app  # <--- NUEVO

app = FastAPI(title="OnePay Scraper - Unified")

@app.get("/")
async def root():
    return {
        "message": "OnePay Scraper Unified",
        "endpoints": {
            "bgp": "/bgp/get-bgp-whois/{as_number}",
            "rues": "/rues/get-representatives/{nit}",
            "rues-full": "/rues-full/get-representatives-full/{nit}"  # <--- NUEVO
        }
    }

app.mount("/bgp", bgp_app)
app.mount("/rues", rues_app)
app.mount("/rues-full", rues_full_app)  # <--- NUEVO
