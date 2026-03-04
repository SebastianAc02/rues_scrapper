import os
import re
import asyncio
from contextlib import asynccontextmanager, suppress
from typing import Dict, Any, List

from fastapi import FastAPI, HTTPException
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# =========================
# Config
# =========================
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1"))
REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "90000"))

semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

_pw = None
_browser = None


# =========================
# Utils
# =========================
def _clean_asn(as_number: str) -> str:
    """
    Acepta 269822 o AS269822 y devuelve AS269822
    """
    if as_number is None:
        raise ValueError("AS vacío")
    s = str(as_number).strip().upper()
    s = s.replace(" ", "")
    if s.startswith("AS"):
        s = s[2:]
    if not s.isdigit():
        raise ValueError(f"AS inválido: {as_number}")
    return f"AS{s}"


def parse_lacnic_whois(raw_text: str) -> Dict[str, Any]:
    """
    Parsea texto whois tipo LACNIC (aut-num, owner, ownerid, person, etc.).
    Conserva campos repetidos en lista.
    """
    if not raw_text:
        return {}

    data: Dict[str, Any] = {}
    repeated_keys = {"address", "phone", "country", "created", "changed"}

    lines = raw_text.replace("\r", "").split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # comentarios whois
        if line.startswith("%"):
            continue
        if ":" not in line:
            continue

        k, v = line.split(":", 1)
        key = k.strip().lower().replace("-", "_")
        val = v.strip()

        if key in repeated_keys:
            if key not in data:
                data[key] = []
            data[key].append(val)
        else:
            # si se repite un campo "normal", lo pasamos a lista
            if key in data:
                if not isinstance(data[key], list):
                    data[key] = [data[key]]
                data[key].append(val)
            else:
                data[key] = val

    # Normalizaciones útiles
    if "aut_num" not in data and "autnum" in data:
        data["aut_num"] = data["autnum"]

    # Campo directo para matching por nombre
    owner = data.get("owner")
    if isinstance(owner, list):
        owner = owner[0] if owner else ""
    data["owner_name"] = owner or ""

    return data


async def extract_bgp_data(page) -> Dict[str, Any]:
    """
    Extrae:
    - título/nombre mostrado arriba
    - website mostrado arriba
    - raw whois del tab Whois
    - parse whois
    """
    # Intentar activar tab Whois
    whois_tab_candidates = [
        "a:has-text('Whois')",
        "button:has-text('Whois')",
        "text=Whois",
    ]
    for sel in whois_tab_candidates:
        with suppress(Exception):
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=5000)
                await page.wait_for_timeout(800)
                break

    # Nombre mostrado (ej: COLOMBIA MAS TV S.A.S)
    display_name = ""
    with suppress(Exception):
        h1 = page.locator("h1").first
        if await h1.count() > 0:
            display_name = (await h1.inner_text()).strip()

    # Website mostrado arriba
    website = ""
    with suppress(Exception):
        # primero intenta link http/https visible en cabecera
        a = page.locator("a[href^='http']").first
        if await a.count() > 0:
            website = (await a.get_attribute("href") or "").strip()

    # Raw Whois: intentar en <pre>, si no en tab activa, si no body
    raw_whois = ""
    whois_selectors = [
        "#whois pre",
        "pre",
        ".tab-pane.active",
        "body",
    ]
    for sel in whois_selectors:
        with suppress(Exception):
            loc = page.locator(sel).first
            if await loc.count() > 0:
                txt = (await loc.inner_text()).strip()
                if "aut-num:" in txt.lower() or "whois.lacnic.net" in txt.lower():
                    raw_whois = txt
                    break

    # fallback final body
    if not raw_whois:
        with suppress(Exception):
            raw_whois = (await page.locator("body").inner_text()).strip()

    parsed = parse_lacnic_whois(raw_whois)

    return {
        "display_name": display_name,
        "website": website,
        "whois_raw": raw_whois,
        "whois_parsed": parsed,
        # Este campo te sirve directo para match por nombre
        "owner_for_match": parsed.get("owner_name", "") or display_name or "",
    }


# =========================
# Lifespan
# =========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pw, _browser

    _pw = await async_playwright().start()
    _browser = await _pw.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-first-run",
            "--mute-audio",
        ],
    )

    yield

    with suppress(Exception):
        await _browser.close()
    with suppress(Exception):
        await _pw.stop()


app = FastAPI(title="OnePay BGP Tools Scraper", lifespan=lifespan)


@app.get("/")
@app.head("/")
async def root():
    return {"message": "OnePay BGP Tools Scraper Online"}


@app.get("/get-bgp-whois/{as_number}")
async def get_bgp_whois(as_number: str):
    global _browser

    async with semaphore:
        context = None
        page = None
        try:
            if not _browser:
                raise HTTPException(status_code=500, detail="Browser no inicializado")

            asn = _clean_asn(as_number)
            asn_num = asn.replace("AS", "")
            url = f"https://bgp.tools/as/{asn_num}#whois"

            context = await _browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/119.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
            )
            page = await context.new_page()

            # bloquear recursos pesados
            async def block_heavy(route):
                req = route.request
                if req.resource_type in {"image", "media", "font", "stylesheet"}:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", block_heavy)

            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=REQUEST_TIMEOUT_MS,
            )
            await page.wait_for_timeout(1500)

            extracted = await extract_bgp_data(page)

            return {
                "success": True,
                "query_as_input": as_number,
                "query_as_normalized": asn,
                "source_url": page.url,
                **extracted,
            }

        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except PlaywrightTimeoutError:
            raise HTTPException(status_code=504, detail="Timeout navegando BGP Tools")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error scraping BGP Tools: {str(e)}")
        finally:
            if page:
                with suppress(Exception):
                    await page.close()
            if context:
                with suppress(Exception):
                    await context.close()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("index:app", host="0.0.0.0", port=port, reload=False)
