import os
import re
import asyncio
from contextlib import asynccontextmanager, suppress
from typing import Dict, Any

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
    if as_number is None:
        raise ValueError("AS vacío")
    s = str(as_number).strip().upper().replace(" ", "")
    if s.startswith("AS"):
        s = s[2:]
    if not s.isdigit():
        raise ValueError(f"AS inválido: {as_number}")
    return f"AS{s}"


def _is_noise_title(value: str) -> bool:
    if not value:
        return True
    v = value.strip().lower()
    noise = {
        "view", "edit", "overview", "prefixes", "connectivity", "whois",
        "search", "login", "bgp.tools"
    }
    return v in noise


def parse_lacnic_whois(raw_text: str) -> Dict[str, Any]:
    if not raw_text:
        return {}

    data: Dict[str, Any] = {}
    repeated_keys = {"address", "phone", "country", "created", "changed"}

    for line in raw_text.replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.startswith("%") or ":" not in line:
            continue

        k, v = line.split(":", 1)
        key = k.strip().lower().replace("-", "_")
        val = v.strip()

        if key in repeated_keys:
            data.setdefault(key, []).append(val)
        else:
            if key in data:
                if not isinstance(data[key], list):
                    data[key] = [data[key]]
                data[key].append(val)
            else:
                data[key] = val

    if "aut_num" not in data and "autnum" in data:
        data["aut_num"] = data["autnum"]

    owner = data.get("owner")
    if isinstance(owner, list):
        owner = owner[0] if owner else ""

    person = data.get("person")
    if isinstance(person, list):
        person = person[0] if person else ""

    data["owner_name"] = owner or ""
    data["person_name"] = person or ""
    return data


def _extract_company_from_body(body_text: str) -> str:
    # Caso típico visible en bgp.tools:
    # FIESTA TELECOMUNICACIONES SAS
    # AS Number 273187
    m = re.search(r"\n\s*([A-Z0-9ÁÉÍÓÚÑ .,&\-]{4,})\s*\n\s*AS Number\s+\d+", body_text, re.IGNORECASE)
    if m:
        name = m.group(1).strip()
        if not _is_noise_title(name):
            return name

    # fallback por línea previa a "AS Number"
    lines = [ln.strip() for ln in body_text.splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
        if re.search(r"^AS Number\s+\d+", ln, re.IGNORECASE) and i > 0:
            prev = lines[i - 1].strip()
            if not _is_noise_title(prev):
                return prev
    return ""


def _extract_website_from_body(body_text: str) -> str:
    # Busca URLs en texto
    m = re.search(r"(https?://[^\s]+)", body_text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _extract_whois_block(body_text: str) -> str:
    # Si viene bloque whois real de LACNIC, normalmente trae "% Joint Whois" o "aut-num:"
    low = body_text.lower()
    if "% joint whois" in low:
        start = low.find("% joint whois")
        return body_text[start:].strip()

    if "aut-num:" in low:
        start = low.find("aut-num:")
        return body_text[start:].strip()

    # fallback: devolver body completo (para debug)
    return body_text.strip()


async def extract_bgp_data(page) -> Dict[str, Any]:
    # Intentar activar tab Whois
    for sel in ["a:has-text('Whois')", "button:has-text('Whois')", "text=Whois"]:
        with suppress(Exception):
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=5000)
                await page.wait_for_timeout(900)
                break

    body_text = ""
    with suppress(Exception):
        body_text = (await page.locator("body").inner_text()).strip()

    # display_name robusto
    display_name = ""
    with suppress(Exception):
        h1 = page.locator("h1").first
        if await h1.count() > 0:
            t = (await h1.inner_text()).strip()
            if not _is_noise_title(t):
                display_name = t

    if not display_name:
        display_name = _extract_company_from_body(body_text)

    # website robusto (evita agarrar link de issue tracker)
    website = ""
    with suppress(Exception):
        links = page.locator("a[href^='http']")
        n = await links.count()
        for i in range(min(n, 20)):
            href = (await links.nth(i).get_attribute("href") or "").strip()
            txt = (await links.nth(i).inner_text() or "").strip().lower()
            if not href:
                continue
            if "github.com/bgptools/issues" in href.lower():
                continue
            if txt in {"issue tracker", "contact us", "pricing", "login"}:
                continue
            if href.startswith("http"):
                website = href
                break

    if not website:
        website = _extract_website_from_body(body_text)

    # whois raw y parsed
    raw_whois = _extract_whois_block(body_text)
    parsed = parse_lacnic_whois(raw_whois)

    owner_for_match = (
        parsed.get("owner_name", "")
        or parsed.get("person_name", "")
        or display_name
        or ""
    )

    scraping_warning = "removed from this page due to a detected scraping campaign" in body_text.lower()

    return {
        "display_name": display_name,
        "website": website,
        "whois_raw": raw_whois,
        "whois_parsed": parsed,
        "owner_for_match": owner_for_match,
        "scraping_warning": scraping_warning,
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


app = FastAPI(title="OnePay Scraper", lifespan=lifespan)


@app.get("/")
@app.head("/")
async def root():
    return {"message": "OnePay Scraper Online"}


# =========================
# Endpoint 1 (RUES) - MISMO NOMBRE
# =========================
@app.get("/get-representatives/{nit}")
async def get_representatives(nit: str):
    global _browser

    async with semaphore:
        context = None
        page = None

        try:
            if not _browser:
                raise HTTPException(status_code=500, detail="Browser no inicializado")

            context = await _browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/119.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
            )
            page = await context.new_page()

            async def block_heavy(route):
                req = route.request
                if req.resource_type in {"image", "media", "font", "stylesheet"}:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", block_heavy)

            await page.goto(
                f"https://www.rues.org.co/buscar/RM/{nit}",
                wait_until="domcontentloaded",
                timeout=REQUEST_TIMEOUT_MS,
            )

            btn_info = page.locator("a:has-text('Ver información')").first
            await btn_info.wait_for(state="visible", timeout=30000)
            await btn_info.click()
            await page.wait_for_timeout(1200)

            tab_rep = page.locator("a:has-text('Representante legal')").first
            await tab_rep.wait_for(state="visible", timeout=30000)
            await tab_rep.click()
            await page.wait_for_timeout(1500)

            raw_text = ""
            active_tab = page.locator(".tab-pane.active")
            if await active_tab.count() > 0:
                raw_text = (await active_tab.first.inner_text()).strip()

            if not raw_text:
                content = page.locator(".tab-content")
                if await content.count() > 0:
                    raw_text = (await content.first.inner_text()).strip()

            if not raw_text:
                raw_text = (await page.locator("body").inner_text()).strip()

            return {
                "success": True,
                "nit": nit,
                "source_url": page.url,
                "raw_text": raw_text,
            }

        except PlaywrightTimeoutError:
            raise HTTPException(status_code=504, detail="Timeout navegando RUES")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error scraping RUES: {str(e)}")
        finally:
            if page:
                with suppress(Exception):
                    await page.close()
            if context:
                with suppress(Exception):
                    await context.close()


# =========================
# Endpoint 2 (BGP) - MISMO NOMBRE
# =========================
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
