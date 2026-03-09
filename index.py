import os
import re
import socket
import asyncio
import unicodedata
from contextlib import asynccontextmanager, suppress
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# =========================
# Config
# =========================

MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "20"))
REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "45000"))
WHOIS_TIMEOUT_SEC = int(os.getenv("WHOIS_TIMEOUT_SEC", "15"))
PAGE_POOL_SIZE = int(os.getenv("PAGE_POOL_SIZE", "10"))

semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

_pw = None
_browser = None
_page_pool = asyncio.Queue()

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


def whois_query_lacnic(asn: str, timeout: int = 20) -> str:

    query = f"{asn}\r\n".encode("utf-8")
    chunks = []

    with socket.create_connection(("whois.lacnic.net", 43), timeout=timeout) as sock:

        sock.settimeout(timeout)
        sock.sendall(query)

        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    return b"".join(chunks).decode("utf-8", errors="ignore")


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


# =========================
# Text fixing
# =========================

MOJIBAKE_HINTS = ("Ã", "Â", "�", "谩", "贸", "铆", "脫", "聽", "帽")

def _suspicious_score(s: str) -> int:

    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    hints = sum(s.count(h) for h in MOJIBAKE_HINTS)
    replacement = s.count("\ufffd")

    return cjk * 3 + hints * 5 + replacement * 8


def _try_recode(s: str, src_encoding: str) -> str:

    try:
        return s.encode(src_encoding).decode("utf-8")
    except:
        return s


def fix_rues_text(s: str) -> str:

    if not s:
        return s

    candidates = [s]

    for enc in ("gb18030", "latin-1", "cp1252"):
        candidates.append(_try_recode(s, enc))

    best = min(candidates, key=_suspicious_score)

    best = unicodedata.normalize("NFKC", best)
    best = best.replace("\u00a0", " ")
    best = re.sub(r"[ \t]+", " ", best)

    return best.strip()


# =========================
# Page Pool
# =========================

async def get_page():
    return await _page_pool.get()


async def return_page(page):
    await _page_pool.put(page)


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
            "--disable-setuid-sandbox",
            "--no-zygote",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
        ],
    )

    for _ in range(PAGE_POOL_SIZE):

        context = await _browser.new_context(
            viewport={"width": 1366, "height": 768}
        )

        page = await context.new_page()

        async def block_heavy(route):
            if route.request.resource_type in {"image","media","font","stylesheet"}:
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", block_heavy)

        await _page_pool.put(page)

    yield

    with suppress(Exception):
        await _browser.close()

    with suppress(Exception):
        await _pw.stop()


app = FastAPI(title="OnePay Scraper", lifespan=lifespan)


@app.get("/")
async def root():
    return {"message": "OnePay Scraper Online"}


# =========================
# WHOIS
# =========================

@app.get("/get-bgp-whois/{as_number}")
async def get_bgp_whois(as_number: str):

    try:

        asn = _clean_asn(as_number)

        raw = await asyncio.to_thread(
            whois_query_lacnic,
            asn,
            WHOIS_TIMEOUT_SEC,
        )

        parsed = parse_lacnic_whois(raw)

        owner = parsed.get("owner_name") or parsed.get("person_name") or ""

        return {
            "success": True,
            "query_as_input": as_number,
            "query_as_normalized": asn,
            "display_name": owner,
            "website": "",
            "whois_raw": raw,
            "whois_parsed": parsed,
        }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# RUES Scraper
# =========================

@app.get("/get-representatives/{nit}")
async def get_representatives(nit: str):

    async with semaphore:

        page = await get_page()

        try:

            await page.goto(
                f"https://www.rues.org.co/buscar/RM/{nit}",
                wait_until="domcontentloaded",
                timeout=REQUEST_TIMEOUT_MS,
            )

            btn = page.locator("a:has-text('Ver información')").first
            await btn.wait_for(timeout=15000)
            await btn.click()

            tab = page.locator("a:has-text('Representante legal')").first
            await tab.wait_for(timeout=15000)
            await tab.click()

            await page.wait_for_timeout(300)

            content = page.locator(".tab-pane.active")

            raw_text = ""

            if await content.count() > 0:
                raw_text = await content.first.inner_text()

            raw_text = fix_rues_text(raw_text)

            return JSONResponse(
                content={
                    "success": True,
                    "nit": nit,
                    "source_url": page.url,
                    "raw_text": raw_text,
                }
            )

        except PlaywrightTimeoutError:

            raise HTTPException(
                status_code=504,
                detail="Timeout navegando RUES"
            )

        except Exception as e:

            raise HTTPException(
                status_code=500,
                detail=f"Error scraping RUES: {str(e)}"
            )

        finally:

            await return_page(page)
