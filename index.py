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
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1"))
REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "90000"))
WHOIS_TIMEOUT_SEC = int(os.getenv("WHOIS_TIMEOUT_SEC", "20"))

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
# Text fixing (RUES mojibake)
# =========================
MOJIBAKE_HINTS = ("Ã", "Â", "�", "谩", "贸", "铆", "脫", "聽", "帽")


def _suspicious_score(s: str) -> int:
    # Penaliza mezcla rara de caracteres CJK + tokens típicos de mojibake
    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    hints = sum(s.count(h) for h in MOJIBAKE_HINTS)
    replacement = s.count("\ufffd")
    return cjk * 3 + hints * 5 + replacement * 8


def _try_recode(s: str, src_encoding: str) -> str:
    try:
        return s.encode(src_encoding, errors="strict").decode("utf-8", errors="strict")
    except Exception:
        return s


def fix_rues_text(s: str) -> str:
    if not s:
        return s

    candidates = [s]

    # Primera pasada
    for enc in ("gb18030", "gbk", "latin-1", "cp1252"):
        candidates.append(_try_recode(s, enc))

    # Segunda pasada (casos doblemente rotos)
    for c in list(candidates):
        for enc in ("gb18030", "gbk", "latin-1"):
            candidates.append(_try_recode(c, enc))

    best = min(candidates, key=_suspicious_score)

    # Limpieza final
    best = unicodedata.normalize("NFKC", best)
    best = best.replace("\u00a0", " ").replace("\u200b", "").replace("\ufeff", "")
    best = re.sub(r"[ \t]+", " ", best)
    best = re.sub(r" *\n *", "\n", best)
    return best.strip()


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
# Endpoint 1: LACNIC WHOIS
# =========================
@app.get("/get-bgp-whois/{as_number}")
async def get_bgp_whois(as_number: str):
    try:
        asn = _clean_asn(as_number)
        raw = await asyncio.to_thread(whois_query_lacnic, asn, WHOIS_TIMEOUT_SEC)
        parsed = parse_lacnic_whois(raw)

        owner_for_match = (
            parsed.get("owner_name", "")
            or parsed.get("person_name", "")
            or ""
        )

        return {
            "success": True,
            "query_as_input": as_number,
            "query_as_normalized": asn,
            "source_url": "whois://whois.lacnic.net",
            "whois_source": "whois.lacnic.net",
            "display_name": owner_for_match,
            "website": "",
            "whois_raw": raw,
            "whois_parsed": parsed,
            "owner_for_match": owner_for_match,
            "scraping_warning": False
        }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error consultando WHOIS LACNIC: {str(e)}")


# =========================
# Endpoint 2: RUES normal
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

            # Fix mojibake antes de responder
            raw_text = fix_rues_text(raw_text)

            payload = {
                "success": True,
                "nit": nit,
                "source_url": page.url,
                "raw_text": raw_text,
            }

            return JSONResponse(
                content=payload,
                media_type="application/json; charset=utf-8"
            )

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


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("index:app", host="0.0.0.0", port=port, reload=False)
