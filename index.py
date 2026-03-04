import os
import asyncio
from contextlib import asynccontextmanager, suppress
from fastapi import FastAPI, HTTPException
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# Controla concurrencia para no reventar memoria en planes pequeños
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1"))
REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "90000"))

semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

# Globals reutilizables (evita lanzar Chromium en cada request)
_pw = None
_browser = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pw, _browser

    _pw = await async_playwright().start()

    # Flags para bajar consumo de RAM/CPU
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

    # Cierre único global (sin doble cierre por request)
    with suppress(Exception):
        await _browser.close()
    with suppress(Exception):
        await _pw.stop()


app = FastAPI(title="OnePay RUES Scraper", lifespan=lifespan)


@app.get("/")
@app.head("/")
async def root():
    return {"message": "OnePay Scraper Online"}


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

            # Bloquear recursos pesados para bajar memoria
            async def block_heavy(route):
                req = route.request
                if req.resource_type in {"image", "media", "font", "stylesheet"}:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", block_heavy)

            # 1) Buscar por NIT
            await page.goto(
                f"https://www.rues.org.co/buscar/RM/{nit}",
                wait_until="domcontentloaded",
                timeout=REQUEST_TIMEOUT_MS,
            )

            # 2) Click en "Ver información"
            btn_info = page.locator("a:has-text('Ver información')").first
            await btn_info.wait_for(state="visible", timeout=30000)
            await btn_info.click()

            await page.wait_for_timeout(1200)

            # 3) Click en pestaña "Representante legal"
            tab_rep = page.locator("a:has-text('Representante legal')").first
            await tab_rep.wait_for(state="visible", timeout=30000)
            await tab_rep.click()
            await page.wait_for_timeout(1500)

            # 4) Traer todo el texto del tab activo (fallbacks)
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
            # Cierre seguro por request (sin romper si ya cerró)
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
