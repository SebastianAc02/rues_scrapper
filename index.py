import os
from fastapi import FastAPI, HTTPException
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

app = FastAPI(title="OnePay RUES Scraper")

@app.get("/")
@app.head("/")
async def root():
    return {"message": "OnePay Scraper Online"}

@app.get("/get-representatives/{nit}")
async def get_representatives(nit: str):
    browser = None
    context = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/119.0.0.0 Safari/537.36"
                )
            )

            page = await context.new_page()

            # 1) Buscar por NIT
            search_url = f"https://www.rues.org.co/buscar/RM/{nit}"
            await page.goto(search_url, wait_until="domcontentloaded", timeout=90000)

            # 2) Click en "Ver información" (primer resultado)
            btn_info = page.locator("a:has-text('Ver información')").first
            await btn_info.wait_for(state="visible", timeout=30000)
            await btn_info.click()

            # Esperar navegación SPA
            await page.wait_for_timeout(1500)

            # 3) Abrir pestaña "Representante legal"
            tab_rep = page.locator("a:has-text('Representante legal')").first
            await tab_rep.wait_for(state="visible", timeout=30000)
            await tab_rep.click()

            # Espera para render
            await page.wait_for_timeout(2000)

            # 4) Extraer TODO el texto de la pestaña activa
            # Fallbacks por si cambia el DOM
            raw_text = ""

            tab_active = page.locator(".tab-pane.active")
            if await tab_active.count() > 0:
                raw_text = (await tab_active.first.inner_text()).strip()

            if not raw_text:
                tab_content = page.locator(".tab-content")
                if await tab_content.count() > 0:
                    raw_text = (await tab_content.first.inner_text()).strip()

            if not raw_text:
                # último fallback: cuerpo completo
                raw_text = (await page.locator("body").inner_text()).strip()

            return {
                "success": True,
                "nit": nit,
                "source": page.url,
                "raw_text": raw_text
            }

    except PlaywrightTimeoutError as e:
        raise HTTPException(status_code=504, detail=f"Timeout en navegación RUES: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scraping RUES: {str(e)}")
    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("index:app", host="0.0.0.0", port=port, reload=True)
