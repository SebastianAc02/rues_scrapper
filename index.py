import asyncio
import os
from fastapi import FastAPI, HTTPException
from playwright.async_api import async_playwright

app = FastAPI(title="OnePay RUES Scraper")


@app.get("/")
@app.head("/") # Esto permite que el Health Check de Render pase de una
async def root():
    return {"message": "OnePay Scraper Online"}



@app.get("/get-representatives/{nit}")
async def get_rues_data(nit: str):
    async with async_playwright() as p:
        # headless=True para producción, False si quieres ver la ventana en tu Mac
        browser = await p.chromium.launch(headless=True) 
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        )
        page = await context.new_page()

        try:
            print(f"🚀 Iniciando búsqueda para NIT: {nit}")
            # 1. Navegar a la búsqueda inicial
            await page.goto(f"https://www.rues.org.co/buscar/RM/{nit}", wait_until="networkidle", timeout=60000)

            # 2. Clic en 'Ver información' (Selector dinámico para SPA)
            print("🖱️ Buscando botón 'Ver información'...")
            btn_info = page.locator("a:has-text('Ver información')").first
            await btn_info.wait_for(state="visible", timeout=15000)
            await btn_info.click()
            print("✅ Clic en detalle exitoso.")

            # 3. Clic en la pestaña 'Representante legal'
            print("📑 Cambiando a pestaña de Representantes...")
            tab_rep = page.locator("a:has-text('Representante legal')")
            await tab_rep.wait_for(state="visible", timeout=15000)
            await tab_rep.click()
            
            # Espera pequeña para que el contenido de la pestaña renderice
            await page.wait_for_timeout(2000)
            print("✅ Pestaña cargada.")

            # 4. Extraer el texto de los representantes
            # Sacamos el texto del contenedor principal de la ficha
            raw_text = await page.locator(".tab-content").inner_text()
            
            await browser.close()
            print(f"🏁 Proceso completado para NIT {nit}")
            
            return {
                "success": True, 
                "nit": nit, 
                "data": raw_text.strip()
            }

        except Exception as e:
            await browser.close()
            print(f"❌ Error crítico: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Fallo en navegación: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # Puerto dinámico para Railway o 9000 para tu local
    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("index:app", host="0.0.0.0", port=port, reload=True)