import os
import re
import json
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from playwright.async_api import async_playwright
from openai import OpenAI

app = FastAPI(title="RUES Full Scraper")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

@app.get("/get-representatives-full/{nit}")
async def get_representatives_full(nit: str):
    nit_sin_dv = nit.split("-")[0]
    nit_digits = re.sub(r"\D", "", nit_sin_dv)
    if not nit_digits:
        raise HTTPException(status_code=400, detail="NIT vacío o mal formado")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Ir a la página de RUES
            await page.goto("https://www.rues.org.co/")
            
            # Esperar y llenar el campo de búsqueda por NIT
            await page.fill('input[name="nit"]', nit_digits)
            
            # Click en el botón de buscar (puede ser un botón o un enlace con texto "Buscar")
            await page.click('button:has-text("Buscar")')
            
            # Esperar a que carguen los resultados
            await page.wait_for_selector('table, .resultados, .tabla', timeout=15000)

            # Extraer todo el texto visible de la página
            texto_completo = await page.text_content('body')
            await browser.close()

        # Si no hay texto, error
        if not texto_completo or len(texto_completo.strip()) < 100:
            raise HTTPException(status_code=404, detail="No se encontraron datos para este NIT")

        # Enviar el texto a la IA para extraer la información estructurada
        parsed = await parse_with_ai(texto_completo)

        return JSONResponse(
            content={
                "success": True,
                "nit": nit_digits,
                "parsed_by_ai": parsed,
                "raw_text": texto_completo
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def parse_with_ai(texto: str) -> dict:
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY no configurada")

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
    Eres un asistente experto en extraer información de certificados de existencia y representación legal (Cámara de Comercio de Colombia).
    A partir del siguiente texto extraído de la página de RUES, extrae y estructura la información en JSON.

    Texto:
    {texto[:10000]}  # Limitar para no exceder el contexto de la IA

    Devuelve un JSON con:
    - empresa: nombre de la empresa
    - nit: número de identificación
    - representantes: lista de objetos con nombre, rol, identificacion
    - facultades: texto con las facultades del representante legal
    - telefono: número de teléfono si aparece
    - email: correo electrónico si aparece
    - direccion: dirección comercial
    - matricula: número de matrícula
    """

    response = await asyncio.to_thread(
        client.chat.completions.create,
        model=OPENAI_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"raw_ai_response": content, "error": "No se pudo parsear el JSON"}
