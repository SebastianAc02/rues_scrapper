import os
import re
import json
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from playwright.async_api import async_playwright
from openai import OpenAI

app = FastAPI(title="RUES Full Scraper con IA")

# Configuración
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# ============================================================
# FUNCIÓN PARA EXTRAER TODO EL TEXTO DE LA PÁGINA DE RUES
# ============================================================
async def extraer_texto_rues(nit: str) -> str:
    """Scrapea la página de RUES y devuelve TODO el texto visible."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        await page.goto("https://www.rues.org.co/")
        await page.fill('input[name="nit"]', nit)
        await page.click('button[type="submit"]')

        # Esperar a que cargue la tabla de resultados (máximo 15 segundos)
        await page.wait_for_selector('table', timeout=15000)

        # Extraer TODO el texto visible de la página
        texto_completo = await page.locator("body").inner_text()
        await browser.close()

        return texto_completo


# ============================================================
# FUNCIÓN PARA PROCESAR EL TEXTO CON IA
# ============================================================
async def estructurar_con_ia(texto: str) -> dict:
    """Envía el texto a OpenAI y devuelve un JSON estructurado."""
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY no configurada")

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
    Eres un asistente experto en extraer información de certificados de existencia y representación legal de Colombia (RUES).

    A continuación tienes el texto COMPLETO extraído de la página de resultados de RUES para un NIT específico.
    El texto contiene TODA la información de la empresa: datos generales, representantes legales (principal y suplente),
    facultades, revisores fiscales, y cualquier otra persona mencionada con un rol dentro de la empresa.

    Tu tarea es extraer TODA la información relevante y estructurarla en un JSON con el siguiente formato:

    {{
        "empresa": {{
            "razon_social": "nombre completo de la empresa",
            "nit": "NIT sin dígito de verificación",
            "estado_matricula": "ACTIVA, CANCELADA, etc.",
            "direccion": "dirección completa",
            "telefonos": ["lista de números de teléfono encontrados"],
            "correos": ["lista de correos electrónicos encontrados"],
            "actividad_economica": "código CIIU o descripción",
            "tamano_empresa": "Micro, Pequeña, Mediana, Grande"
        }},
        "personas": [
            {{
                "nombre": "nombre completo",
                "rol": "Representante Legal Principal | Representante Legal Suplente | Gerente | Revisor Fiscal | Subgerente | Apoderado | Otro",
                "tipo_identificacion": "CC | NIT | CE | Otro",
                "identificacion": "número de identificación",
                "facultades": "texto completo de las facultades (si aplica, solo para el representante legal principal)"
            }}
        ],
        "facultades_completas": "texto completo de las facultades del representante legal (si aparece)",
        "observaciones": "cualquier otra información relevante que no encaje en los campos anteriores"
    }}

    REGLAS IMPORTANTES:
    1. El texto contiene SECCIONES claramente marcadas como "REPRESENTACION LEGAL (PRINCIPALES)", "REPRESENTACION LEGAL (SUPLENTES)", "FACULTADES", etc.
    2. Los representantes aparecen como: "CÉDULA - NOMBRE COMPLETO" (ej. "32853968 - ALGARIN ARIZA KAREN LORENA").
    3. Extrae CADA PERSONA mencionada con un rol específico (representante principal, suplente, gerente, revisor fiscal, etc.).
    4. Las facultades suelen ser un texto largo que describe las funciones del representante legal.
    5. Si un campo no aparece en el texto, déjalo como string vacío o lista vacía.
    6. Devuelve SOLO el JSON, sin texto adicional.

    --- TEXTO EXTRAÍDO DE RUES ---
    {texto}
    --- FIN DEL TEXTO ---
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
        return {"error": "No se pudo parsear el JSON", "raw_ai_response": content}


# ============================================================
# ENDPOINT PRINCIPAL
# ============================================================
@app.get("/get-representatives-full/{nit}")
async def get_representatives_full(nit: str):
    # Limpiar NIT
    nit_sin_dv = nit.split("-")[0]
    nit_digits = re.sub(r"\D", "", nit_sin_dv)
    if not nit_digits:
        raise HTTPException(status_code=400, detail="NIT vacío o mal formado")

    try:
        # 1. Scrapear la página de RUES
        texto_rues = await extraer_texto_rues(nit_digits)

        # 2. Estructurar con IA
        datos_estructurados = await estructurar_con_ia(texto_rues)

        return JSONResponse(
            content={
                "success": True,
                "nit": nit_digits,
                "data": datos_estructurados,
                "raw_text": texto_rues[:500] + "..." if len(texto_rues) > 500 else texto_rues,  # Preview
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# ENDPOINT DE PRUEBA (para ver si el servicio está vivo)
# ============================================================
@app.get("/")
async def root():
    return {"message": "RUES Full Scraper con IA - Online"}
