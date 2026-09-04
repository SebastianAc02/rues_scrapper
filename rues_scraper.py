import os
import re
import json
import asyncio
import unicodedata
import urllib.request
import urllib.parse

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from openai import OpenAI  # pip install openai

# =========================
# Config
# =========================
RUES_OPEN_DATA_TIMEOUT_SEC = int(os.getenv("RUES_OPEN_DATA_TIMEOUT_SEC", "15"))
RUES_OPEN_DATA_URL = "https://www.datos.gov.co/resource/c82u-588k.json"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # o gpt-4o si quieres más precisión

# =========================
# Text fixing (sin cambios)
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

def _query_rues_open_data(nit: str) -> list:
    params = urllib.parse.urlencode({"nit": nit})
    url = f"{RUES_OPEN_DATA_URL}?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=RUES_OPEN_DATA_TIMEOUT_SEC) as resp:
        return json.loads(resp.read().decode("utf-8"))

def build_full_text_for_ai(row: dict) -> str:
    """
    Construye un texto descriptivo con TODOS los campos de la fila,
    incluyendo los que no están en la lista predefinida.
    """
    lines = []
    for key, val in row.items():
        if val:
            # Limpiar el valor
            clean_val = fix_rues_text(str(val))
            lines.append(f"{key.replace('_', ' ').title()}: {clean_val}")
    return "\n".join(lines)

async def parse_with_ai(text: str) -> dict:
    """
    Envía el texto completo a la IA y le pide que extraiga TODA la información relevante
    de representantes, cargos, contactos, etc., en una estructura dinámica.
    """
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY no configurada")

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
    Eres un asistente experto en extraer información de certificados de existencia y representación legal (Cámara de Comercio de Colombia).
    A partir del siguiente texto, extrae y estructura TODA la información relevante de la empresa.

    El texto contiene información de:
    - Razón social, NIT, domicilio, dirección, teléfonos, correos.
    - Representantes legales (principales, suplentes, gerentes, revisores fiscales, apoderados, etc.)
    - Fechas de nombramiento, actas, etc.
    - Actividad económica, tamaño de empresa, estado de matrícula.

    IMPORTANTE:
    - Identifica TODOS los cargos mencionados (Representante Legal Principal, Suplente, Gerente, Revisor Fiscal, Apoderado, etc.).
    - Para cada cargo, extrae: nombre completo, tipo de identificación (CC, NIT, CE, etc.) y número de identificación.
    - Si hay varias personas con el mismo cargo, inclúyelas a todas (ej. varios apoderados).
    - Extrae también cualquier teléfono, correo electrónico o dirección que aparezca.
    - La estructura de la respuesta debe ser dinámica: si no hay suplente, no aparezca; si hay gerente, que aparezca.

    Texto:
    {text}

    Devuelve un JSON con la siguiente estructura (los campos son ejemplos, ajústalos según lo que encuentres):
    {{
        "empresa": "nombre de la empresa",
        "nit": "NIT sin dígito de verificación",
        "direccion": "dirección completa",
        "telefonos": ["lista de teléfonos encontrados"],
        "correos": ["lista de correos electrónicos encontrados"],
        "cargos": [
            {{
                "cargo": "Representante Legal Principal",
                "nombre": "nombre completo",
                "tipo_identificacion": "CC",
                "identificacion": "número"
            }},
            {{
                "cargo": "Representante Legal Suplente",
                "nombre": "nombre",
                "tipo_identificacion": "CC",
                "identificacion": "número"
            }},
            {{
                "cargo": "Gerente General",
                "nombre": "nombre",
                "tipo_identificacion": "CC",
                "identificacion": "número"
            }},
            ... (todos los que aparezcan)
        ],
        "otros_datos": {{
            "estado_matricula": "estado",
            "fecha_actualizacion": "fecha",
            "actividad_economica": "código",
            "tamano_empresa": "tamaño"
        }}
    }}

    Si no encuentras algún campo, no lo incluyas.
    Solo responde con el JSON, sin texto adicional.
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

# =========================
# FastAPI app
# =========================
app = FastAPI(title="OnePay Scraper - RUES con IA Dinámica")

@app.get("/")
async def root():
    return {"message": "OnePay Scraper - RUES con IA Dinámica Online"}

@app.get("/get-representatives/{nit}")
async def get_representatives(nit: str):
    nit_sin_dv = nit.split("-")[0]
    nit_digits = re.sub(r"\D", "", nit_sin_dv)
    if not nit_digits:
        raise HTTPException(status_code=400, detail="NIT vacío o mal formado")

    try:
        rows = await asyncio.to_thread(_query_rues_open_data, nit_digits)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Error consultando el dataset abierto de Confecámaras: {str(e)}"
        )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="NIT no encontrado en el dataset de Confecámaras (Datos Abiertos Colombia)"
        )

    row = rows[0]

    # Construir el texto completo para la IA
    full_text = build_full_text_for_ai(row)

    try:
        parsed_by_ai = await parse_with_ai(full_text)
    except Exception as e:
        parsed_by_ai = {"error": str(e)}

    # También devolvemos los campos básicos estructurados para respaldo
    return JSONResponse(
        content={
            "success": True,
            "nit": nit_digits,
            "structured_basic": {
                "company_name": fix_rues_text(row.get("razon_social", "")),
                "estado_matricula": fix_rues_text(row.get("estado_matricula", "")),
                "fecha_actualizacion": fix_rues_text(row.get("fecha_actualizacion", "")),
                "direccion": fix_rues_text(row.get("direccion", "")),
                "telefono": fix_rues_text(row.get("telefono", "")),
                "email": fix_rues_text(row.get("email", "")),
                "actividad_economica": fix_rues_text(row.get("actividad_economica", "")),
                "tamano_empresa": fix_rues_text(row.get("tamano_empresa", "")),
            },
            "parsed_by_ai": parsed_by_ai,
            "raw": row,
        }
    )
