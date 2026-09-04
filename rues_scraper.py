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

# Config
RUES_OPEN_DATA_TIMEOUT_SEC = int(os.getenv("RUES_OPEN_DATA_TIMEOUT_SEC", "15"))
RUES_OPEN_DATA_URL = "https://www.datos.gov.co/resource/c82u-588k.json"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # o gpt-4o

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

def _query_rues_open_data(nit: str) -> list:
    params = urllib.parse.urlencode({"nit": nit})
    url = f"{RUES_OPEN_DATA_URL}?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=RUES_OPEN_DATA_TIMEOUT_SEC) as resp:
        return json.loads(resp.read().decode("utf-8"))

def build_text_for_ai(row: dict) -> str:
    """
    Construye un texto descriptivo con todos los campos relevantes de la fila
    para que la IA pueda extraer la información.
    """
    fields = [
        "razon_social",
        "nit",
        "estado_matricula",
        "fecha_actualizacion",
        "direccion",
        "telefono",
        "email",
        "actividad_economica",
        "tamano_empresa",
        "representante_legal",
        "num_identificacion_representante_legal",
        "clase_identificacion_rl",
        "representante_legal_suplente",
        "num_identificacion_rl_suplente",
        # Si hay más campos, se pueden agregar aquí
    ]
    lines = []
    for key in fields:
        val = row.get(key, "")
        if val:
            lines.append(f"{key.replace('_', ' ').title()}: {val}")
    # Si hay campos adicionales no listados, se agregan como "Otros datos"
    extra = {k: v for k, v in row.items() if k not in fields and v}
    if extra:
        lines.append("Otros datos:")
        for k, v in extra.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)

async def parse_with_ai(text: str) -> dict:
    """
    Envía el texto a la IA para extraer representantes, suplentes, gerentes,
    teléfonos, correos, direcciones, etc.
    """
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY no configurada")

    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
    Eres un asistente experto en extraer información de certificados de existencia y representación legal (Cámara de Comercio de Colombia).
    A partir del siguiente texto, extrae y estructura la información de la empresa en JSON.

    Cómo leer el texto:
    - El certificado registra los nombramientos en orden cronológico, cada uno bajo un encabezado tipo
      "Por Acta número N del [fecha]... se designó a:" seguido de una tabla con columnas
      CARGO, NOMBRE e IDENTIFICACION (el nombre a veces queda partido en dos líneas).
    - Un nombramiento más reciente reemplaza al cargo anterior de la misma posición (Principal o Suplente).
    - Si un acta posterior dice que alguien "renuncia" a un cargo, ese cargo queda vacante desde esa
      fecha, a menos que un acta aún más reciente nombre un reemplazo. No reportes como vigente a
      alguien que renunció.
    - Ignora la sección de "FUNCIONES" (lista numerada de funciones del Gerente General): son cláusulas
      estándar del certificado, no información de la empresa.
    - Reporta únicamente el estado VIGENTE a la fecha del documento: representante legal principal
      actual y suplente actual (si lo hay).

    Texto:
    {text}

    Devuelve un JSON con la siguiente estructura:
    {{
        "empresa": "nombre de la empresa",
        "nit": "NIT sin dígito de verificación",
        "direccion": "dirección completa",
        "telefonos": ["lista de teléfonos encontrados"],
        "correos": ["lista de correos electrónicos encontrados"],
        "representantes": [
            {{
                "nombre": "nombre completo",
                "rol": "Representante Legal Principal" o "Representante Legal Suplente" o "Gerente" o "Revisor Fiscal",
                "tipo_identificacion": "CC" o "NIT" o "CE",
                "identificacion": "número de identificación"
            }}
        ],
        "otros_contactos": [
            {{
                "nombre": "nombre",
                "rol": "rol mencionado",
                "identificacion": "número si aparece"
            }}
        ]
    }}

    Si no encuentras algún campo, déjalo como string vacío o lista vacía.
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
        # Fallback: si la IA no devuelve JSON válido, devolvemos lo que haya
        return {"raw_ai_response": content, "error": "No se pudo parsear el JSON"}

# =========================
# FastAPI app
# =========================
app = FastAPI(title="OnePay Scraper - RUES con IA")

@app.get("/")
async def root():
    return {"message": "OnePay Scraper - RUES con IA Online"}

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

    # Construir el texto para la IA
    text_for_ai = build_text_for_ai(row)

    try:
        parsed_by_ai = await parse_with_ai(text_for_ai)
    except Exception as e:
        parsed_by_ai = {"error": str(e)}

    # También devolvemos los campos estructurados para respaldo
    return JSONResponse(
        content={
            "success": True,
            "nit": nit_digits,
            "structured": {
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
            "raw": row,  # Datos crudos para depuración
        }
    )
