import os
import re
import json
import asyncio
import unicodedata
import urllib.request
import urllib.parse

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

# Config
RUES_OPEN_DATA_TIMEOUT_SEC = int(os.getenv("RUES_OPEN_DATA_TIMEOUT_SEC", "15"))
RUES_OPEN_DATA_URL = "https://www.datos.gov.co/resource/c82u-588k.json"

# Text fixing
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

app = FastAPI(title="OnePay Scraper - RUES")

@app.get("/")
async def root():
    return {"message": "OnePay Scraper - RUES Online"}

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

    def get_field(key: str, default: str = "") -> str:
        return fix_rues_text(row.get(key, default))

    # Construir lista de representantes
    representatives = []

    principal = get_field("representante_legal")
    principal_id = get_field("num_identificacion_representante_legal")
    principal_type = get_field("clase_identificacion_rl")
    if principal:
        representatives.append({
            "nombre": principal,
            "tipo_identificacion": principal_type or "CC",
            "identificacion": principal_id,
            "rol": "Representante Legal Principal"
        })

    suplente = get_field("representante_legal_suplente")
    suplente_id = get_field("num_identificacion_rl_suplente")
    if suplente:
        representatives.append({
            "nombre": suplente,
            "tipo_identificacion": "CC",
            "identificacion": suplente_id,
            "rol": "Representante Legal Suplente"
        })

    # Nota: No hay campo "gerente" en este dataset; el principal suele ser el gerente.

    return JSONResponse(
        content={
            "success": True,
            "nit": nit_digits,
            "company_name": get_field("razon_social"),
            "estado_matricula": get_field("estado_matricula"),
            "fecha_actualizacion": get_field("fecha_actualizacion"),
            "direccion": get_field("direccion"),
            "telefono": get_field("telefono"),
            "email": get_field("email"),
            "actividad_economica": get_field("actividad_economica"),
            "tamano_empresa": get_field("tamano_empresa"),
            "representantes": representatives,
            "source": "Datos Abiertos Colombia — Confecámaras (dataset c82u-588k)",
            "source_url": "https://www.datos.gov.co/Comercio-Industria-y-Turismo/Personas-Naturales-Personas-Jur-dicas-y-Entidades-/c82u-588k",
            "raw": row,  # Todos los datos crudos
        }
    )
