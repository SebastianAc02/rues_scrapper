import os
import re
import socket
import asyncio
import unicodedata
import urllib.request
import urllib.parse
import json
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

# =========================
# Config
# =========================

WHOIS_TIMEOUT_SEC = int(os.getenv("WHOIS_TIMEOUT_SEC", "15"))
RUES_OPEN_DATA_TIMEOUT_SEC = int(os.getenv("RUES_OPEN_DATA_TIMEOUT_SEC", "15"))

# Dataset abierto oficial de Confecámaras (Personas Naturales, Personas
# Jurídicas y Entidades Sin Ánimo de Lucro) en el portal de Datos Abiertos
# de Colombia, expuesto vía Socrata (SODA API), sin autenticación.
RUES_OPEN_DATA_URL = "https://www.datos.gov.co/resource/c82u-588k.json"

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


app = FastAPI(title="OnePay Scraper")


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
# RUES: representante legal
# =========================
#
# rues.org.co es un SPA que carga sus resultados de busqueda cifrando el
# cuerpo de la peticion contra elasticprd.rues.org.co/query, y ademas
# bloquea navegadores automatizados (chequea navigator.webdriver) antes de
# dejar cargar esa app. Automatizar eso significaria evadir esas dos
# protecciones a proposito, y eso no se hace.
#
# En vez de scrapear esa SPA, se consulta el dataset oficial que publica
# Confecamaras en Datos Abiertos Colombia (Socrata), que trae exactamente
# el mismo dato de registro mercantil, incluido el representante legal, sin
# autenticacion y sin necesidad de navegador. Verificado contra RUES en
# vivo el 2026-08-24 para NIT 900886219 (Ruralink S.A.S.) y 890903938
# (Bancolombia S.A.): coincide exacto, y en el caso de Bancolombia el
# dataset abierto trae el dato que la SPA de RUES ni siquiera muestra.

def _query_rues_open_data(nit: str) -> list:

    params = urllib.parse.urlencode({"nit": nit})
    url = f"{RUES_OPEN_DATA_URL}?{params}"

    req = urllib.request.Request(url, headers={"Accept": "application/json"})

    with urllib.request.urlopen(req, timeout=RUES_OPEN_DATA_TIMEOUT_SEC) as resp:
        return json.loads(resp.read().decode("utf-8"))


@app.get("/get-representatives/{nit}")
async def get_representatives(nit: str):

    nit_digits = re.sub(r"\D", "", nit)

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

    company_name = fix_rues_text(row.get("razon_social", ""))
    representative_name = fix_rues_text(row.get("representante_legal", ""))
    representative_id = row.get("num_identificacion_representante_legal", "")
    representative_id_type = row.get("clase_identificacion_rl", "")

    available = bool(representative_name)

    return JSONResponse(
        content={
            "success": True,
            "nit": nit_digits,
            "company_name": company_name,
            "estado_matricula": row.get("estado_matricula", ""),
            "source": "Datos Abiertos Colombia — Confecámaras (dataset c82u-588k)",
            "source_url": "https://www.datos.gov.co/Comercio-Industria-y-Turismo/Personas-Naturales-Personas-Jur-dicas-y-Entidades-/c82u-588k",
            "fecha_actualizacion": row.get("fecha_actualizacion", ""),
            "legal_representatives_available": available,
            "legal_representative": {
                "nombre": representative_name,
                "tipo_identificacion": representative_id_type,
                "identificacion": representative_id,
            } if available else None,
        }
    )
