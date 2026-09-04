# bgp_tools.py
import os
import socket
import asyncio
from typing import Dict, Any

from fastapi import FastAPI, HTTPException

# =========================
# Config
# =========================
WHOIS_TIMEOUT_SEC = int(os.getenv("WHOIS_TIMEOUT_SEC", "15"))

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
# FastAPI app (BGP Tools)
# =========================
app = FastAPI(title="OnePay Scraper - BGP Tools")


@app.get("/")
async def root():
    return {"message": "OnePay Scraper - BGP Tools Online"}


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
