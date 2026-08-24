Herramienta HTTP: RUES Scraper (OnePay). Busca una empresa colombiana por NIT y devuelve su razón social y representante legal, a partir del dataset abierto oficial que publica Confecámaras (no scraping del sitio web de RUES).

Endpoint: GET https://rues-scrapper.onrender.com/get-representatives/{nit}
- {nit}: acepta el NIT en cualquier formato común — con puntos, con espacios, con o sin el dígito de verificación después del guion. 900886219, 900.886.219, 900886219-2 y 900.886.219-2 dan todos el mismo resultado; el servidor limpia el formato antes de consultar.

Respuesta 200 (éxito):
{
  "success": true,
  "nit": "900886219",
  "company_name": "RURALINK S.A.S",
  "estado_matricula": "ACTIVA",
  "source": "Datos Abiertos Colombia — Confecámaras (dataset c82u-588k)",
  "source_url": "https://www.datos.gov.co/Comercio-Industria-y-Turismo/Personas-Naturales-Personas-Jur-dicas-y-Entidades-/c82u-588k",
  "fecha_actualizacion": "2026/03/17 15:55:59.083000000",
  "legal_representatives_available": true,
  "legal_representative": {
    "nombre": "GIRALDO GIRALDO MARCO TULIO",
    "tipo_identificacion": "CEDULA DE CIUDADANIA",
    "identificacion": "70902017"
  }
}

Si el NIT existe pero el dataset no tiene representante legal cargado: "legal_representatives_available": false y "legal_representative": null. No es error.

"fecha_actualizacion" es la fecha del último dato que Confecámaras cargó para esa empresa en el dataset — no es en tiempo real, pero se actualiza de forma continua (verificado con registros de marzo y agosto de 2026).

Errores:
- 400: NIT vacío o mal formado.
- 404: NIT no encontrado en el dataset.
- 502: el dataset de Datos Abiertos Colombia no respondió. Reintentar.
- 500: error interno del scraper.

Uso: llamar una vez por NIT. El dato ya viene estructurado (no hay que parsear texto libre).

Nota técnica: antes este endpoint scrapeaba rues.org.co con un navegador headless. Se reemplazó porque RUES bloquea navegadores automatizados y cifra las peticiones a su buscador — cualquier forma de esquivar eso quedó descartada a propósito. El dataset abierto de Confecámaras trae el mismo dato (verificado contra RUES en vivo para varios NITs), sin esa fricción.
