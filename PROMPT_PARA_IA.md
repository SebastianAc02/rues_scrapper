Herramienta HTTP: RUES Scraper (OnePay). Busca una empresa colombiana por NIT en el RUES y devuelve su razón social y representante legal.

Endpoint: GET https://rues-scrapper.onrender.com/get-representatives/{nit}
- {nit}: solo dígitos, sin puntos ni guion de verificación. Ej: 890903938

Respuesta 200 (éxito):
{
  "success": true,
  "nit": "890903938",
  "company_name": "razón social tal como aparece en RUES",
  "source_url": "url exacta de la ficha en rues.org.co",
  "legal_representatives_available": true,
  "legal_representatives_raw": "texto plano de la pestaña 'Representante legal', puede traer varios representantes"
}

Si RUES no tiene esa información pública para la empresa: "legal_representatives_available": false y "legal_representatives_raw" contendrá "Información no disponible". Ese caso no es un error: la empresa existe pero RUES no expone el dato.

Errores:
- 400: NIT vacío o mal formado.
- 404/504: NIT no encontrado en RUES o el sitio no respondió a tiempo. Reintentar una vez antes de darlo por definitivo.
- 500: error interno del scraper.

Uso: llamar una vez por NIT, leer "legal_representatives_raw" como texto (no está en JSON estructurado por representante, es el bloque de texto tal como lo muestra RUES: nombre, tipo y número de identificación, cargo). Extraer de ahí lo que se necesite.

Límite: el servicio corre en un plan chico de Render con concurrencia baja (3 requests simultáneos). Para lotes de NITs, espaciar las llamadas en vez de dispararlas todas en paralelo.
