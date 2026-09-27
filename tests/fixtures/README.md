# Fixtures de pruebas

Respuestas reales de las APIs públicas, capturadas el 2026-09-26 y recortadas (se quitaron referencias y configuraciones que los tests no usan). Sirven para que WireMock simule las fuentes sin depender de la red, y para comprobar que los clientes leen el formato real.

| Carpeta | Fuente | Licencia / aviso |
|---|---|---|
| `osv/` | OSV.dev (`api.osv.dev`), registros de la GitHub Advisory Database | CC-BY 4.0 (GitHub Advisory Database) |
| `cve/` | CVE Services (`cveawg.mitre.org`), contenedor CNA y ADP de CISA (Vulnrichment) | CVE® — Copyright © The MITRE Corporation. Uso bajo la licencia de los CVE Terms of Use (https://www.cve.org/Legal/TermsOfUse). Datos ADP de CISA: CC0-1.0 |
| `nvd/` | NIST NVD CVE API 2.0 | Dominio público (Title 17 U.S.C.). This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| `epss/` | FIRST EPSS API (`api.first.org`) | Uso libre; se solicita atribución a FIRST EPSS |
| `kev/` | CISA Known Exploited Vulnerabilities (subconjunto de 4 entradas) | Dominio público (U.S. Government) |
| `sbom/` | SBOM CycloneDX 1.6 ficticios creados para las pruebas (paquetes públicos reales, proyecto inventado) | MIT (este repositorio) |
