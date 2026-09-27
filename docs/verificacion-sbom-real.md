# Verificación con un SBOM real

Criterio de aceptación: «un SBOM real de mis repos produce hallazgos verificables». Esta página documenta la
prueba hecha el **2026-09-27** con el backend de **Facturador-Sri** (Spring Boot 4.1.1, Java 17), otro proyecto
del portafolio.

## 1. Generación del SBOM

```bash
# Dentro del repositorio de Facturador-Sri (no modifica el proyecto: solo resuelve dependencias)
mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom \
  -DoutputFormat=json -DoutputName=facturador-sri.cdx -DschemaVersion=1.6 -DincludeTestScope=false
```

- Herramienta: `cyclonedx-maven-plugin` 2.9.3 (última versión en Maven Central a la fecha).
- Resultado: CycloneDX **1.6**, **124 componentes** (ámbitos compile, provided, runtime y system).
- Copia versionada: [`docs/sbom-real/facturador-sri.cdx.json`](sbom-real/facturador-sri.cdx.json). Solo contiene
  coordenadas y hashes de dependencias públicas; no incluye datos personales ni rutas locales.

## 2. Ingesta en vuln-manager

1. Proyecto `facturador-sri`, exposición `PUBLIC` y entorno `PRODUCTION`.
2. `POST /api/projects/{id}/sboms`, con `Content-Type: application/vnd.cyclonedx+json`, respondió `201`.
3. La importación encoló el enriquecimiento. Luego `POST /api/sync` ejecutó OSV → KEV → EPSS → CVE → NVD.
4. Todas las fuentes terminaron `SUCCEEDED`. KEV quedó `SKIPPED` porque el catálogo no había cambiado
   (`304 Not Modified` por ETag).

## 3. Contraste independiente con OSV

Un script aparte consultó directamente `https://api.osv.dev/v1/querybatch` con las mismas 124 PURL,
sin calificadores `?type=jar`, que ECMA-427 permite omitir. Después comparó cada par (componente, vulnerabilidad)
contra los hallazgos de la app, teniendo en cuenta los alias (GHSA ↔ CVE).

| Métrica | Valor |
|---|---|
| Pares (PURL, vulnerabilidad) devueltos por OSV | 3 |
| Hallazgos creados por vuln-manager | 3 |
| Faltantes en la app | 0 |
| Sobrantes en la app | 0 |

## 4. Hallazgos obtenidos

Los tres afectan a `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.24`. La versión corregida
sugerida es **11.0.25** (la misma rama 11.0.x; OSV lista también 10.1.58 y 9.0.121 para otras ramas).

| Id (OSV) | CVE | Severidad | CVSS | EPSS (percentil) | KEV | Prioridad | SLA BOD 26-04 |
|---|---|---|---|---|---|---|---|
| GHSA-9xv2-5v5q-p794 | CVE-2026-65905 | CRITICAL | 9.8 | 0.540 | No | P3 (R6) | Fila 5 · 3 días |
| GHSA-gcx9-497g-6cp6 | CVE-2026-65182 | CRITICAL | 9.1 | 0.493 | No | P3 (R6) | Fila 5 · 3 días |
| GHSA-h3x4-894j-xpx5 | CVE-2026-68525 | CRITICAL | 9.1 | 0.484 | No | P3 (R6) | Fila 5 · 3 días |

## 5. Por qué P3 con un plazo de 3 días (y no P1)

Estas son dos preguntas distintas y el sistema las responde por separado.

- **Prioridad (orden de trabajo).** CISA-ADP marca la explotación SSVC como `none`. Además, no están en KEV
  y el percentil EPSS (0.54) queda por debajo del umbral 0.90. Por eso la regla R6 dice «sin señal de
  explotación, pero impacto alto en un servicio expuesto» → **P3**. Un CVSS de 9.8 por sí solo no sube
  la prioridad; así lo recomiendan FIRST (EPSS) y CISA (SSVC).
- **Plazo (cumplimiento).** BOD 26-04, fila 5, aplica a un activo expuesto públicamente. Las vulnerabilidades
  son *automatable = yes* y *technical impact = total* según CISA-ADP Vulnrichment. Esa fila da **3 días** desde
  la detección, sin triage forense.

Si mañana alguna entra en KEV o su EPSS supera el percentil 0.90, la siguiente sincronización la sube a P1/P2.
Eso genera una alerta de escalamiento con la explicación guardada en el hallazgo.

## 6. Idempotencia comprobada

- Reenviar el mismo archivo devuelve `200` con la importación existente, gracias a la deduplicación por hash SHA-256.
- Una segunda sincronización completa no cambia ningún hallazgo: `itemsUpdated = 0` en OSV y NVD.

## 7. Acción recomendada para Facturador-Sri

Hay que subir Tomcat embebido a 11.0.25. En Spring Boot se hace con la propiedad `tomcat.version` o
actualizando al siguiente parche de Spring Boot 4.1.x que ya la incluya. Después se genera el SBOM de nuevo
y se sube: la reconciliación cerrará los tres hallazgos como `FIXED`.
