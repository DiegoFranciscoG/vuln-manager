# Política de seguridad

## Reportar una vulnerabilidad

No abras un issue público. Escríbeme por GitHub ([DiegoFranciscoG](https://github.com/DiegoFranciscoG)) o usa *Security › Report a vulnerability* del repositorio (reporte privado). Incluye los pasos para reproducir el problema. Respondo en un máximo de 7 días.

## Versiones soportadas

Solo la rama `main` recibe correcciones.

## Prácticas aplicadas

### Secretos y configuración
- Secretos solo por variables de entorno. `.env` no se versiona; [`.env.example`](.env.example) trae las claves vacías.
- Sin valores por defecto:
  - La app no arranca sin `ConnectionStrings__Default` o sin un `Jwt__Secret` de al menos 256 bits.
  - Compose exige los obligatorios con `${VAR:?}`.
- gitleaks en CI escanea todo el historial en cada push y pull request (y corre también como hook pre-commit local).

### Autenticación y autorización (OWASP A01, A07 · API1–API5)
- Política global deny-by-default. Los endpoints públicos se marcan uno a uno: login, salud, OpenAPI y fuentes de datos.
- Roles `Admin`, `Analyst` y `Viewer`. Las API keys de ingesta están limitadas a su proyecto, se guardan como SHA-256, expiran y se pueden revocar.
- JWT HS256 de 15 minutos. Las cookies son `HttpOnly`, `Secure` y `SameSite=Lax` (permite volver desde el enlace de una alerta), y los formularios usan tokens antiforgery.
- Argon2id (m = 19 MiB, t = 2, p = 1). La cuenta se bloquea 15 minutos tras 5 intentos fallidos.
- Rate limiting:
  - Envíos de login: 10/min por IP.
  - Ingesta: 30/min.
  - Global: 600/min.
  - Trigger de sincronización: 6/h, con comparación en tiempo constante del token.

### Entradas y salidas (A03, A04, A05 · API4, API8)
- Validación con DataAnnotations. Los enums solo aceptan nombres definidos y rechazan números o combinaciones.
- SBOM: tipo de contenido, tamaño (10 MiB) y esquema CycloneDX validados. Solo se guardan los metadatos, el hash SHA-256 y los componentes; el archivo no se escribe en disco.
- SQL solo parametrizado (EF Core).
- Exportación CSV protegida contra inyección de fórmulas.
- Errores como `ProblemDetails`, sin stack traces, con `traceId`.
- Cabeceras:
  - CSP estricta (`script-src 'self'`, `frame-ancestors 'none'`).
  - `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP y HSTS.
  - Sin cabecera `Server`.
- CORS cerrado por defecto; solo se permiten orígenes explícitos desde el entorno.

### Datos personales (LOPDP de Ecuador)
- Solo se guarda el email para iniciar sesión. La auditoría registra identificadores, nunca emails ni secretos.
- La auditoría es de solo inserción: un trigger de PostgreSQL bloquea `UPDATE` y `DELETE`. Tiene retención configurable (`Audit__RetentionDays`).
- Los datos de demostración son ficticios (dominio reservado `.test`).

### Cadena de suministro (A06, A08)
- Versiones centralizadas en `Directory.Packages.props` y Dependabot para NuGet, GitHub Actions y Docker.
- Acciones de GitHub fijadas por SHA, con `permissions` mínimos.
- Imágenes Docker con versión exacta. El runtime es *chiseled* (sin shell ni gestor de paquetes) y corre como usuario no root.
- Trivy escanea la imagen en CI y falla ante HIGH/CRITICAL corregibles.
- CI genera el SBOM CycloneDX de vuln-manager, que se puede cargar en la propia plataforma.

### Consumo de APIs externas (API10)
- Los límites publicados se respetan: NVD 5 peticiones/30 s sin clave, EPSS ≤ 100 CVE por petición y GET condicional para KEV.
- Reintentos con backoff exponencial y jitter que honran `Retry-After`.
- Las respuestas se validan antes de persistir y los webhooks salientes solo aceptan HTTPS.
