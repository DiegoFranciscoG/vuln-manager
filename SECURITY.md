# Política de seguridad

## Reportar una vulnerabilidad
No abras un issue público. Escríbeme por GitHub (perfil DiegoFranciscoG) con los pasos para reproducir el problema. Respondo en un máximo de 7 días.

## Prácticas aplicadas en este proyecto
- Secretos solo por variables de entorno (`.env` no se versiona; ver `.env.example`).
- Escaneo de secretos con gitleaks en cada push y pull request.
- Dependencias revisadas con Dependabot.
- Autenticación y autorización deny-by-default; validación de entradas; errores sin detalles internos.
