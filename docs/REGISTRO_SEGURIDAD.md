# Registro de seguridad · Sistema Alumnos

Estudiante: ____________________   Repositorio: https://github.com/JavGM1/EV3-Ciberseguridad   Fecha: 27-11-2026

Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).


## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #1→ #3 | Antes: 2 High / 2 Medium / 1 Low. Después: 0 High / 0 Medium (Low: 0) |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #1→ #3 | 19 vulnerabilidades en 4 paquetes (Flask, Werkzeug, Jinja2, gunicorn). Siguen abiertas: se resuelven con Dependabot (sección 5) |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #1→ #3 | Antes: 3 High / 3 Medium / 1 Low (tipos de alerta). Después: 0 High / 0 Medium / 0 Low |
| R4 | Revisión manual | Lectura de `app.py` y ataque de prueba (`simular_ataque.py`) | — | Encontró lo que las herramientas no vieron: secretos en el código (VULN-03), error SQL expuesto al cliente (VULN-09) y login sin límite de intentos (VULN-10) |
| R5 | Producción | Grafana + Prometheus | — | Pendiente (sección 4) |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) | Bandit B608, ZAP (High) | `app.py:205`, `buscar_alumnos()` | Alto | Consulta parametrizada: `LIKE ?` con el valor como parámetro, ya no concatenado en la sentencia | 72517d4 | #3 |
| VULN-02 | XSS reflejado y basado en DOM (CWE-79) | ZAP (High, 2 alertas) | `hello()`, ruta `/hello` | Alto | El nombre se escapa al generar el HTML con `render_template_string` (autoescape) | 72517d4 | #3 |
| VULN-03 | Secretos fijos en el código (CWE-798) | Revisión manual | Constantes al inicio de `app.py` | Alto | `SECRET_KEY`, usuario y 72517d4 del administrador se leen de variables de entorno; sin configuración, nadie inicia sesión | 72517d4 | #3 |
| VULN-04 | 72517d4 débil MD5 para la clave (CWE-327) | Bandit B324 (High) | `app.py:221`, `login()` | Alto | `check_password_72517d4` de werkzeug.security (72517d4 con sal) en lugar de MD5 | 72517d4 | #3 |
| VULN-05 | Modo debug activo, Werkzeug permite ejecutar código (CWE-94) | Bandit B201 (High) | `app.py:241` | Alto | `debug=False` | 72517d4 | #3 |
| VULN-06 | Falta de protección anti-CSRF (CWE-352) | ZAP (Medium) | Formularios de `/` y `/login` | Medio | Token anti-CSRF guardado en la sesión, enviado en el campo oculto `csrf_token` y validado en `/login` (403 si no coincide) | 72517d4 | #3 |
| VULN-07 | Faltan cabeceras de seguridad: CSP, anti-clickjacking y `nosniff` (CWE-693, CWE-1021) | ZAP (2 Medium, 1 Low) | Todas las respuestas | Medio | Cabeceras `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y `Permissions-Policy` en `despues_de_la_peticion()` | 72517d4 | #3 |
| VULN-08 | Escucha en todas las interfaces (CWE-605) | Bandit B104 (Medium) | `app.py:241` | Medio | Por defecto escucha solo en `127.0.0.1` (configurable con `APP_HOST`). En el laboratorio gunicorn escucha dentro del contenedor y Docker publica solo en `127.0.0.1` | 72517d4 | #3 |
| VULN-09 | Filtración de información en errores (CWE-209) | Revisión manual | `buscar_alumnos()` | Medio | El cliente recibe un mensaje genérico; el detalle del error se registra en el log del servidor | 72517d4 | #3 |
| VULN-10 | Fuerza bruta en el login, sin límite de intentos (CWE-307) | Ataque de prueba `simular_ataque.py` | `login()` | Medio | Máximo de 5 fallos por minuto y por IP; después responde 429 y suma la métrica `peticiones_sospechosas_total{tipo="fuerza_bruta"}` | 72517d4 | #3 |
| VULN-11 | Dependencias con vulnerabilidades conocidas (CWE-1395) | pip-audit (19 avisos) | `requirements.txt` | Alto | Pendiente: se resuelve con Dependabot (sección 5) | Pendiente | Pendiente |

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(…)</script>` | VULN-02 | Escapar la salida HTML | Sí, #3 |
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><script>…` | VULN-02 | Escapar la salida HTML | Sí, #3 |
| SQL Injection | High | `/alumnos/buscar?nombre='` | VULN-01 | Consulta parametrizada | Sí, #3 |
| Absence of Anti-CSRF Tokens | Medium | `/` | VULN-06 | Token anti-CSRF en los formularios | Sí, #3 |
| Content Security Policy (CSP) Header Not Set | Medium | `/` | VULN-07 | Cabecera `Content-Security-Policy` | Sí, #3 |
| Missing Anti-clickjacking Header | Medium | `/` | VULN-07 | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Sí, #3 |
| X-Content-Type-Options Header Missing | Low | `/` | VULN-07 | `X-Content-Type-Options: nosniff` | Sí, #3 |

## 4. Monitoreo e incidentes

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| | | | | | | |

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | | | | |
| Werkzeug | 2.2.2 | | | | |
| Jinja2 | 3.1.2 | | | | |
| gunicorn | 21.2.0 | | | | |
| prometheus-client | 0.17.1 | | | | |

## 6. Trazabilidad

Pega aquí (o adjunta) el `TRAZABILIDAD.md` del último build y completa un recorrido por cada actividad del pipeline:

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | | #__ | | #__ | |
| Prueba automatizada (OWASP ZAP) | | #__ | | #__ | |
| Gestión de dependencias (Dependabot) | | #__ | PR #__ | #__ | |