"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

Además de las rutas de negocio, la app publica métricas para Prometheus en /metrics.
Las métricas de seguridad (logins fallidos y peticiones sospechosas) se ven en Grafana.

Versión corregida: ver docs/REGISTRO_SEGURIDAD.md (VULN-01 a VULN-10).
"""
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash

app = Flask(__name__)

## Si no hay hash de administrador configurado, nadie puede iniciar sesión.
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_CLAVE_HASH", "")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>). Sirve para la trazabilidad.
VERSION = os.environ.get("APP_VERSION", "dev")
## Archivo SQLite con los alumnos (cada entorno usa el suyo).
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

## VULN-10: límite de intentos fallidos de login por IP (ventana deslizante en memoria).
LOGIN_MAX_FALLOS = int(os.environ.get("LOGIN_MAX_FALLOS", "5"))
LOGIN_VENTANA_S = int(os.environ.get("LOGIN_VENTANA_S", "60"))
_FALLOS = defaultdict(deque)
_FALLOS_LOCK = threading.Lock()

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (detección, no bloqueo).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

## VULN-06: los formularios llevan un token anti-CSRF (campo oculto «csrf_token»).
PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


def token_csrf():
    """!
    @brief Devuelve el token anti-CSRF de la sesión actual (lo crea si no existe).
    @return Token en texto hexadecimal.
    """
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def token_csrf_valido(enviado):
    """!
    @brief Compara en tiempo constante el token recibido con el de la sesión.
    @param enviado Token que llegó en el formulario.
    @return True si coincide con el de la sesión.
    """
    esperado = session.get("csrf")
    return bool(esperado) and hmac.compare_digest(enviado.encode(), esperado.encode())


def login_bloqueado(ip):
    """!
    @brief Indica si una IP superó el máximo de logins fallidos dentro de la ventana de tiempo.
    @param ip Dirección del cliente.
    @return True si debe recibir HTTP 429.
    """
    ahora = time.monotonic()
    with _FALLOS_LOCK:
        intentos = _FALLOS[ip]
        while intentos and ahora - intentos[0] > LOGIN_VENTANA_S:
            intentos.popleft()
        return len(intentos) >= LOGIN_MAX_FALLOS


def registrar_fallo(ip):
    """!
    @brief Anota un login fallido de una IP para el límite de intentos.
    @param ip Dirección del cliente.
    """
    with _FALLOS_LOCK:
        _FALLOS[ip].append(time.monotonic())


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra la métrica de cada petición y agrega las cabeceras de seguridad (VULN-07).
    @param respuesta Respuesta que Flask enviará al cliente.
    @return La misma respuesta.
    """
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    respuesta.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    respuesta.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces y formularios del sistema.
    @return Página HTML.
    """
    return render_template_string(PORTADA, version=VERSION, csrf_token=token_csrf())


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario cuyo nombre llega en el parámetro de URL «name».
    @return Página HTML con el saludo (el nombre se escapa: VULN-02).
    """
    name = request.args.get("name", "visitante")
    return render_template_string("<h1>Hola, {{ name }}!</h1>", name=name)


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos cuyo nombre contenga el texto del parámetro «nombre».
    @return JSON con los alumnos encontrados.

    VULN-01: consulta parametrizada. VULN-09: el error detallado va al log, no al cliente.
    """
    nombre = request.args.get("nombre", "")
    try:
        filas = conectar().execute("SELECT * FROM alumnos WHERE nombre LIKE ?", (f"%{nombre}%",)).fetchall()
    except sqlite3.Error:
        app.logger.exception("Error al buscar alumnos")
        return jsonify({"error": "No se pudo completar la búsqueda"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida las credenciales del administrador enviadas por formulario.
    @return JSON con el resultado; 403 sin token CSRF válido, 429 si hay demasiados intentos
            fallidos, 401 si las credenciales no son válidas.

    VULN-03: credenciales desde el entorno. VULN-04: hash con werkzeug.security (no MD5).
    VULN-06: token anti-CSRF. VULN-10: límite de intentos.
    """
    if not token_csrf_valido(request.form.get("csrf_token", "")):
        return jsonify({"error": "Token CSRF inválido"}), 403
    ip = request.remote_addr
    if login_bloqueado(ip):
        SOSPECHOSAS.labels(tipo="fuerza_bruta").inc()
        app.logger.warning("Login bloqueado por exceso de intentos desde %s", ip)
        return jsonify({"error": "Demasiados intentos, espera un momento"}), 429
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    usuario_ok = hmac.compare_digest(usuario.encode(), ADMIN_USUARIO.encode())
    clave_ok = bool(ADMIN_CLAVE_HASH) and check_password_hash(ADMIN_CLAVE_HASH, clave)
    if usuario_ok and clave_ok:
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})
    LOGIN_FALLIDOS.inc()
    registrar_fallo(ip)
    app.logger.warning("Login fallido para el usuario %r desde %s", usuario[:50], ip)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # VULN-05: sin modo debug y escuchando solo en localhost por defecto. En el laboratorio la app corre con gunicorn.
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=int(os.environ.get("APP_PORT", "5000")), debug=False)