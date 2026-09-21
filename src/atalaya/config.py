"""Configuración central de Atalaya, cargada desde variables de entorno / .env."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Ajustes de la aplicación. Todos los valores tienen defaults seguros."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ─── Base de datos ────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./atalaya.sqlite3"

    # ─── Capa IA ──────────────────────────────────────────────────────
    ai_provider: str = "anthropic"
    anthropic_api_key: str = ""
    ai_model: str = "claude-sonnet-4-6"
    #: Límite de tokens de salida por llamada. El triaje y la consulta NL
    #: piden respuestas acotadas (severidad+impacto+remediación, o una
    #: respuesta a una pregunta); no hace falta margen para generación larga.
    ai_max_tokens: int = 1024
    #: Timeout (segundos) por llamada al proveedor de IA.
    ai_timeout: float = 60.0
    #: Reintentos del SDK ante fallo transitorio (rate limit, 5xx).
    ai_max_retries: int = 2
    #: Triajes concurrentes al procesar varios hallazgos. Acotado por la
    #: misma razón que `dns_concurrency`: no saturar al proveedor ni disparar
    #: el coste de una tacada de llamadas simultáneas sin control.
    ai_concurrency: int = 5

    # ─── Informes ─────────────────────────────────────────────────────
    #: Directorio donde se escriben los informes PDF generados. Relativo al
    #: directorio de trabajo del proceso salvo que se dé una ruta absoluta.
    reports_dir: str = "reports"

    # ─── APIs externas de descubrimiento ──────────────────────────────
    shodan_api_key: str = ""

    #: Endpoint de Certificate Transparency. Parametrizado para poder
    #: apuntar a una réplica o a un servicio equivalente sin tocar código.
    crtsh_url: str = "https://crt.sh"
    #: Timeout (segundos) de las peticiones HTTP a fuentes externas.
    http_timeout: float = 30.0
    #: Reintentos ante fallo transitorio de crt.sh (servicio históricamente
    #: inestable). Se aplica backoff exponencial entre intentos.
    crtsh_retries: int = 3

    # ─── Resolución DNS ───────────────────────────────────────────────
    #: Timeout (segundos) por consulta DNS individual.
    dns_timeout: float = 3.0
    #: Consultas DNS simultáneas. Limita el paralelismo para no saturar
    #: el resolver ni provocar descartes por rate limiting.
    dns_concurrency: int = 50
    #: Servidores DNS a usar, separados por comas. Vacío = los del sistema.
    dns_resolvers: str = ""

    # ─── Descubrimiento: puertos ────────────────────────────────────────
    #: Timeout (segundos) por conexión TCP individual.
    port_scan_timeout: float = 2.0
    #: Conexiones simultáneas dentro del escaneo de un único host. Acota la
    #: intrusividad (CLAUDE.md, restricción de seguridad 5): un barrido
    #: agresivo degrada el servicio del objetivo y es indistinguible de un
    #: ataque.
    port_scan_concurrency: int = 100

    # ─── Descubrimiento: cabeceras HTTP ─────────────────────────────────
    #: Timeout (segundos) por petición HTTP de análisis de cabeceras.
    header_scan_timeout: float = 10.0

    # ─── Descubrimiento: TLS ─────────────────────────────────────────────
    #: Timeout (segundos) por conexión TLS de inspección de certificado.
    tls_scan_timeout: float = 5.0

    # ─── Enriquecimiento (puertos + cabeceras + TLS) ────────────────────
    #: Hosts procesados en paralelo por cada técnica al enriquecer un
    #: escaneo ya resuelto. Igual motivo que `dns_concurrency`: sin este
    #: límite, un escaneo con muchos subdominios activos dispararía cientos
    #: de conexiones simultáneas sin control.
    enrichment_host_concurrency: int = 10

    # ─── Aplicación ───────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    environment: str = "development"
    log_level: str = "INFO"

    # ─── Salvaguarda de autorización ──────────────────────────────────
    #: Solo estos dominios pueden escanearse. Cadena separada por comas;
    #: vacío = sin restricción (usar con responsabilidad).
    scan_allowlist: str = ""

    @property
    def allowlist(self) -> list[str]:
        """Dominios autorizados, normalizados a minúsculas."""
        return [d.strip().lower() for d in self.scan_allowlist.split(",") if d.strip()]

    @property
    def dns_servers(self) -> list[str]:
        """Servidores DNS configurados explícitamente (vacío = los del sistema)."""
        return [s.strip() for s in self.dns_resolvers.split(",") if s.strip()]


settings = Settings()
