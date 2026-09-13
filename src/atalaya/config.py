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
