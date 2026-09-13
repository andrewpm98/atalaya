"""Configuración central de Atalaya, cargada desde variables de entorno / .env."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Ajustes de la aplicación. Todos los valores tienen defaults seguros."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Base de datos
    database_url: str = "sqlite+aiosqlite:///./atalaya.sqlite3"

    # Capa IA
    ai_provider: str = "anthropic"
    anthropic_api_key: str = ""
    ai_model: str = "claude-sonnet-4-6"

    # APIs externas de descubrimiento
    shodan_api_key: str = ""

    # Aplicación
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    environment: str = "development"
    log_level: str = "INFO"

    # Salvaguarda de autorización: solo estos dominios pueden escanearse.
    # Cadena separada por comas; vacío = sin restricción.
    scan_allowlist: str = ""

    @property
    def allowlist(self) -> list[str]:
        return [d.strip() for d in self.scan_allowlist.split(",") if d.strip()]


settings = Settings()
