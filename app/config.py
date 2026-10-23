from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = 60
    ingest_api_key: str   # used by the security team's pipeline, not user logins
    ai_api_key: str       # used by the AI SOC Engineer to submit recommendations

    # Optional: threat intel enrichment. If either key is missing, the
    # lookup endpoint still works — it just returns "no_provider_configured"
    # instead of failing.
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    @field_validator("virustotal_api_key", "abuseipdb_api_key", mode="before")
    @classmethod
    def treat_disabled_provider_keys_as_unconfigured(cls, value: str | None) -> str | None:
        if isinstance(value, str) and value.strip().upper() == "DISABLED":
            return None
        return value


settings = Settings()