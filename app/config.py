from ipaddress import ip_network

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = 60
    ingest_api_key: str   # used by the security team's pipeline, not user logins
    ai_api_key: str       # used by the AI SOC Engineer to submit recommendations
    internal_network_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

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

    @field_validator("internal_network_cidrs")
    @classmethod
    def validate_internal_network_cidrs(cls, value: str) -> str:
        networks = [network.strip() for network in value.split(",") if network.strip()]
        if not networks:
            raise ValueError("At least one internal network CIDR is required")
        for network in networks:
            ip_network(network, strict=False)
        return ",".join(networks)


settings = Settings()