from ipaddress import ip_network
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict




# Load environment-backed settings and reject unsafe or incomplete configuration.
class Settings(BaseSettings):
    # extra="ignore": .env is shared with docker-compose (POSTGRES_PASSWORD)
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = Field(default=60, gt=0, le=1440)
    ingest_api_key: str   # used by the security team's pipeline, not user logins
    ai_api_key: str       # used by the AI SOC Engineer to submit recommendations
    internal_network_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    # Optional: threat intel enrichment. If either key is missing, the
    # lookup endpoint still works — it just returns "no_provider_configured"
    # instead of failing.
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    # Firewall integration. "simulated" only logs what would happen;
    # "fmc" blocks IPs on Cisco Secure Firewall through its management
    # center; "meraki" pushes deny rules to Cisco Meraki MX networks.
    firewall_mode: Literal["simulated", "fmc", "meraki"] = "simulated"
    # "dry_run" talks to the real FMC/Meraki (login, reads) but never writes;
    # switch to "live" only when blocks should really be enforced.
    firewall_execution_mode: Literal["dry_run", "live"] = "dry_run"
    fmc_host: str = ""  # e.g. https://fmc.example.local
    fmc_username: str = ""
    fmc_password: str = ""
    fmc_dynamic_object: str = "SOC-Blocked-IPs"
    fmc_verify_tls: bool = True
    fmc_ca_bundle: str = ""  # path to the FMC's CA certificate, if it's self-signed
    meraki_api_key: str | None = None
    meraki_network_ids: str = ""  # comma-separated, e.g. "L_123,N_456"
    meraki_base_url: str = "https://api.meraki.com/api/v1"
    meraki_block_inbound: bool = True  # also block traffic from the attacker, not just to it

    @property
    def meraki_network_id_list(self) -> list[str]:
        return [n.strip() for n in self.meraki_network_ids.split(",") if n.strip()]

    @model_validator(mode="after")
    def validate_fmc_settings(self):
        if self.firewall_mode == "fmc":
            missing = [
                name.upper()
                for name in ("fmc_host", "fmc_username", "fmc_password", "fmc_dynamic_object")
                if not getattr(self, name).strip()
            ]
            if missing:
                raise ValueError(f"{', '.join(missing)} required when FIREWALL_MODE=fmc")
            if not self.fmc_host.startswith("https://"):
                raise ValueError("FMC_HOST must start with https://")
        return self

    @model_validator(mode="after")
    def validate_meraki_settings(self):
        if self.firewall_mode == "meraki":
            if not self.meraki_api_key:
                raise ValueError("MERAKI_API_KEY is required when FIREWALL_MODE=meraki")
            if not self.meraki_network_id_list:
                raise ValueError("MERAKI_NETWORK_IDS is required when FIREWALL_MODE=meraki")
        return self

    @model_validator(mode="after")
    def validate_distinct_application_secrets(self):
        secrets = (self.jwt_secret, self.ingest_api_key, self.ai_api_key)
        if len(set(secrets)) != len(secrets):
            raise ValueError("JWT_SECRET, INGEST_API_KEY, and AI_API_KEY must be different values")
        return self

    @field_validator("jwt_secret", "ingest_api_key", "ai_api_key")
    @classmethod
    def validate_application_secrets(cls, value: str) -> str:
        if len(value.strip()) < 32:
            raise ValueError("must contain at least 32 non-whitespace characters")
        placeholder_prefixes = ("change-this", "generate-a-random", "replace-with")
        if value.strip().lower().startswith(placeholder_prefixes):
            raise ValueError("must be replaced with a randomly generated secret")
        return value.strip()

    @field_validator("virustotal_api_key", "abuseipdb_api_key", "meraki_api_key", mode="before")
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




# Share one validated configuration instance throughout the backend.
settings = Settings()
