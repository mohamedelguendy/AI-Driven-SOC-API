from pydantic_settings import BaseSettings, SettingsConfigDict
 
 
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
 
    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = 60
    ingest_api_key: str  # used by the security team's pipeline, not user logins
    ai_api_key: str      # used by the AI SOC Engineer to submit recommendations
 
 
settings = Settings()