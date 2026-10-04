from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str="LLM-Powered Security Log Analyzer"
    database_url: str="sqlite:///./security_analyzer.db"
    api_key: str=""
    llm_enabled: bool=False
    llm_base_url: str="https://api.openai.com/v1"
    llm_api_key: str=""
    llm_model: str="gpt-4o-mini"
    rate_limit_per_minute: int=120
    log_level: str="INFO"
    model_config=SettingsConfigDict(env_file=".env",extra="ignore")

@lru_cache
def get_settings(): return Settings()
