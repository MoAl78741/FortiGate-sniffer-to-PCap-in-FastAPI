from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "FortiGate Sniffer to PCAP"
    SECRET_KEY: str = "hjshjhdjah kjshkjdhjs" # TODO: Change in production
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./database.db"

    class Config:
        env_file = ".env"

settings = Settings()
