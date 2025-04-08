from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic_settings import BaseSettings, SettingsConfigDict

import secrets

app = FastAPI()
security = HTTPBasic()


class Auth(BaseSettings):
    model_config = SettingsConfigDict(env_file=[".env", "_env"])
    username: bytes
    password: bytes


auth = Auth()


def get_current_username(
    creds: Annotated[HTTPBasicCredentials, Depends(security)],
):
    is_correct_username = secrets.compare_digest(creds.username.encode(), auth.username)
    is_correct_password = secrets.compare_digest(creds.password.encode(), auth.password)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


@app.get("/")
def read_root(user_name: Annotated[str, Depends(get_current_username)]):
    return {"message": f"You are authenticated {user_name}!"}


@app.get("/health")
def check_health():
    return {"message": "ok"}
