import os
from datetime import datetime, timedelta, timezone

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

load_dotenv()

# La clé secrète vient du fichier .env (jamais commité sur GitHub — voir .env.example).
# Si elle est absente, on refuse de démarrer plutôt que d'utiliser une valeur par
# défaut non sécurisée : ça évite d'héberger l'appli en public avec une clé connue.
SECRET_KEY = os.environ.get("EDU_SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "change-me":
    raise RuntimeError(
        "EDU_SECRET_KEY manquante ou non modifiée. Copie .env.example vers .env et "
        "mets une valeur aléatoire longue (voir README) avant de lancer l'appli."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12h

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalide ou expirée",
        )


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    return {"id": int(payload["sub"]), "role": payload["role"], "full_name": payload.get("full_name", "")}


def require_teacher(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "prof":
        raise HTTPException(status_code=403, detail="Réservé aux professeurs")
    return user


def require_student(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "eleve":
        raise HTTPException(status_code=403, detail="Réservé aux élèves")
    return user
