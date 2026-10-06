"""Point d'entrée du backend FastAPI."""

import hmac
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes_capture import router as capture_router
from app.config import get_settings
from app.utils.logging import configure_logging, get_logger


settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger(__name__)

# main.py se trouve dans backend/app ; deux niveaux au-dessus se trouve le projet.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_ROOT = PROJECT_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Journalise le démarrage et l'arrêt du serveur."""
    logger.info(
        "Démarrage de %s en mode %s",
        settings.app_name,
        settings.app_env,
    )
    yield
    logger.info("Arrêt de %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(capture_router)

basic_auth = HTTPBasic(auto_error=False)


@app.middleware("http")
async def protect_production_site(request: Request, call_next):
    """Exige une authentification HTTP Basic en production, hors santé."""
    if settings.app_env == "production" and request.url.path != "/api/health":
        credentials = await basic_auth(request)
        valid = (
            credentials is not None
            and hmac.compare_digest(
                credentials.username.encode("utf-8"),
                settings.app_username.encode("utf-8"),
            )
            and hmac.compare_digest(
                credentials.password.encode("utf-8"),
                settings.app_password.encode("utf-8"),
            )
        )
        if not valid:
            return Response(
                content="Authentification requise.",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="NetGuard"'},
                media_type="text/plain; charset=utf-8",
            )
    return await call_next(request)

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_ROOT / "static"),
    name="static",
)

templates = Jinja2Templates(
    directory=FRONTEND_ROOT / "templates",
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    """Affiche le tableau de bord."""
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"app_name": settings.app_name},
    )


@app.get("/api/health", tags=["État de l'application"])
async def health() -> dict[str, str]:
    """Confirme que l'API répond."""
    return {
        "status": "ok",
        "app": settings.app_name,
        "capture_enabled": str(settings.capture_enabled).lower(),
    }
