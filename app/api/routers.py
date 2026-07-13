from fastapi import APIRouter

from .remediation import coverage_router
from .remediation import router as remediation_router
from .vulnerabilities import router as vulnerabilities_router
from .risk import router as risk_router

system_router = APIRouter(tags=["system"])
session_router = APIRouter(tags=["session"])
tasks_router = APIRouter(tags=["scanner-tasks"])
operations_router = APIRouter(tags=["operations"])
imports_router = APIRouter(tags=["imports-exports"])
assets_router = APIRouter(tags=["assets"])
asset_cards_router = APIRouter(tags=["asset-cards"])
asset_query_router = APIRouter(tags=["asset-query"])
passports_router = APIRouter(tags=["vulnerability-passports"])
diagnostics_router = APIRouter(tags=["diagnostics"])
automations_router = APIRouter(prefix="/api/automations", tags=["automations"])
notifications_router = APIRouter(prefix="/api/notifications", tags=["notifications"])
auth_router = APIRouter(prefix="/api/auth", tags=["application-auth"])


API_ROUTERS = (
    auth_router,
    system_router,
    session_router,
    tasks_router,
    operations_router,
    imports_router,
    assets_router,
    asset_cards_router,
    asset_query_router,
    passports_router,
    diagnostics_router,
    automations_router,
    notifications_router,
    vulnerabilities_router,
    remediation_router,
    coverage_router,
    risk_router,
)
