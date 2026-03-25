"""Prometheus /metrics endpoint (P11-T2).

Exposes DLP metrics in Prometheus exposition format.
No authentication required — metrics endpoints are typically
scraped by monitoring infrastructure.
"""

from fastapi import APIRouter, Response

from server.metrics import get_metrics

router = APIRouter(tags=["monitoring"])


@router.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    body, content_type = get_metrics()
    return Response(content=body, media_type=content_type)
