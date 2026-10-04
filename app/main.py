from collections import defaultdict,deque
from time import monotonic
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings
from app.db import Base,engine
from app.api.routes import router
from app.logging_config import configure_logging
configure_logging()
import logging
log=logging.getLogger(__name__)
if not get_settings().api_key:
    log.warning("API_KEY is not set: write endpoints are unauthenticated. Set API_KEY in .env for any non-demo use.")
Base.metadata.create_all(bind=engine)
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self,app): super().__init__(app); self.limit=get_settings().rate_limit_per_minute; self.q=defaultdict(deque)
    async def dispatch(self,request,call_next):
        ip=request.client.host if request.client else "unknown"; now=monotonic(); q=self.q[ip]
        while q and now-q[0]>60:q.popleft()
        if len(q)>=self.limit:return JSONResponse({"detail":"Rate limit exceeded"},status_code=429)
        q.append(now); return await call_next(request)
app=FastAPI(title=get_settings().app_name,version="1.0.0")
app.add_middleware(RateLimitMiddleware); app.include_router(router)
@app.get("/")
def root(): return {"name":get_settings().app_name,"docs":"/docs"}
