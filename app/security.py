from fastapi import Header,HTTPException
from app.config import get_settings
def require_api_key(x_api_key:str|None=Header(default=None)):
    expected=get_settings().api_key
    if expected and x_api_key!=expected: raise HTTPException(401,"Invalid or missing API key")
