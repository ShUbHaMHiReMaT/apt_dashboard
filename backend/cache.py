import time

CACHE = {}
CACHE_TTL = 300  # seconds

def get_cached(ioc):
    entry = CACHE.get(ioc)
    if not entry:
        return None
    data, ts = entry
    if time.time() - ts > CACHE_TTL:
        del CACHE[ioc]
        return None
    return data

def set_cache(ioc, data):
    CACHE[ioc] = (data, time.time())