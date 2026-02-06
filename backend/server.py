import sys
import os

sys.path.insert(0, '/app')
os.chdir('/app')

from dotenv import load_dotenv
load_dotenv('/app/.env', override=True)

from fastapi_server import app
