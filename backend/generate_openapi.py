import json
import sys
from app.main import app

def main():
    openapi_schema = app.openapi()
    with open("openapi.json", "w") as f:
        json.dump(openapi_schema, f)

if __name__ == "__main__":
    main()
