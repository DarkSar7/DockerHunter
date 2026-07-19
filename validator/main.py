import uvicorn

from app.app import app
from app.config import ensure_default_config, load_config


if __name__ == "__main__":
    ensure_default_config()
    config = load_config()
    server_config = config.get("server", {"host": "0.0.0.0", "port": 8000})

    print(f"Starting server on {server_config['host']}:{server_config['port']}")
    uvicorn.run(
        "main:app",
        host=server_config["host"],
        port=server_config["port"],
        reload=False,
    )
