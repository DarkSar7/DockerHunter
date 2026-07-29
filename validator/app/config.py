import os
import yaml

CONFIG_PATH = "config/config.yaml"


def load_config():
    # Try reading the unified DockerHunter config first to avoid desync
    home = os.path.expanduser("~")
    main_config_path = os.path.join(home, ".dockerhunter", "config.yaml")
    if os.path.exists(main_config_path):
        try:
            with open(main_config_path, "r") as file:
                cfg = yaml.safe_load(file) or {}
                # Translate Go configuration format to Python's expected structure
                val_cfg = cfg.get("validator", {})
                py_cfg = {
                    "huggingface": {
                        "token": val_cfg.get("huggingface_token", ""),
                        "model": {
                            "name": val_cfg.get("model_name", "bigcode/starpii"),
                            "cache_dir": os.path.expanduser(val_cfg.get("cache_dir", "~/.dockerhunter/models")),
                            "use_auth_token": True,
                        },
                    }
                }
                return py_cfg
        except Exception:
            pass

    # Fallback to local config/config.yaml if main config doesn't exist
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as file:
            cfg = yaml.safe_load(file) or {}
            # Ensure path is expanded
            if "huggingface" in cfg and "model" in cfg["huggingface"]:
                cache = cfg["huggingface"]["model"].get("cache_dir", "/app/models")
                cfg["huggingface"]["model"]["cache_dir"] = os.path.expanduser(cache)
            return cfg
    return {}


def ensure_default_config():
    os.makedirs("config", exist_ok=True)
    if os.path.exists(CONFIG_PATH):
        return
    default_config = {
        "server": {"host": "0.0.0.0", "port": 8000},
        "huggingface": {
            "token": "",
            "model": {
                "name": "bigcode/starpii",
                "cache_dir": "/app/models",
                "use_auth_token": True,
            },
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    }
    with open(CONFIG_PATH, "w") as file:
        yaml.dump(default_config, file, default_flow_style=False)
    print(f"Created default config file at {CONFIG_PATH}")
