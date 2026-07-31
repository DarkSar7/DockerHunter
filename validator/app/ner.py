import os
import sys
from transformers import pipeline
from app.config import load_config


def load_model():
    try:
        config = load_config()
        hf_config = config.get("huggingface", {})
        model_config = hf_config.get("model", {})

        model_name = model_config.get("name", "bigcode/starpii")
        cache_dir = model_config.get("cache_dir", "/app/models")
        hf_token = hf_config.get("token") or os.environ.get("HUGGINGFACEHUB_API_TOKEN")

        # Explicit cache_dir configuration
        if hf_token:
            print(f"Using Hugging Face token for model: {model_name}", file=sys.stderr)
            try:
                return pipeline(
                    "ner",
                    model=model_name,
                    aggregation_strategy="simple",
                    token=hf_token,
                    model_kwargs={"cache_dir": cache_dir}
                )
            except Exception as e:
                print(f"⚠️ Failed loading model with token, trying offline: {e}", file=sys.stderr)
                return pipeline(
                    "ner",
                    model=model_name,
                    aggregation_strategy="simple",
                    token=hf_token,
                    model_kwargs={"cache_dir": cache_dir, "local_files_only": True}
                )

        print(f"Loading model WITHOUT authentication: {model_name}", file=sys.stderr)
        try:
            return pipeline(
                "ner",
                model=model_name,
                aggregation_strategy="simple",
                model_kwargs={"cache_dir": cache_dir}
            )
        except Exception as e:
            print(f"⚠️ Failed loading model online, trying offline (local_files_only=True): {e}", file=sys.stderr)
            return pipeline(
                "ner",
                model=model_name,
                aggregation_strategy="simple",
                model_kwargs={"cache_dir": cache_dir, "local_files_only": True}
            )
    except Exception as e:
        print(f"❌ Error loading NER model: {e}")
        return None
