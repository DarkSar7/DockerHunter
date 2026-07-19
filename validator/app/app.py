from fastapi import FastAPI
from app.ner import load_model
from app.routes import build_router

print("🔄 Loading detection model...")
try:
    model = load_model()
    if model is not None:
        print("✅ Detection model loaded successfully")
    else:
        print("⚠️  Detection model failed to load. API will return errors for validation requests.")
except Exception as e:
    print(f"❌ Error during model loading: {e}")
    model = None
    print("⚠️  Continuing without detection model. API will return errors for validation requests.")


app = FastAPI(title="DockerHunter AI Validator Service", version="1.0.0")
app.include_router(build_router(model))
