import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock transformers module to avoid importing it during test setup
sys.modules['transformers'] = MagicMock()

# Force local resolution by inserting current directory into sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import app.ner

# We mock the load_model function before importing the app to prevent it from loading transformers/torch
with patch('app.ner.load_model', return_value=MagicMock()):
    from fastapi.testclient import TestClient
    from app.app import app

class TestValidatorAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "DockerHunter AI Validator Service is running"})

    def test_health_endpoint(self):
        # Test healthy status when model is mock-loaded
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy", "model_loaded": True})

    def test_validate_batch_endpoint(self):
        # We will mock the model pipeline behavior directly inside the validation endpoint
        mock_pipeline = MagicMock()
        # Mock pipeline returning detected entities: word "supersecret" in the first context
        mock_pipeline.side_effect = lambda texts: [
            [{"word": "supersecret", "entity_group": "secret", "score": 0.99}], # First text
            [] # Second text
        ]
        
        # Build router with mock pipeline and attach to a new test app
        from app.routes import build_router
        from fastapi import FastAPI
        test_app_instance = FastAPI()
        test_app_instance.include_router(build_router(mock_pipeline))
        test_app = TestClient(test_app_instance)

        payload = {
            "candidates": [
                {
                    "image": "lyft/clutch",
                    "tag": "sha-1",
                    "file": "/app/config.py",
                    "line": 42,
                    "variable": "API_KEY",
                    "value": "supersecret",
                    "context": "api_key = 'supersecret'"
                },
                {
                    "image": "lyft/clutch",
                    "tag": "sha-1",
                    "file": "/app/db.go",
                    "line": 12,
                    "variable": "DB_PASS",
                    "value": "placeholder",
                    "context": "db_pass = 'placeholder'"
                }
            ]
        }
        
        response = test_app.post("/validate", json=payload)
        self.assertEqual(response.status_code, 200)
        results = response.json().get("results", [])
        self.assertEqual(len(results), 2)
        
        # First candidate is valid (secret detected)
        self.assertTrue(results[0]["valid"])
        self.assertEqual(results[0]["candidate"]["value"], "supersecret")
        
        # Second candidate is invalid (no secret detected)
        self.assertFalse(results[1]["valid"])

if __name__ == '__main__':
    unittest.main()
