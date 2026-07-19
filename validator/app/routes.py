import time
from fastapi import APIRouter, HTTPException
from app.models import ValidateRequest, ValidateResponse, ValidationResult


def build_router(model_pipeline):
    router = APIRouter()

    @router.get("/")
    async def root():
        return {"message": "DockerHunter AI Validator Service is running"}

    @router.get("/health")
    async def health_check():
        return {"status": "healthy", "model_loaded": model_pipeline is not None}

    @router.post("/validate", response_model=ValidateResponse)
    async def validate_candidates(request: ValidateRequest):
        if model_pipeline is None:
            raise HTTPException(status_code=500, detail="NER model pipeline not loaded")

        if not request.candidates:
            return ValidateResponse(results=[])

        try:
            # Construct texts to analyze. We prioritize context (the code line) for NER.
            # Fall back to value if context is missing.
            texts = [c.context if c.context.strip() else c.value for c in request.candidates]

            # Batch inference
            pipeline_results = model_pipeline(texts)

            # Ensure pipeline_results is a list of results (if a single text was sent, wrap it)
            if len(texts) == 1 and not isinstance(pipeline_results, list):
                pipeline_results = [pipeline_results]

            results = []
            for candidate, model_res in zip(request.candidates, pipeline_results):
                # model_res is a list of entities detected in this specific text
                detected_words = []
                if isinstance(model_res, list):
                    detected_words = [item["word"].strip().lower() for item in model_res if "word" in item]
                
                # Check if the candidate's value matches or is a subset of detected entities
                cand_val_lower = candidate.value.strip().lower()
                is_valid = False
                
                # If there are any entities detected, let's check if they relate to candidate's value
                for word in detected_words:
                    if word in cand_val_lower or cand_val_lower in word:
                        is_valid = True
                        break
                
                results.append(ValidationResult(candidate=candidate, valid=is_valid))

            return ValidateResponse(results=results)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error validating candidates: {str(e)}")

    return router
