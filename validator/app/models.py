from typing import List
from pydantic import BaseModel


class Candidate(BaseModel):
    image: str
    tag: str
    file: str
    line: int
    variable: str
    value: str
    context: str


class ValidateRequest(BaseModel):
    candidates: List[Candidate]


class ValidationResult(BaseModel):
    candidate: Candidate
    valid: bool


class ValidateResponse(BaseModel):
    results: List[ValidationResult]
