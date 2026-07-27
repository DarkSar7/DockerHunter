import sys
import os
import json

# Force local resolution of app modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.ner import load_model
from app.config import ensure_default_config

VALID_ENTITIES = {"key", "password", "token", "secret"}

def truncate_context(context, value, max_len=100):
	if not context:
		return value
	if len(context) <= max_len:
		return context
	
	idx = context.find(value)
	if idx == -1:
		return context[:max_len]
		
	start = max(0, idx - (max_len - len(value)) // 2)
	end = min(len(context), start + max_len)
	return context[start:end]

def main():
	ensure_default_config()
	print("🔄 Loading StarPII model pipeline...", file=sys.stderr)
	model_pipeline = load_model()
	if model_pipeline is not None:
		print("✅ StarPII model pipeline loaded successfully", file=sys.stderr)
	else:
		print("❌ Failed to load StarPII model pipeline", file=sys.stderr)
		sys.exit(1)

	print("Validator ready to receive batches on stdin.", file=sys.stderr)

	while True:
		line = sys.stdin.readline()
		if not line:
			break # EOF received
		
		line = line.strip()
		if not line:
			continue
		
		batch_id = ""
		try:
			req = json.loads(line)
			batch_id = req.get("batch_id", "")
			candidates = req.get("candidates", [])
			if not candidates:
				print(json.dumps({"batch_id": batch_id, "results": []}))
				sys.stdout.flush()
				continue
			
			# Construct truncated texts for NER inference
			texts = []
			for c in candidates:
				ctx = c.get("context", "")
				val = c.get("value", "")
				truncated = truncate_context(ctx, val, max_len=100)
				texts.append(truncated if truncated.strip() else val)

			# Perform pipeline inference with per-item fallback isolation
			try:
				pipeline_results = model_pipeline(texts)
				if len(texts) == 1 and not isinstance(pipeline_results, list):
					pipeline_results = [pipeline_results]
			except Exception as batch_err:
				print(f"Batch inference failed: {batch_err}. Falling back to single-item validation...", file=sys.stderr)
				pipeline_results = []
				for t in texts:
					try:
						single_res = model_pipeline(t)
						if not isinstance(single_res, list):
							single_res = [single_res]
						pipeline_results.append(single_res[0] if single_res else [])
					except Exception as single_err:
						print(f"Single-item inference failed for text {t!r}: {single_err}", file=sys.stderr)
						pipeline_results.append([])

			results = []
			for candidate, model_res in zip(candidates, pipeline_results):
				detected_words = []
				if isinstance(model_res, list):
					# Filter to keep only secret/credential-relevant entities (prevent false positives on Email/IP/Name/Username)
					filtered_res = []
					for ent in model_res:
						ent_type = (ent.get("entity_group") or ent.get("entity") or "").lower()
						if ent_type.startswith("b-") or ent_type.startswith("i-"):
							ent_type = ent_type[2:]
						if ent_type in VALID_ENTITIES:
							filtered_res.append(ent)

					# Reconstruct words from contiguous token offsets (tokenizer-independent)
					sorted_ents = sorted(filtered_res, key=lambda x: x.get("start", 0))
					reconstructed = []
					curr_word = ""
					curr_end = -1
					for ent in sorted_ents:
						start = ent.get("start", 0)
						end = ent.get("end", 0)
						word = ent.get("word", "")
						
						if curr_end == -1:
							curr_word = word
							curr_end = end
						elif start == curr_end:
							curr_word += word
							curr_end = end
						else:
							if curr_word:
								reconstructed.append(curr_word)
							curr_word = word
							curr_end = end
					if curr_word:
						reconstructed.append(curr_word)
					
					detected_words = [w.strip().lower() for w in reconstructed if w.strip()]
				
				cand_val_lower = candidate.get("value", "").strip().lower()
				is_valid = False
				
				for word in detected_words:
					if len(word) >= 4 and (word in cand_val_lower or cand_val_lower in word):
						coverage = len(word) / len(cand_val_lower)
						if coverage >= 0.4 or cand_val_lower in word:
							is_valid = True
							break
				
				results.append({
					"candidate": candidate,
					"valid": is_valid
				})

			print(json.dumps({"batch_id": batch_id, "results": results}))
			sys.stdout.flush()
		except Exception as e:
			print(f"Error processing batch: {e}", file=sys.stderr)
			# Send back empty results with matching batch_id so Go pipeline doesn't block or desync
			print(json.dumps({"batch_id": batch_id, "results": []}))
			sys.stdout.flush()

if __name__ == "__main__":
	main()
