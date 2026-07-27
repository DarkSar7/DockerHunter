import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from io import StringIO

# Force local resolution by inserting current directory into sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Mock transformers module to avoid loading it during imports
sys.modules['transformers'] = MagicMock()

import app.ner
from main import main, truncate_context

class TestValidatorStdinStdout(unittest.TestCase):
	def test_truncate_context(self):
		# Value is found and centered
		ctx = "prefix_data_aws_key_value_is_here_suffix_data"
		val = "aws_key_value"
		truncated = truncate_context(ctx, val, max_len=30)
		self.assertTrue(len(truncated) <= 30)
		self.assertTrue(val in truncated)

		# Context is short enough
		short_ctx = "short_context"
		self.assertEqual(truncate_context(short_ctx, "val", max_len=100), short_ctx)

	@patch('main.load_model')
	def test_main_loop(self, mock_load_model):
		# Mock pipeline returns detected words: word "supersecret" in the first context
		mock_pipeline = MagicMock()
		mock_pipeline.side_effect = lambda texts: [
			[{"word": "supersecret", "entity_group": "secret", "score": 0.99}], # First text
			[] # Second text
		]
		mock_load_model.return_value = mock_pipeline

		# Set up mock stdin/stdout
		input_data = {
			"batch_id": "test-batch-123",
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
		
		# We send the request line, then an empty string to simulate EOF
		mock_stdin = StringIO(json.dumps(input_data) + "\n\n")
		mock_stdout = StringIO()

		with patch('sys.stdin', mock_stdin), patch('sys.stdout', mock_stdout):
			main()

		# Parse output from mock_stdout
		output_lines = mock_stdout.getvalue().strip().split("\n")
		self.assertEqual(len(output_lines), 1)

		resp = json.loads(output_lines[0])
		self.assertEqual(resp.get("batch_id"), "test-batch-123")
		
		results = resp.get("results", [])
		self.assertEqual(len(results), 2)
		
		# First candidate should be valid
		self.assertTrue(results[0]["valid"])
		self.assertEqual(results[0]["candidate"]["value"], "supersecret")
		
		# Second candidate should be invalid
		self.assertFalse(results[1]["valid"])

	@patch('main.load_model')
	def test_entity_discrimination(self, mock_load_model):
		# Mock pipeline returns NAME (invalid) for first text and PASSWORD (valid) for second text
		mock_pipeline = MagicMock()
		mock_pipeline.side_effect = lambda texts: [
			[{"word": "john_doe", "entity_group": "NAME", "score": 0.99}],
			[{"word": "supersecretpassword", "entity_group": "PASSWORD", "score": 0.99}]
		]
		mock_load_model.return_value = mock_pipeline

		input_data = {
			"batch_id": "test-batch-456",
			"candidates": [
				{
					"image": "test",
					"tag": "latest",
					"file": "main.go",
					"line": 5,
					"variable": "USER_NAME",
					"value": "john_doe",
					"context": "username = 'john_doe'"
				},
				{
					"image": "test",
					"tag": "latest",
					"file": "main.go",
					"line": 6,
					"variable": "DB_PASS",
					"value": "supersecretpassword",
					"context": "db_pass = 'supersecretpassword'"
				}
			]
		}

		mock_stdin = StringIO(json.dumps(input_data) + "\n\n")
		mock_stdout = StringIO()

		with patch('sys.stdin', mock_stdin), patch('sys.stdout', mock_stdout):
			main()

		output_lines = mock_stdout.getvalue().strip().split("\n")
		self.assertEqual(len(output_lines), 1)

		resp = json.loads(output_lines[0])
		results = resp.get("results", [])
		self.assertEqual(len(results), 2)

		# First candidate (NAME) should be filtered out / invalid
		self.assertFalse(results[0]["valid"])

		# Second candidate (PASSWORD) should be valid
		self.assertTrue(results[1]["valid"])

if __name__ == '__main__':
	unittest.main()
