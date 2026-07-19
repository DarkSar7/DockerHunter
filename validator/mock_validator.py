import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class MockValidatorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "model_loaded": True}).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Mock Validator is running"}).encode())

    def do_POST(self):
        if self.path == '/validate':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            req = json.loads(post_data.decode())

            results = []
            for c in req.get('candidates', []):
                # Simple mock classifier: mark as valid if value does not contain "placeholder"
                val = c.get('value', '').lower()
                is_valid = "placeholder" not in val and "your_" not in val
                results.append({
                    "candidate": c,
                    "valid": is_valid
                })

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run(port=9001):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MockValidatorHandler)
    print(f"Starting mock validator on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
