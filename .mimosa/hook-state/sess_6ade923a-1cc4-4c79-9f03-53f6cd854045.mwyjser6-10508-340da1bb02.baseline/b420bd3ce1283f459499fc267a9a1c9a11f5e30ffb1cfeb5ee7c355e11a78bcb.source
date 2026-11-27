from fastapi.testclient import TestClient

from app.factory import create_app


def test_api_responses_are_not_cacheable(tmp_path):
    app = create_app(static_dir=tmp_path)

    @app.get("/api/ping")
    def ping():
        return {"ok": True}

    @app.get("/other")
    def other():
        return {"ok": True}

    client = TestClient(app)
    assert client.get("/api/ping").headers["Cache-Control"] == "no-store"
    assert "Cache-Control" not in client.get("/other").headers
