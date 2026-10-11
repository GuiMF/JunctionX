from fastapi.testclient import TestClient

from api.main import create_app


def preflight(app, origin):
    with TestClient(app) as client:
        return client.options("/api/uploads/test", headers={
            "Origin": origin,
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Content-Type",
        })


def test_health_check_does_not_create_a_scan():
    with TestClient(create_app()) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert "/healthz" not in client.get("/openapi.json").json()["paths"]


def test_hosted_origin_from_environment(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", " https://quantumtrace.example/ ,https://preview.example, ")
    app = create_app()
    for origin in ("https://quantumtrace.example", "https://preview.example"):
        response = preflight(app, origin)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
    assert preflight(app, "https://untrusted.example").status_code == 400
    assert preflight(app, "http://localhost:5173").status_code == 400


def test_explicit_origins_override_environment(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://environment.example")
    app = create_app(cors_origins=["https://explicit.example"])
    assert preflight(app, "https://explicit.example").status_code == 200
    assert preflight(app, "https://environment.example").status_code == 400
    assert "access-control-allow-origin" not in preflight(
        create_app(cors_origins=[]), "https://environment.example"
    ).headers


def test_empty_environment_disables_cors(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", " , ")
    assert "access-control-allow-origin" not in preflight(
        create_app(), "http://localhost:5173"
    ).headers
