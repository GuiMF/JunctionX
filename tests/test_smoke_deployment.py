"""Container sockets may accept/reset connections before Uvicorn is ready."""
from urllib.error import URLError

import pytest

from scripts import smoke_deployment


@pytest.mark.parametrize('error', [ConnectionResetError('starting'), URLError('refused'), TimeoutError('starting')])
def test_health_readiness_retries_transient_startup_errors(monkeypatch, error):
    attempts = []

    def request(*args, **kwargs):
        attempts.append(args)
        if len(attempts) == 1:
            raise error
        return {'status': 'ok'}

    monkeypatch.setattr(smoke_deployment, 'request', request)
    monkeypatch.setattr(smoke_deployment.time, 'sleep', lambda _: None)
    smoke_deployment.wait_for_health('http://127.0.0.1:8000')
    assert len(attempts) == 2


def test_health_readiness_stops_at_deadline(monkeypatch):
    times = iter([0, 61])
    monkeypatch.setattr(smoke_deployment.time, 'monotonic', lambda: next(times))
    def reset(*args, **kwargs):
        raise ConnectionResetError('still starting')
    monkeypatch.setattr(smoke_deployment, 'request', reset)
    with pytest.raises(ConnectionResetError):
        smoke_deployment.wait_for_health('http://127.0.0.1:8000')
