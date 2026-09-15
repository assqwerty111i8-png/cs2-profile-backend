import pytest
import anyio

from app.pinned_transport import PinnedIPBackend


@pytest.mark.anyio
async def test_https_pins_ip_without_dns(monkeypatch):
    called = {}

    async def fake_connect_tcp(
        remote_host,
        remote_port,
        **kwargs,
    ):
        called["host"] = remote_host
        called["port"] = remote_port

        # Нам не нужно настоящее соединение
        raise RuntimeError("MOCK_CONNECTION")

    monkeypatch.setattr(
        anyio,
        "connect_tcp",
        fake_connect_tcp,
    )

    backend = PinnedIPBackend(
        verified_ip="93.184.216.34"
    )

    with pytest.raises(RuntimeError, match="MOCK_CONNECTION"):
        await backend.connect_tcp(
            host="example.com",
            port=443,
            timeout=1,
        )

    assert called["host"] == "93.184.216.34"
    assert called["port"] == 443
