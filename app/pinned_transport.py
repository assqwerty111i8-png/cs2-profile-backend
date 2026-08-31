import ssl
from typing import Iterable

import anyio
import httpcore
import httpx


class AnyIOStreamAdapter(httpcore.AsyncNetworkStream):
    def __init__(self, stream):
        self.stream = stream

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            with anyio.fail_after(timeout):
                return await self.stream.receive(max_bytes)
        except TimeoutError as exc:
            raise httpcore.ReadTimeout("Read timed out") from exc
        except (anyio.EndOfStream, anyio.ClosedResourceError):
            return b""

    async def write(
        self,
        buffer: bytes,
        timeout: float | None = None,
    ) -> None:
        try:
            with anyio.fail_after(timeout):
                await self.stream.send(buffer)
        except TimeoutError as exc:
            raise httpcore.WriteTimeout("Write timed out") from exc

    async def aclose(self) -> None:
        await self.stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            with anyio.fail_after(timeout):
                tls_stream = await anyio.streams.tls.TLSStream.wrap(
                    self.stream,
                    ssl_context=ssl_context,
                    hostname=server_hostname,
                    standard_compatible=False,
                )

            return AnyIOStreamAdapter(tls_stream)

        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(
                "TLS connection timed out"
            ) from exc


class PinnedIPBackend(httpcore.AsyncNetworkBackend):

    def __init__(self, verified_ip: str):
        self.verified_ip = verified_ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple] | None = None,
    ) -> httpcore.AsyncNetworkStream:

        try:
            with anyio.fail_after(timeout):
                stream = await anyio.connect_tcp(
                    remote_host=self.verified_ip,
                    remote_port=port,
                    local_host=local_address,
                )

        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(
                f"Connection to {self.verified_ip}:{port} timed out"
            ) from exc

        except OSError as exc:
            raise httpcore.ConnectError(
                f"Connection to {self.verified_ip}:{port} failed"
            ) from exc

        return AnyIOStreamAdapter(stream)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options=None,
    ):
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)


class HTTPXResponseStream(httpx.AsyncByteStream):

    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class PinnedIPTransport(httpx.AsyncBaseTransport):

    def __init__(
        self,
        verified_ip: str,
        *,
        verify: bool | ssl.SSLContext = True,
    ):
        self.verified_ip = verified_ip

        if isinstance(verify, ssl.SSLContext):
            ssl_context = verify
        else:
            ssl_context = httpx.create_ssl_context(
                verify=verify
            )

        self.pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            http1=True,
            http2=False,
            network_backend=PinnedIPBackend(
                verified_ip
            ),
        )

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:

        httpcore_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )

        response = await self.pool.handle_async_request(
            httpcore_request
        )

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=HTTPXResponseStream(
                response.stream
            ),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self):
        await self.pool.aclose()