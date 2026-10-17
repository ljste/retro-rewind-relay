"""Relay the browser runtime's TCP and UDP sockets over one WebSocket connection."""
from __future__ import annotations

import asyncio
import errno
import ipaddress
import logging
import socket
import struct
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Sequence, cast

from aioice import stun
from aioice.turn import TurnClientTcpProtocol
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

HEADER = struct.Struct("<IIIiiII")
RECORD = struct.Struct("<III")
MAGIC = 0x31534B57
LIMIT = 4 * 1024 * 1024
PROTOCOL = "wiicompiled-net-v1"
LOGGER = logging.getLogger("web-net")
ERRORS = {
    errno.EAGAIN: 1, errno.EWOULDBLOCK: 1, errno.EINVAL: 2, errno.EBADF: 2,
    errno.ECONNREFUSED: 3, errno.ECONNRESET: 4, errno.EPIPE: 4,
    errno.EADDRINUSE: 5, errno.ENETUNREACH: 6, errno.EHOSTUNREACH: 6,
    errno.ENOTCONN: 7, errno.ETIMEDOUT: 8, errno.EACCES: 9, errno.EPERM: 9,
    errno.EMFILE: 10, errno.ENOBUFS: 11,
}
OPTIONS = {
    1: (socket.SOL_SOCKET, socket.SO_BROADCAST),
    2: (socket.SOL_SOCKET, socket.SO_REUSEADDR),
    3: (socket.IPPROTO_TCP, socket.TCP_NODELAY),
    4: (socket.SOL_SOCKET, socket.SO_SNDBUF),
    5: (socket.SOL_SOCKET, socket.SO_RCVBUF),
    6: (socket.SOL_SOCKET, socket.SO_LINGER),
    7: (socket.SOL_SOCKET, socket.SO_OOBINLINE),
    8: (socket.SOL_SOCKET, socket.SO_KEEPALIVE),
}


@dataclass(frozen=True)
class Packet:
    op: int
    request: int = 0
    descriptor: int = -1
    result: int = 0
    address: int = 0
    port: int = 0
    data: bytes = b""

    def encode(self) -> bytes:
        return HEADER.pack(MAGIC, self.op, self.request, self.descriptor,
                           self.result, self.address, self.port) + self.data

    @classmethod
    def decode(cls, data: bytes) -> Packet:
        if len(data) < HEADER.size:
            raise ValueError("Truncated socket packet")
        magic, *fields = HEADER.unpack_from(data)
        if magic != MAGIC:
            raise ValueError("Unknown socket protocol")
        return cls(*fields, data=data[HEADER.size:])


def address_fields(address: tuple[str, int]) -> tuple[int, int]:
    return int.from_bytes(socket.inet_aton(address[0]), "big"), address[1]


def destination(packet: Packet) -> tuple[str, int]:
    return socket.inet_ntoa(packet.address.to_bytes(4, "big")), packet.port


def wire_error(error: OSError) -> int:
    return -ERRORS.get(error.errno or 0, 12)


@dataclass(frozen=True)
class TurnConfig:
    host: str
    port: int
    username: str
    password: str
    tls: bool = True


class TurnProtocol(TurnClientTcpProtocol):

    def datagram_received(self, data: bytes | str, addr: tuple[str, int]) -> None:
        if isinstance(data, bytes) and len(data) >= 20 and (data[0] & 0xC0) == 0:
            try:
                message = stun.parse_message(data)
            except ValueError:
                return
            if message.message_class == stun.Class.INDICATION and message.message_method == stun.Method.DATA:
                # New peer ports arrive as indications before a channel has been bound.
                peer = message.attributes.get("XOR-PEER-ADDRESS")
                offset = 20
                while offset + 4 <= len(data):
                    kind, size = struct.unpack_from("!HH", data, offset)
                    if offset + 4 + size > len(data):
                        return
                    if kind == 0x0013 and self.receiver is not None and peer is not None:
                        self.receiver.datagram_received(data[offset + 4:offset + 4 + size], peer)
                        break
                    offset += 4 + (size + 3) // 4 * 4
                return
        super().datagram_received(data, addr)


class TurnDatagram(asyncio.DatagramProtocol):

    def __init__(self, received: Callable[[bytes, tuple[str, int]], None],
                 failed: Callable[[OSError], None], limit: int) -> None:
        self.received = received
        self.failed = failed
        self.limit = limit
        self.address = ("0.0.0.0", 0)
        self.peer: tuple[str, int] | None = None
        self.options: dict[int, int] = {4: 65536, 5: 65536}
        self.transport: asyncio.Transport | None = None
        self.protocol: TurnProtocol | None = None
        self.sender: asyncio.Task[None] | None = None
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()
        self.queued_bytes = 0
        self.closed = False

    async def open(self, config: TurnConfig) -> None:
        transport, protocol = await asyncio.get_running_loop().create_connection(
            lambda: TurnProtocol((config.host, config.port), config.username, config.password,
                                 lifetime=600, channel_refresh_time=240),
            config.host, config.port, ssl=config.tls or None, family=socket.AF_INET)
        self.transport = cast(asyncio.Transport, transport)
        self.protocol = protocol
        self.address = await protocol.connect()
        protocol.receiver = self
        self.sender = asyncio.create_task(self.send_packets())

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.closed:
            self.received(data, addr)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.closed:
            self.failed(OSError(errno.ECONNRESET, "TURN connection closed"))
            self.close()

    def sendto(self, data: bytes, peer: tuple[str, int]) -> None:
        if self.closed or self.protocol is None:
            raise OSError(errno.ENOTCONN, "TURN socket is closed")
        if self.queued_bytes + len(data) > self.limit:
            raise OSError(errno.ENOBUFS, "TURN send queue is full")
        self.queued_bytes += len(data)
        self.queue.put_nowait((data, peer))

    async def send_packets(self) -> None:
        assert self.protocol is not None
        try:
            while True:
                data, peer = await self.queue.get()
                await self.protocol.send_data(data, peer)
                self.queued_bytes -= len(data)
        except (OSError, stun.TransactionError) as error:
            self.failed(error if isinstance(error, OSError) else
                        OSError(errno.ECONNRESET, "TURN channel failed"))
            self.close()

    def close(self) -> None:
        self.closed = True
        if self.sender is not None:
            self.sender.cancel()
        if self.protocol is not None and self.protocol.refresh_task is not None:
            self.protocol.refresh_task.cancel()
        if self.transport is not None:
            self.transport.close()


@dataclass
class RelaySocket:
    native: socket.socket
    connecting: bool = False
    eof: bool = False
    queued: deque[tuple[bytes, tuple[str, int] | None]] = field(default_factory=deque)
    queued_bytes: int = 0


class RelaySession:

    def __init__(self, connection: ServerConnection, *, public_only: bool = False,
                 turn: TurnConfig | None = None) -> None:
        self.connection = connection
        self.loop = asyncio.get_running_loop()
        self.sockets: dict[int, RelaySocket | TurnDatagram] = {}
        self.next_descriptor = 1
        self.outgoing: asyncio.Queue[Packet] = asyncio.Queue()
        self.outgoing_bytes = 0
        self.requests: set[asyncio.Task[None]] = set()
        self.public_only = public_only
        self.turn = turn

    def peer(self, packet: Packet) -> tuple[str, int]:
        address = destination(packet)
        if self.public_only and not ipaddress.IPv4Address(address[0]).is_global:
            raise OSError(errno.EACCES, "Hosted relay destinations must be public")
        return address

    def emit(self, packet: Packet) -> None:
        if packet.op == 101:
            LOGGER.debug("recv fd=%d peer=%s:%d bytes=%d", packet.descriptor,
                         socket.inet_ntoa(packet.address.to_bytes(4, "big")), packet.port, len(packet.data))
        self.outgoing_bytes += HEADER.size + len(packet.data)
        if self.outgoing_bytes > LIMIT:
            raise OSError(errno.ENOBUFS, "Browser receive queue is full")
        self.outgoing.put_nowait(packet)

    def reply(self, packet: Packet, result: int = 0, *, address: int = 0,
              port: int = 0, data: bytes = b"") -> None:
        if packet.request:
            self.emit(Packet(100, packet.request, packet.descriptor, result, address, port, data))

    def close(self, descriptor: int) -> None:
        state = self.sockets.pop(descriptor, None)
        if isinstance(state, TurnDatagram):
            state.close()
        elif state is not None:
            self.loop.remove_reader(state.native.fileno())
            self.loop.remove_writer(state.native.fileno())
            state.native.close()

    def readable(self, descriptor: int) -> None:
        state = self.sockets.get(descriptor)
        if not isinstance(state, RelaySocket):
            return
        try:
            for _ in range(16):
                data, peer = state.native.recvfrom(65536)
                if not data and state.native.type == socket.SOCK_STREAM:
                    state.eof = True
                    self.loop.remove_reader(state.native.fileno())
                    self.emit(Packet(103, descriptor=descriptor))
                    return
                if not peer:
                    peer = state.native.getpeername()
                address, port = address_fields(peer)
                self.emit(Packet(101, descriptor=descriptor, address=address, port=port, data=data))
        except BlockingIOError:
            pass
        except OSError as error:
            LOGGER.warning("read fd=%d failed: %s", descriptor, error)
            self.loop.remove_reader(state.native.fileno())
            self.emit(Packet(104, descriptor=descriptor, result=wire_error(error)))

    def writable(self, descriptor: int) -> None:
        state = self.sockets.get(descriptor)
        if not isinstance(state, RelaySocket):
            return
        try:
            if state.connecting:
                error = state.native.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                state.connecting = False
                if error:
                    raise OSError(error, "Remote connection failed")
                self.loop.add_reader(state.native.fileno(), self.readable, descriptor)
                self.emit(Packet(102, descriptor=descriptor))
            while state.queued:
                data, peer = state.queued[0]
                count = state.native.sendto(data, peer) if peer else state.native.send(data)
                state.queued_bytes -= count
                if count == len(data):
                    state.queued.popleft()
                else:
                    state.queued[0] = (data[count:], peer)
                    break
            if not state.queued:
                self.loop.remove_writer(state.native.fileno())
        except BlockingIOError:
            self.loop.add_writer(state.native.fileno(), self.writable, descriptor)
        except OSError as error:
            LOGGER.warning("write fd=%d failed: %s", descriptor, error)
            self.loop.remove_writer(state.native.fileno())
            state.queued.clear()
            state.queued_bytes = 0
            self.emit(Packet(104, descriptor=descriptor, result=wire_error(error)))

    async def resolve(self, packet: Packet) -> None:
        try:
            host, service = packet.data.split(b"\0", 1)
            records = await self.loop.getaddrinfo(
                host.decode() or None, service.decode() or None, family=socket.AF_INET,
                type=packet.result, proto=packet.address)
            addresses = dict.fromkeys((address_fields(item[4])[0], item[1], item[2]) for item in records)
            payload = b"".join(RECORD.pack(*item) for item in addresses)
            self.reply(packet, port=records[0][4][1] if records else 0, data=payload)
        except (OSError, ValueError, UnicodeError) as error:
            self.reply(packet, wire_error(error) if isinstance(error, OSError) else -2)

    async def open_turn(self, packet: Packet, descriptor: int, state: TurnDatagram) -> None:
        assert self.turn is not None
        try:
            await asyncio.wait_for(state.open(self.turn), timeout=20)
            self.reply(packet, descriptor)
        except (OSError, TimeoutError, stun.TransactionError) as error:
            LOGGER.warning("TURN allocation failed: %s", type(error).__name__)
            self.close(descriptor)
            self.reply(packet, wire_error(error) if isinstance(error, OSError) else -8)

    def handle_turn(self, packet: Packet, state: TurnDatagram) -> None:
        if packet.op == 2:
            self.reply(packet)
        elif packet.op == 3:
            state.peer = self.peer(packet)
            self.emit(Packet(102, descriptor=packet.descriptor))
        elif packet.op == 4:
            peer = self.peer(packet) if packet.port else state.peer
            if peer is None:
                raise OSError(errno.ENOTCONN, "UDP socket has no peer")
            state.sendto(packet.data, peer)
        elif packet.op == 5:
            self.close(packet.descriptor)
        elif packet.op == 6:
            address, port = address_fields(state.address)
            self.reply(packet, address=address, port=port)
        elif packet.op in (7, 8) and packet.address in (1, 2, 4, 5):
            if packet.op == 7:
                state.options[packet.address] = struct.unpack_from("<i", packet.data)[0]
                self.reply(packet)
            else:
                self.reply(packet, state.options.get(packet.address, 0))
        else:
            raise OSError(errno.EINVAL, "Unsupported TURN socket operation")

    def handle(self, packet: Packet) -> None:
        LOGGER.debug("op=%d fd=%d arg=%d address=%s port=%d bytes=%d", packet.op,
                     packet.descriptor, packet.result,
                     socket.inet_ntoa(packet.address.to_bytes(4, "big")), packet.port, len(packet.data))
        try:
            if packet.op == 9:
                task = asyncio.create_task(self.resolve(packet))
                self.requests.add(task)
                task.add_done_callback(self.requests.discard)
                return
            if packet.op == 1:
                if len(self.sockets) >= 64 or packet.result not in (1, 2) or packet.address not in (0, 6, 17):
                    raise OSError(errno.EMFILE, "Socket limit or unsupported socket type")
                if self.turn is not None and packet.result == socket.SOCK_DGRAM:
                    descriptor = self.next_descriptor
                    self.next_descriptor += 1
                    turn_state = TurnDatagram(
                        lambda data, peer: self.emit(Packet(101, descriptor=descriptor,
                                                           address=address_fields(peer)[0],
                                                           port=peer[1], data=data)),
                        lambda error: self.emit(Packet(104, descriptor=descriptor, result=wire_error(error))),
                        LIMIT)
                    self.sockets[descriptor] = turn_state
                    task = asyncio.create_task(self.open_turn(packet, descriptor, turn_state))
                    self.requests.add(task)
                    task.add_done_callback(self.requests.discard)
                    return
                native = socket.socket(socket.AF_INET, packet.result, packet.address)
                native.setblocking(False)
                descriptor = self.next_descriptor
                self.next_descriptor += 1
                self.sockets[descriptor] = RelaySocket(native)
                if packet.result == socket.SOCK_DGRAM:
                    self.loop.add_reader(native.fileno(), self.readable, descriptor)
                self.reply(packet, descriptor)
                return
            state = self.sockets.get(packet.descriptor)
            if state is None:
                raise OSError(errno.EBADF, "Unknown socket")
            if isinstance(state, TurnDatagram):
                self.handle_turn(packet, state)
                return
            native = state.native
            if packet.op == 2:
                # Browser clients have separate virtual interfaces and may reuse the same game port.
                native.bind(("0.0.0.0", 0) if self.public_only else destination(packet))
                self.reply(packet)
            elif packet.op == 3:
                error = native.connect_ex(self.peer(packet))
                if error in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                    state.connecting = True
                    self.loop.add_writer(native.fileno(), self.writable, packet.descriptor)
                elif error:
                    self.emit(Packet(102, descriptor=packet.descriptor,
                                     result=wire_error(OSError(error, "Remote connection failed"))))
                else:
                    self.loop.add_reader(native.fileno(), self.readable, packet.descriptor)
                    self.emit(Packet(102, descriptor=packet.descriptor))
            elif packet.op == 4:
                if state.queued_bytes + len(packet.data) > LIMIT:
                    raise OSError(errno.ENOBUFS, "Remote send queue is full")
                peer = self.peer(packet) if packet.port else None
                state.queued.append((packet.data, peer))
                state.queued_bytes += len(packet.data)
                self.writable(packet.descriptor)
                if state.queued:
                    self.loop.add_writer(native.fileno(), self.writable, packet.descriptor)
            elif packet.op == 5:
                self.close(packet.descriptor)
            elif packet.op == 6:
                address, port = address_fields(native.getsockname())
                self.reply(packet, address=address, port=port)
            elif packet.op in (7, 8):
                level, option = OPTIONS[packet.address]
                if packet.op == 7:
                    value = (struct.pack("ii", *struct.unpack("<ii", packet.data)) if packet.address == 6
                             else struct.unpack_from("<i", packet.data)[0])
                    native.setsockopt(level, option, value)
                    self.reply(packet)
                else:
                    self.reply(packet, native.getsockopt(level, option))
            elif packet.op == 10:
                native.shutdown(packet.result)
            else:
                raise OSError(errno.EINVAL, "Unknown socket operation")
        except (OSError, KeyError, struct.error) as error:
            LOGGER.warning("op=%d fd=%d failed: %s", packet.op, packet.descriptor, error)
            result = wire_error(error) if isinstance(error, OSError) else -2
            if packet.request:
                self.reply(packet, result)
            else:
                self.emit(Packet(104, descriptor=packet.descriptor, result=result))

    async def send_packets(self) -> None:
        while True:
            packet = await self.outgoing.get()
            self.outgoing_bytes -= HEADER.size + len(packet.data)
            await self.connection.send(packet.encode())

    async def run(self) -> None:
        sender = asyncio.create_task(self.send_packets())
        try:
            async for message in self.connection:
                if isinstance(message, str):
                    raise ValueError("Socket packets must be binary")
                self.handle(Packet.decode(message))
        except (ConnectionClosed, ValueError):
            pass
        finally:
            sender.cancel()
            for task in self.requests:
                task.cancel()
            await asyncio.gather(sender, *self.requests, return_exceptions=True)
            for descriptor in list(self.sockets):
                self.close(descriptor)


class NetworkRelay:

    def __init__(self, origins: Sequence[str | None]) -> None:
        self.origins = origins
        self.port = 0
        self.ready = threading.Event()
        self.failure: BaseException | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop_event: asyncio.Event | None = None
        self.thread = threading.Thread(target=self.run, name="network-relay", daemon=True)

    async def accept(self, connection: ServerConnection) -> None:
        if connection.request is None or connection.request.path != "/network":
            await connection.close(1008, "Unknown relay route")
            return
        LOGGER.info("Browser socket session connected")
        await RelaySession(connection).run()
        LOGGER.info("Browser socket session closed")

    async def serve(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        async with serve(self.accept, "127.0.0.1", 0, origins=self.origins,
                         subprotocols=[PROTOCOL], compression=None, max_size=1024 * 1024 + HEADER.size) as server:
            self.port = server.sockets[0].getsockname()[1]
            self.ready.set()
            await self.stop_event.wait()

    def run(self) -> None:
        try:
            asyncio.run(self.serve())
        except BaseException as error:
            self.failure = error
            self.ready.set()

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("Network relay did not start")
        if self.failure:
            raise RuntimeError("Network relay failed") from self.failure

    def stop(self) -> None:
        if self.loop is not None and self.stop_event is not None:
            self.loop.call_soon_threadsafe(self.stop_event.set)
            self.thread.join(timeout=5)
