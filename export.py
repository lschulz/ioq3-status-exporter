#!/bin/env python3

import argparse
import asyncio
import secrets
import time
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import influxdb_client
from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync

import pan
from pan import udp as pan_udp

influx_url = "https://127.0.0.1:8086"
influx_bucket = "ioq3-scion"
influx_org = ""
influx_token = ""


class AddrType(Enum):
    IPV4 = 0
    IPV6 = 1
    SCION_IPV4 = 2
    SCION_IPV6 = 3


class IA(NamedTuple):
    isd: int
    asn: int

    def __str__(self):
        if self.asn < 2**32:
            return f"{self.isd}-{self.asn}"
        else:
            hig = (self.asn >> 32) & 0xffff
            mid = (self.asn >> 16) & 0xffff
            low = self.asn & 0xffff
            return f"{self.isd}-{hig:x}:{mid:x}:{low:x}"


class Server(NamedTuple):
    type:  AddrType
    scion: Optional[IA]
    ip:    Any
    port:  int

    def __str__(self):
        if self.type == AddrType.IPV4:
            return f"{self.ip}:{self.port}"
        elif self.type == AddrType.IPV6:
            return f"[{self.ip}]:{self.port}"
        elif self.type == AddrType.SCION_IPV4 or self.type == AddrType.SCION_IPV6:
            return f"[{self.scion},{self.ip}]:{self.port}"
        else:
            assert False


def parse_server_list(raw: bytes) -> Tuple[List[Server], bool]:
    servers = []

    while len(raw) > 0:
        if raw[0] == ord(b"\\"):
            # IPv4
            if raw[1:7] == b"EOT\0\0\0":
                return (servers, True)
            ip = IPv4Address(raw[1:5])
            port = int.from_bytes(raw[5:7], 'big')
            servers.append(Server(AddrType.IPV4, None, ip, port))
            raw = raw[7:]
        elif raw[0] == ord(b"/"):
            # IPv6
            ip = IPv6Address(raw[1:17])
            port = int.from_bytes(raw[17:19], 'big')
            servers.append(Server(AddrType.IPV6, None, ip, port))
            raw = raw[19:]
        elif raw[0] == ord(b"$"):
            if raw[1] == ord(b"\\"):
                # SCION + IPv4
                ia = IA(int.from_bytes(raw[2:4], 'big'),
                        int.from_bytes(raw[4:10], 'big'))
                ip = IPv4Address(raw[10:14])
                port = int.from_bytes(raw[14:16], 'big')
                servers.append(Server(AddrType.SCION_IPV4, ia, ip, port))
                raw = raw[16:]
            elif ord(b"/"):
                # SCION + IPv6
                ia = IA(int.from_bytes(raw[2:4], 'big'),
                        int.from_bytes(raw[4:10], 'big'))
                ip = IPv4Address(raw[10:26])
                port = int.from_bytes(raw[26:28], 'big')
                servers.append(Server(AddrType.SCION_IPV6, ia, ip, port))
                raw = raw[28:]
            else:
                print("WARNING: Invalid response packet")
                return servers, False

    return servers, False


class MasterQueryProtocol(asyncio.DatagramProtocol):
    def __init__(self,
            servers: asyncio.Future[List[Server]],
            game_name: bytes = b"Quake3Arena",
            protocol: int = 68,
            args: bytes = b"ipv4 ipv6 scion",
            timeout: float = 1.0, # seconds
            ):
        self._servers = servers
        self._query = b"\xff\xff\xff\xffgetserversExt %b %d %b" % (game_name, protocol, args)
        self._timeout = timeout
        self._server_list: List[Server] = []
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self._transport = transport
        self._timer = asyncio.get_running_loop().call_later(self._timeout, self.connection_timeout)
        self._transport.sendto(self._query)

    def datagram_received(self, data, addr):
        header = b"\xff\xff\xff\xffgetserversExtResponse"
        if data.startswith(header):
            try:
                servers, eof = parse_server_list(data[len(header):])
            except Exception as e:
                print("WARNING:", e)
            else:
                self._server_list.extend(servers)
                if eof and self._transport:
                    self._servers.set_result(self._server_list)
                    self._transport.close()
        else:
            print("WARNING: Invalid response packet")

    def error_received(self, e):
        print("WARNING:", e)

    def connection_timeout(self):
        self._servers.set_exception(RuntimeError("No response from master server"))

    def connection_lost(self, exc):
        self._timer.cancel()


def parse_status_string(raw: bytes) -> Dict:
    d = {}
    split = raw.split(b"\\")[1:]
    for k, v in list(zip(split, split[1:]))[::2]:
        v = v.decode()
        try:
            v = int(v)
        except:
            pass
        d[k.decode()] = v
    return d


def parse_status(status: bytes, challenge: str) -> Optional[Dict]:
    d = parse_status_string(status.splitlines()[1])
    if d.get("challenge") == challenge:
        return d
    return None


class ServerStatusProtocol(asyncio.DatagramProtocol):
    """Sends a getstatus and getinfo command to the server and merges the results.
    TODO: Retransmit after timeout?
    """
    def __init__(self,
            status: asyncio.Future[Dict],
            timeout: float = 1.0, # seconds
            ):
        self._status = status
        self._challenge = secrets.token_urlsafe(8)
        self._query_info = b"\xff\xff\xff\xffgetstatus %b" % self._challenge.encode()
        self._query_status = b"\xff\xff\xff\xffgetinfo %b" % self._challenge.encode()
        self._info_response = None
        self._status_response = None
        self._timeout = timeout
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self._transport = transport
        self._timer = asyncio.get_running_loop().call_later(self._timeout, self.connection_timeout)
        self._transport.sendto(self._query_info)
        self._transport.sendto(self._query_status)

    def datagram_received(self, data, addr):
        try:
            if data.startswith(b"\xff\xff\xff\xffinfoResponse\n"):
                self._info_response = parse_status(data, self._challenge)
            elif data.startswith(b"\xff\xff\xff\xffstatusResponse\n"):
                self._status_response = parse_status(data, self._challenge)
        except Exception as e:
            print("WARNING:", e)
        if self._info_response and self._status_response:
            self._status.set_result({**self._info_response, **self._status_response})
            if self._transport is not None:
                self._transport.close()

    def error_received(self, e):
        print("WARNING:", e)

    def connection_timeout(self):
        self._status.set_exception(RuntimeError("No response from server"))

    def connection_lost(self, exc):
        self._timer.cancel()


async def get_status(loop, server: Tuple[str, int], timeout: float = 1.0):
    future_status = loop.create_future()
    transport, proto = await loop.create_datagram_endpoint(
        lambda: ServerStatusProtocol(future_status, timeout),
        remote_addr = server)
    return future_status, transport


def get_status_pan(server: str, timeout: float = 1.0):
    remote = pan_udp.resolveUDPAddr(server)
    with pan_udp.Conn(remote) as conn:
        challenge = secrets.token_urlsafe(8)
        conn.write(b"\xff\xff\xff\xffgetinfo %b" % challenge.encode())
        conn.write(b"\xff\xff\xff\xffgetstatus %b" % challenge.encode())

        t0 = time.time()
        info_response = None
        status_response = None
        while True:
            conn.set_deadline(timeout)
            data = conn.read()
            if data.startswith(b"\xff\xff\xff\xffinfoResponse\n"):
                info_response = parse_status(data, challenge)
            elif data.startswith(b"\xff\xff\xff\xffstatusResponse\n"):
                status_response = parse_status(data, challenge)
            if info_response and status_response:
                return {**info_response, **status_response}
            elif (time.time() - t0) > timeout:
                raise pan.DeadlineExceeded()


def add_field(p: influxdb_client.Point, status: Dict, key: str) -> influxdb_client.Point:
    v = status.get(key)
    if v is not None:
        p.field(key, v)
    return p


async def query_servers(master_ip, master_port: int = 27950):
    loop = asyncio.get_running_loop()
    future_servers = loop.create_future()

    transport, proto = await loop.create_datagram_endpoint(
        lambda: MasterQueryProtocol(future_servers),
        remote_addr = (master_ip, master_port))

    async with InfluxDBClientAsync(url=influx_url,
        token=influx_token, org=influx_org, verify_ssl=False) as client:

        servers = None
        try:
            servers = await future_servers
        except Exception as e:
            print("ERROR:", e)
        finally:
            transport.close()

        if servers is not None:
            write_api = client.write_api()

            record = []
            srv_cnt = [0, 0, 0, 0]
            for server in servers:
                srv_cnt[server.type.value] += 1
                p = influxdb_client.Point("server_status")
                p.tag("server", str(server)).tag("type", server.type.name)
                # TODO: Concurrency
                if server.type == AddrType.IPV4 or server.type == AddrType.IPV6:
                    future_status, transport = await get_status(loop, (str(server.ip), server.port))
                    try:
                        status = await future_status
                    except Exception as e:
                        print(f"ERROR({str(server)}):", e)
                        p.field("online", False)
                        record.append(p)
                        continue
                    finally:
                        transport.close()
                elif server.type == AddrType.SCION_IPV4 or server.type == AddrType.SCION_IPV6:
                    try:
                        status = get_status_pan(str(server))
                    except Exception as e:
                        print(f"ERROR({str(server)}):", e)
                        p.field("online", False)
                        record.append(p)
                        continue
                else:
                    continue
                p.field("online", True)
                add_field(p, status, "sv_hostname")
                add_field(p, status, "sv_encryption")
                add_field(p, status, "com_gamename")
                add_field(p, status, "com_protocol")
                add_field(p, status, "version")
                add_field(p, status, "g_gametype")
                add_field(p, status, "mapname")
                add_field(p, status, "g_humanplayers")
                record.append(p)

            p = influxdb_client.Point("server_count").tag("master", master_ip)
            p.field("ipv4", srv_cnt[0])
            p.field("ipv6", srv_cnt[1])
            p.field("scion_ipv4", srv_cnt[2])
            p.field("scion_ipv6", srv_cnt[3])
            record.append(p)

            for r in record:
                print(str(r))
            await write_api.write(bucket=influx_bucket, record=record)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("master", help="IP address of the master server")
    parser.add_argument("-p", "--port", default=27950, help="Master server port")
    args = parser.parse_args()
    asyncio.run(query_servers(args.master, args.port))


if __name__ == "__main__":
    main()
