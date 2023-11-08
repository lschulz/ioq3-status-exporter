#!/bin/env python3

import argparse
import asyncio
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, List, NamedTuple, Optional, Tuple

import influxdb_client
from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync

influx_url = "https://127.0.0.1:8086"
influx_bucket = "scion"
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


class Server(NamedTuple):
    type:  AddrType
    scion: Optional[IA]
    ip:    Any
    port:  int


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


async def count_servers(master_ip, master_port: int = 27950):
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

            srv_cnt = [0, 0, 0, 0]
            for server in servers:
                srv_cnt[server.type.value] += 1

            p = influxdb_client.Point("q3a_servers").tag("master", master_ip)
            p.field("ipv4", srv_cnt[0])
            p.field("ipv6", srv_cnt[1])
            p.field("scion_ipv4", srv_cnt[2])
            p.field("scion_ipv6", srv_cnt[3])
            await write_api.write(bucket=influx_bucket, record=[p])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("master", help="IP address of the master server")
    parser.add_argument("-p", "--port", default=27950, help="Master server port")
    args = parser.parse_args()
    asyncio.run(count_servers(args.master, args.port))


if __name__ == "__main__":
    main()
