#
# This file is part of LiteX.
#
# Copyright (c) 2015-2020 Florent Kermarrec <florent@enjoy-digital.fr>
# Copyright (c) 2016 Tim 'mithro' Ansell <mithro@mithis.com>
# SPDX-License-Identifier: BSD-2-Clause

import socket

from litex.tools.remote.etherbone import EtherbonePacket, EtherboneRecord
from litex.tools.remote.etherbone import EtherboneReads, EtherboneWrites

from litex.tools.remote.csr_builder import CSRBuilder

# CommTCP ------------------------------------------------------------------------------------------

class CommTCP(CSRBuilder):
    def __init__(self, server="192.168.1.50", port=1234, csr_csv=None, debug=False):
        CSRBuilder.__init__(self, comm=self, csr_csv=csr_csv)
        self.server = server
        self.port   = port
        self.debug  = debug

    def open(self, probe=True):
        if hasattr(self, "socket"):
            return
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))
        self.socket.settimeout(2)
        if probe:
            self.probe(self.server, self.port)

    def close(self):
        if not hasattr(self, "socket"):
            return
        self.socket.close()
        del self.socket

    def probe(self, ip, port, loose=False):
        raise NotImplementedError("Cannot use probe function in TCP.")

    def scan(self, ip="192.168.1.x"):
        raise NotImplementedError("Cannot use scan function in TCP.")

    def read(self, addr, length=None, burst="incr"):
        assert burst == "incr"
        length_int = 1 if length is None else length
        record = EtherboneRecord()
        record.reads = EtherboneReads(addrs=[addr+4*j for j in range(length_int)])
        record.rcount = len(record.reads)

        packet = EtherbonePacket()
        packet.records = [record]
        packet.encode()

        self.socket.sendall(packet.bytes)

        datas = self.socket.recv(8192)
        packet = EtherbonePacket(datas)
        packet.decode()
        datas = packet.records.pop().writes.get_datas()
        if self.debug:
            for i, value in enumerate(datas):
                print("read 0x{:08x} @ 0x{:08x}".format(value, addr + 4*i))
        return datas[0] if length is None else datas

    def write(self, addr, datas):
        datas = datas if isinstance(datas, list) else [datas]
        length = len(datas)
        record = EtherboneRecord()
        record.writes = EtherboneWrites(base_addr=addr, datas=iter(datas))
        record.wcount = len(record.writes)

        packet = EtherbonePacket()
        packet.records = [record]
        packet.encode()

        self.socket.sendall(packet.bytes)

        if self.debug:
            for i, value in enumerate(datas):
                print("write 0x{:08x} @ 0x{:08x}".format(value, addr + 4*i))
