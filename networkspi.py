import socket

class DummyNetworkSpiCSPin:
    def __init__(self, network_spi):
        self.pin = network_spi.set_cs
    

    def value(self, value):
        self.pin(value)


class NetworkSPI:
    COMMAND_READ = b'\x01'
    COMMAND_READINTO = b'\x02'
    COMMAND_WRITE = b'\x04'
    COMMAND_WRITE_READINTO = b'\x08'

    COMMAND_CS_LOW = b'\x10'
    COMMAND_CS_HIGH = b'\x20'


    def __init__(self, host, port):
        hostport = socket.getaddrinfo(host, port)
        self.sock = socket.socket()
        self.sock.connect(hostport[0][-1])


    def write_readinto(self, write_buf, read_buf):
        command = self.COMMAND_WRITE_READINTO
        data = bytes(write_buf)
        length = len(data)
        packet = command + length.to_bytes(4, 'big') + data
        self.sock.send(packet)
        
        received = b''
        while len(received) < length:
            chunk = self.sock.recv(length - len(received))
            if not chunk:
                raise RuntimeError("Connection lost during SPI transfer")
            received += chunk
        for i in range(len(received)):
            read_buf[i] = received[i]


    def readinto(self, read_buf):
        command = self.COMMAND_READINTO
        length = len(read_buf)
        packet = command + length.to_bytes(4, 'big')
        self.sock.send(packet)
        
        received = b''
        while len(received) < length:
            chunk = self.sock.recv(length - len(received))
            if not chunk:
                raise RuntimeError("Connection lost during SPI transfer")
            received += chunk
   
        for i in range(len(received)):
            read_buf[i] = received[i]


    def read(self, length):
        command = self.COMMAND_READ
        packet = command + length.to_bytes(4, 'big')
        self.sock.send(packet)
        
        received = b''
        while len(received) < length:
            chunk = self.sock.recv(length - len(received))
            if not chunk:
                raise Exception("Connection lost during SPI transfer")
            received += chunk

        return received


    def write(self, data):
        command = self.COMMAND_WRITE
        length = len(data)
        packet = command + length.to_bytes(4, "big") + data
        self.sock.send(packet)


    def set_cs(self, state: bool):
        """Sends a command (0x01) to set the chip select state.
           The state is sent as 1 byte (0 for low, 1 for high)."""
        command = self.COMMAND_CS_HIGH if state else self.COMMAND_CS_LOW
        self.sock.send(command)

        ack = self.sock.recv(1)
        if ack != b'\x00':
            raise RuntimeError("Chip select command failed, ack: " + str(ack))


    def close(self):
        self.sock.close()
