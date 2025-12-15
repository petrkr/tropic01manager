"""
Device Connection Manager for TROPIC01 Manager

Provides driver abstraction and connection lifecycle management
to allow the application to start without requiring a physical device.
"""

from tropicsquare.ports.cpython import TropicSquareCPython
from networkspi import NetworkSPI, DummyNetworkSpiCSPin
from uartspi import UartSPI, TropicUartSpiCS


class SPIDriverType:
    """Available SPI driver types"""
    UART = "UART"
    NETWORK = "Network"


class SPIDriverFactory:
    """Factory for creating SPI driver instances based on type and configuration"""

    @staticmethod
    def create_driver(driver_type, config):
        """
        Create an SPI driver instance.

        Args:
            driver_type: One of SPIDriverType (UART or NETWORK)
            config: Dictionary with driver-specific configuration
                    For UART: {'port': '/dev/ttyACM1', 'baudrate': 115200}
                    For NETWORK: {'host': '192.168.1.100', 'port': 5000}

        Returns:
            tuple: (spi_driver, cs_pin_wrapper)

        Raises:
            ValueError: If driver_type is unknown
            Exception: If driver initialization fails
        """
        if driver_type == SPIDriverType.UART:
            port = config.get('port', '/dev/ttyACM1')
            baudrate = config.get('baudrate', 115200)
            spi = UartSPI(port, baudrate)
            cs = TropicUartSpiCS(spi)
            return spi, cs

        elif driver_type == SPIDriverType.NETWORK:
            host = config.get('host', 'localhost')
            port = config.get('port', 5000)
            spi = NetworkSPI(host, port)
            cs = DummyNetworkSpiCSPin(spi)
            return spi, cs

        else:
            raise ValueError(f"Unknown driver type: {driver_type}")

    @staticmethod
    def get_available_types():
        """Return list of available driver types"""
        return [SPIDriverType.UART, SPIDriverType.NETWORK]


class DeviceConnectionManager:
    """
    Manages device connection lifecycle.

    Allows the application to start without a device connected,
    and provides connect/disconnect functionality.
    """

    def __init__(self):
        """Initialize connection manager in disconnected state"""
        self.ts = None
        self.spi = None
        self.cs = None
        self._connected = False
        self._driver_type = None
        self._config = None

    def connect(self, driver_type, config):
        """
        Connect to device using specified driver type and configuration.

        Args:
            driver_type: One of SPIDriverType (UART or NETWORK)
            config: Dictionary with driver-specific configuration

        Returns:
            bool: True if connection successful, False otherwise

        Raises:
            Exception: Connection errors are propagated to caller
        """
        # Clean up any existing connection first
        if self._connected:
            self.disconnect()

        try:
            # Create driver using factory
            self.spi, self.cs = SPIDriverFactory.create_driver(driver_type, config)

            # Create TropicSquare protocol handler
            self.ts = TropicSquareCPython(self.spi, self.cs)

            # Store connection info
            self._driver_type = driver_type
            self._config = config.copy()
            self._connected = True

            return True

        except Exception as e:
            # Clean up on failure
            self.spi = None
            self.cs = None
            self.ts = None
            self._connected = False
            raise e

    def disconnect(self):
        """
        Disconnect from device and clean up resources.

        Returns:
            bool: True if disconnection successful
        """
        if not self._connected:
            return True

        try:
            # Abort any active secure session
            if self.ts and hasattr(self.ts, '_secure_session') and self.ts._secure_session:
                try:
                    self.ts.abort_secure_session()
                except:
                    pass  # Ignore errors during cleanup

            # Close SPI connection
            if self.spi and hasattr(self.spi, 'close'):
                try:
                    self.spi.close()
                except:
                    pass  # Ignore errors during cleanup

        finally:
            # Always clear state
            self.ts = None
            self.spi = None
            self.cs = None
            self._connected = False
            self._driver_type = None
            self._config = None

        return True

    def is_connected(self):
        """
        Check if device is currently connected.

        Returns:
            bool: True if connected, False otherwise
        """
        return self._connected

    def get_device(self):
        """
        Get TropicSquare device instance.

        Returns:
            TropicSquareCPython or None: Device instance if connected, None otherwise
        """
        return self.ts if self._connected else None

    def get_connection_info(self):
        """
        Get current connection information.

        Returns:
            dict: {'driver_type': str, 'config': dict, 'connected': bool}
        """
        return {
            'driver_type': self._driver_type,
            'config': self._config.copy() if self._config else {},
            'connected': self._connected
        }

    def has_active_session(self):
        """
        Check if there is an active secure session.

        Returns:
            bool: True if connected and has active secure session
        """
        if not self._connected or not self.ts:
            return False

        return hasattr(self.ts, '_secure_session') and self.ts._secure_session is not None
