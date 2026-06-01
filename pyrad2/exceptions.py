class RadiusException(Exception):
    """Base class for all exceptions raised by pyrad2."""

    pass


class ServerPacketError(RadiusException):
    """Exception class for bogus packets.
    ServerPacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """

    pass


class Timeout(RadiusException):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a RADIUS server to respond."""

    pass


class PacketError(RadiusException):
    """Raised when the packet is invalid."""

    pass


class IdentifierExhausted(RadiusException):
    """All 256 RADIUS Identifier slots on a single (source IP, port) flow
    are currently in flight.

    RFC 2865 §3 caps the Identifier field at one octet. Callers that hit
    this need to either wait for an in-flight request to complete, open
    a second source port to get a fresh 256-id space, or queue.
    """

    pass


class ParseError(RadiusException):
    """Exception raised for errors while parsing RADIUS dictionary files.

    Attributes:
        msg (str): Error message.
        file (str): Dictionary file the error originated in, if known.
        line (int): Line number, or ``-1`` if not known.
    """

    def __init__(
        self,
        msg: str | None = None,
        *,
        file: str = "",
        line: int = -1,
    ) -> None:
        self.msg = msg
        self.file = file
        self.line = line

    def __str__(self) -> str:
        out = ""
        if self.file:
            out += self.file
        if self.line > -1:
            out += "(%d)" % self.line
        if self.file or self.line > -1:
            out += ": "
        out += "Parse error"
        if self.msg:
            out += ": %s" % self.msg
        return out
