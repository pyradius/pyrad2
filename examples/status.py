#!/usr/bin/python
import sys
import os

from loguru import logger

from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
from pyrad2.exceptions import Timeout

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))


def format_attribute_values(values):
    """Return RADIUS attribute values in a readable form for the example."""
    return [value.hex() if isinstance(value, bytes) else value for value in values]


srv = Client(
    server="127.0.0.1",
    authport=1812,
    secret=b"Kah3choteereethiejeimaeziecumi",
    dict=Dictionary(THIS_FOLDER + "/dictionary"),
    retries=1,
    timeout=2,
)

req = srv.create_status_packet()
req["FreeRADIUS-Statistics-Type"] = "All"

try:
    logger.info("Sending Status-Server request")
    reply = srv.send_status_packet(req, port="auth")
except Timeout:
    logger.error("RADIUS server does not reply")
    sys.exit(1)
except OSError as error:
    logger.error("Network error: {}", error[1])
    sys.exit(1)

logger.info("Attributes returned by server:")
for i in reply.keys():
    logger.info("{}: {}", i, format_attribute_values(reply[i]))
