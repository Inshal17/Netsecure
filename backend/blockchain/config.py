import os


FABRIC_GATEWAY_URL = os.getenv(
    "FABRIC_GATEWAY_URL",
    "http://localhost:8081",
)

FABRIC_CHANNEL = os.getenv(
    "FABRIC_CHANNEL",
    "mychannel",
)

FABRIC_CHAINCODE = os.getenv(
    "FABRIC_CHAINCODE",
    "evidence",
)