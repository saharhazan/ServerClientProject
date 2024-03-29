""" Name: Sahar Hazan
    ID: 316495092 """

from enum import Enum
from encryptor import AES_KEY_SIZE

PACKET_SIZE = 1024
SERVER_VER = 3
UUID_BYTES = 16
REQ_HEADER_SIZE = 23
DB_NAME = 'defensive.db'
USER_LENGTH = 255
DEFAULT_PORT = 1357
PUB_KEY_LEN = 160
SIZE_UINT32_T = 4
MAX_FILE_LEN = 255
MAX_AES_LEN = 128


class RequestCode(Enum):
    REGISTER_REQUEST = 1025
    PUB_KEY_SEND = 1026
    LOGIN_REQUEST = 1027
    FILE_SEND = 1028
    CRC_OK = 1029
    CRC_INVALID_RETRY = 1030
    CRC_INVALID_EXIT = 1031


class ResponseCode(Enum):
    REGISTER_SUCCESS = 2100
    REGISTER_ERROR = 2101
    PUB_KEY_RECEVIED = 2102
    FILE_OK_CRC = 2103
    MSG_RECEIVED = 2104
    LOGIN_SUCCESS = 2105
    LOGIN_ERROR = 2106
    GENERAL_ERROR = 2107
