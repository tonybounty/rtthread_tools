#  Author:      Tanski Mikaël (@tony_bounty)
#               
#
#  This is a simple little module I wrote to make life easier.  I didn't
#  see anything quite like it in the library, though I may have overlooked
#  something.  I wrote this when I was trying to read some heavily nested
#  tuples with fairly non-descriptive content.  This is modeled very much
#  after Lisp/Scheme - style pretty-printing of lists.  If you find it
#  useful, thank small children who sleep at night.

import struct
import io
import gzip
import zlib
import ctypes
from datetime import datetime
from enum import Enum

from Crypto import Cipher
from Crypto.Cipher import AES


class CompressionType(Enum):
  NONE = 0x0
  QUICKLZ = 0x200
  FASTLZ = 0x300
  GZIP = 0x100

class CipherType(Enum):
  NONE = 0x0
  AES = 0x2

class ReaderHeaderError(Exception):
  pass

class ReaderDataError(Exception):
  pass

class Reader():
  """
  Reader for OTA RThread firmware file (.rbl)

  Call method Process(...) to decompress/decipher.
  """
  def __init__(self, rbl_file:bytes):
    """
      Reader(self, rbl_file)
      \tParse RBL file from rbl_file (bytes type)
    """
    # RBL Header == 0x60 bytes
    if len(rbl_file) <= 0x60:
      raise ReaderHeaderError("Invalid RBL file size, <= 0x60 bytes")

    stream = io.BytesIO(rbl_file)

    read_dword = lambda: struct.unpack("<I", stream.read(4))[0]
    read_int = lambda: struct.unpack("<i", stream.read(4))[0]
    
    self._magic = stream.read(4)
    self._algo = read_dword()
    self._timestamp = read_dword()
    self._name = stream.read(16)
    self._version = stream.read(24)
    self._sn = stream.read(24)
    self._crc32 = read_dword()
    self._hash = read_dword()
    self._size_raw = read_int()
    self._size_package = read_int()
    self._info_crc32 = read_dword()
    self._data = stream.read()

    if self._magic != b'RBL\x00':
      raise ReaderHeaderError("Invalid magic byte, first 3 bytes should be RBL\\0")
    
    self._compression_type = None
    for v in CompressionType:
      if v.value == (self._algo & 0xF00):
        self._compression_type = v
    if not self._compression_type:
      raise ReaderHeaderError(f"Invalid compression type {hex(self._algo & 0xF00)}")

    self._cipher_type = None
    for v in CipherType:
      if v.value == (self._algo & 0xF):
        self._cipher_type = v
    if not self._cipher_type:
      raise ReaderHeaderError(f"Invalid cipher type {hex(self._algo & 0xF)}")

    if self._crc32 != zlib.crc32(self._data):
      raise ReaderDataError("Invalid data CRC32")

    stream.seek(0, io.SEEK_SET)
    if self._info_crc32 != zlib.crc32(stream.read(0x5c)):
      raise ReaderDataError("Invalid header CRC32") 

  def Process(self, key=None, iv=None, check_hash=True) -> bytes:
    """
    Process(self, key=None, iv=None, check_hash=True)
    \tReturn decompressed (if necessary) and deciphered (if necessary) current RBL data.
    \tiv and key are mandatory if property S.cipher_type != 'NONE'. check_hash
    \tcompute the Fowler–Noll–Vo hash of decompressed/deciphered data then compare
    \tresult with hash in rbl header, if is different an excepton ReaderDataError is raise. 
    """
    data = self._data
    
    # AES
    if self._cipher_type == CipherType.AES:
      if key == None or iv == None:
        raise ValueError("No AES key/IV was set")
      aes = AES.new(key, AES.MODE_CBC, iv)
      data = aes.decrypt(data)

    if self._compression_type == CompressionType.GZIP:
      buf = io.BytesIO(data)
      with gzip.GzipFile(mode='rb', fileobj=buf) as f:
        data = f.read(self._size_raw)
    elif self._compression_type == CompressionType.QUICKLZ:
      raise NotImplementedError("QUICKLZ compression is not implemented")
    elif self._compression_type == CompressionType.FASTLZ:
      raise NotImplementedError("FASTLZ compression is not implemented")

    if check_hash:
      if self._hash != self.hash_fnv1a(data):
        raise ReaderDataError("FNV1A hash is not same, data is corrupted")
    return data

      

  @property
  def compression_type(self) -> str:
    return self._compression_type
  
  @property 
  def cipher_type(self) -> str:
    return self._cipher_type

  @property
  def timestamp(self) -> datetime:
    return datetime.fromtimestamp(self._timestamp)

  @property
  def name(self) -> str:
    return self._name.decode("ascii")
  
  @property
  def version(self) -> str:
    return self._version.decode("ascii")
  
  @property
  def sn(self) -> str:
    return self._sn.decode("ascii")

  @property
  def crc32_data(self) -> int:
    return self._crc32

  @property
  def size_raw(self) -> int:
    return self._size_raw

  @property
  def hash(self) -> int:
    return self._hash

  @property
  def size_package(self) -> int:
    return self._size_package

  @property
  def header_crc32(self) -> int:
    return self._info_crc32

  # Fowler–Noll–Vo hash function
  def hash_fnv1a(self, data:bytes, hash=0x811C9DC5) -> int:
    hash32 = ctypes.c_uint32(hash)
    for b in data:
      hash32.value = (b ^ hash32.value) * 16777619
    return hash32.value