# rtthread-tools

Python tools for RT-Thread real-time operating system

installation :
```
git clone https://github.com/tonybounty/rtthread_tools
pip install ./rtthread_tools/
```

## OTA Firmware Reader

Decipher and decompress OTA Firware .RBL

Usage example :
```python
import rtthread_tools.ota_firmware as ota

plain = None

with open("ota_firmware.rbl", "rb") as r:
  rblfile = ota.Reader(r.read())
  if rblfile.cipher_type == ota.CipherType.AES:
    plain = rblfile.Process(key="0123456789ABCDEF0123456789ABCDEF", iv="0123456789ABCDEF")
  else:
    plain = rblfile.Process()

with open("plain_ota_firmware.bin", "wb") as w:
  w.write(plain)
```
