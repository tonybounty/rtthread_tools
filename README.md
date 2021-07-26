# rtthread-tools

Python tools for RT-Thread real-time operating system

install :
```
git clone https://github.com/tonybounty/rtthread_tools
pip install ./rtthread_tools/
```

## OTA Firmware Reader

Decipher and decompress OTA Firmware .RBL

Usage example :
```python
import rtthread_tools.ota_firmware as ota

with open("ota_firmware.rbl", "rb") as r, open("plain_firmware.bin", "wb") as w:
  rblfile = ota.Reader(r.read())
  if rblfile.cipher_type == ota.CipherType.AES:
    w.write(rblfile.Process(key="0123456789ABCDEF0123456789ABCDEF", iv="0123456789ABCDEF"))
  else:
    w.write(rblfile.Process())

```

_QuickLZ and FastLZ compression are currently not supported_
