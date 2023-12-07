# own-pypxe

## DOT

```plain
PS C:\Users\Administrator\Downloads\own-socket> # Install [2021.05 python-3.8.10-amd64 | Huaweicloud](https://repo.huaweicloud.com/python/3.8.10/python-3.8.10-amd64.exe)
PS C:\Users\Administrator\Downloads\own-socket>
PS C:\Users\Administrator\Downloads\own-socket> # Install package to dhcppython
PS C:\Users\Administrator\Downloads\own-socket> pip install -i https://pypi.tuna.tsinghua.edu.cn/simple dhcppython tftpy
PS C:\Users\Administrator\Downloads\own-socket>
PS C:\Users\Administrator\Downloads\own-socket> # Start server.py
PS C:\Users\Administrator\Downloads\own-socket> Remove-Item .\*.log ; python .\server.py
```

## Test

```plain
- load ipxe-x86_64.efi yes
  + load boot.ipxe no
```

## Log

```plain
PS C:\Users\Administrator\Downloads\own-pypxe> Remove-Item .\*.log ; python .\server.py
2023-12-07 16:52:24.032 udp_server PATH C:\Users\Administrator\Downloads\own-pypxe\files
2023-12-07 16:52:24.033 DHCPc (68) 0.0.0.0 started...
2023-12-07 16:52:24.034 DHCPd (67) 0.0.0.0 started...
2023-12-07 16:52:24.034 PorxyDHCPd (4011) 192.168.0.17 started...
2023-12-07 16:52:24.034 tftpy (69) 0.0.0.0 started...
2023-12-07 16:52:24.035 HTTPd (80) 0.0.0.0 started...
2023-12-07 16:52:24.049 tftpy.TftpServer Server requested on ip 0.0.0.0, port 69
2023-12-07 16:52:24.049 tftpy.TftpServer Starting receive loop...
2023-12-07 16:52:27.357 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:00, XID 2829844731
2023-12-07 16:52:27.358 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:01, XID 2829844987
2023-12-07 16:52:27.358 DHCPd (67) DHCPDISCOVER discarded, MAC 00:73:88:1C:DE:02, XID 2484339195
2023-12-07 16:52:37.357 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:00, XID 2829844731
2023-12-07 16:52:37.357 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:01, XID 2829844987
2023-12-07 16:52:37.358 DHCPd (67) DHCPDISCOVER discarded, MAC 00:73:88:1C:DE:02, XID 2484339195
2023-12-07 16:52:39.402 DHCPd (67) DHCPDISCOVER received, MAC 7C:10:C9:1C:79:F7, XID 3611411943
2023-12-07 16:52:39.403 DHCPd (67) msg is b'\x01\x01\x06\x00\xd7A\xc5\xe7\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x019\x02\x05\xc07#\x01\x02\x03\x04\x05\x06\x0c\r\x0f\x11\x12\x16\x17\x1c()*+236:;<BCa\x80\x81\x82\x83\x84\x85\x86\x87a\x11\x00\xd9\x82)\xfdF\xf8$\xd6\xed\xa5|\x10\xc9\x1cy\xf7^\x03\x01\x03\x10]\x02\x00\x07< PXEClient:Arch:00007:UNDI:003016\xff'
2023-12-07 16:52:39.403 DHCPc (68) discovering for another DHCPd on LAN
2023-12-07 16:52:39.403 DHCPc (68) another DHCPd detected on your LAN @ 192.168.0.233
2023-12-07 16:52:39.404 DHCPc (68) None received, MAC 7C:10:C9:1C:79:F7, XID 3611411943
2023-12-07 16:52:39.404 DHCPc (68) msg is b'\x02\x01\x06\x00\xd7A\xc5\xe7\x00\x00\x80\x00\x00\x00\x00\x00\xc0\xa8\x00\x12\xc0\xa8\x00\xe9\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Server233\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BootSelector.efi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc\x01\x04\xff\xff\xff\x00\x03\x04\xc0\xa8\x00\xfb\x06\x08\xcae\xac#\x00\x00\x00\x00\r\x02\x00K6\x04\xc0\xa8\x00\xe9\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
2023-12-07 16:52:39.404 DHCPd (67) DHCPOFFER sent, 255.255.255.255:68, XID 3611411943
2023-12-07 16:52:39.405 DHCPd (67) offer_packet is b'\x02\x01\x06\x00\xd7A\xc5\xe7\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x11\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y017\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ipxe-x86_64.efi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x02\r\x02\x07\xa86\x04\xc0\xa8\x00\x11<\tPXEClientB\x0c192.168.0.17\xff'
2023-12-07 16:52:39.406 DHCPc (68) another DHCPd detected on your LAN @ 192.168.0.17
2023-12-07 16:52:39.406 DHCPc (68) DHCPOFFER received, MAC 7C:10:C9:1C:79:F7, XID 3611411943
2023-12-07 16:52:39.407 DHCPc (68) msg is b'\x02\x01\x06\x00\xd7A\xc5\xe7\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x11\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y017\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ipxe-x86_64.efi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x02\r\x02\x07\xa86\x04\xc0\xa8\x00\x11<\tPXEClientB\x0c192.168.0.17\xff'
2023-12-07 16:52:39.421 DHCPc (68) another DHCPd detected on your LAN @ 172.16.1.251
2023-12-07 16:52:39.421 DHCPc (68) DHCPOFFER received, MAC 7C:10:C9:1C:79:F7, XID 3611411943
2023-12-07 16:52:39.421 DHCPc (68) msg is b'\x02\x01\x06\x00\xd7A\xc5\xe7\x00\x00\x80\x00\x00\x00\x00\x00\xac\x10\x02?\x00\x00\x00\x00\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x026\x04\xac\x10\x01\xfb3\x04\x00\x00\x0e\x10\x01\x04\xff\xff\xf8\x00\x03\x04\xac\x10\x01\xfb\x06\x08\xcae\xac#\xac\x10\x01\xfb+\x08\x80\x00\x00\x04\xac\x10\x01\xfb\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
2023-12-07 16:52:42.593 DHCPd (67) DHCPREQUEST discarded, MAC 7C:10:C9:1C:79:F7, XID 3611411943
2023-12-07 16:52:42.594 PorxyDHCPd (4011) DHCPREQUEST received, MAC 7C:10:C9:1C:79:F7, XID 2984271434
2023-12-07 16:52:42.594 PorxyDHCPd (4011) msg is b'\x01\x01\x06\x00\xb1\xe0^J\x00\x00\x00\x00\xc0\xa8\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x037#\x01\x02\x03\x04\x05\x06\x0c\r\x0f\x11\x12\x16\x17\x1c()*+236:;<BCa\x80\x81\x82\x83\x84\x85\x86\x879\x02\x05\xc0< PXEClient:Arch:00007:UNDI:003016]\x02\x00\x07^\x03\x01\x03\x10a\x11\x00\xd9\x82)\xfdF\xf8$\xd6\xed\xa5|\x10\xc9\x1cy\xf7\xff'
2023-12-07 16:52:42.595 PorxyDHCPd (4011) DHCPACK sent, 0.0.0.0:4011, XID 2984271434
2023-12-07 16:52:42.595 PorxyDHCPd (4011) ack_packet is b'\x02\x01\x06\x00\xb1\xe0^J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x11\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y017\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ipxe-x86_64.efi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x05\r\x02\x07\xa86\x04\xc0\xa8\x00\x11<\tPXEClientB\x0c192.168.0.17a\x11\x00\xd9\x82)\xfdF\xf8$\xd6\xed\xa5|\x10\xc9\x1cy\xf7\xff'
2023-12-07 16:52:42.813 DHCPd (67) DHCPDISCOVER received, MAC FC:34:97:BA:F1:81, XID 2338013992
2023-12-07 16:52:42.813 DHCPd (67) msg is b'\x01\x01\x06\x00\x8b[C(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc4\x97\xba\xf1\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x017\x1c\x01\x02\x03\x04\x05\x06\x0b\x0c\r\x0f\x10\x11\x12\x16\x17\x1c()*+236:;<BC9\x02\x04\xeca\x11\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff]\x02\x00\x00^\x03\x01\x02\x01<\tPXEClient\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
2023-12-07 16:52:42.815 DHCPd (67) DHCPOFFER sent, 255.255.255.255:68, XID 2338013992
2023-12-07 16:52:42.815 DHCPd (67) offer_packet is b'\x02\x01\x06\x00\x8b[C(\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x11\x00\x00\x00\x00\xfc4\x97\xba\xf1\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y017\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ipxe-x86_64.efi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x02\r\x02\x07\xa86\x04\xc0\xa8\x00\x11<\tPXEClientB\x0c192.168.0.17\xff'
2023-12-07 16:52:43.652 tftpy.TftpStates Setting tidport to 1949
2023-12-07 16:52:43.652 tftpy.TftpStates Dropping unsupported option 'windowsize'
2023-12-07 16:52:43.654 tftpy.TftpStates requested file is in the server root - good
2023-12-07 16:52:43.654 tftpy.TftpStates Opening file C:\Users\Administrator\Downloads\own-pypxe\files\ipxe-x86_64.efi for reading
2023-12-07 16:52:43.655 tftpy.TftpServer Currently handling these sessions:
2023-12-07 16:52:43.655 tftpy.TftpServer     192.168.0.18:1949 <tftpy.TftpStates.TftpStateExpectACK object at 0x0000019A1AFDACD0>
2023-12-07 16:52:43.858 tftpy.TftpStates Reached EOF on file ipxe-x86_64.efi
2023-12-07 16:52:43.859 tftpy.TftpStates Received ACK to final DAT, we're done.
2023-12-07 16:52:43.859 tftpy.TftpServer Successful transfer.
2023-12-07 16:52:43.860 tftpy.TftpServer
2023-12-07 16:52:43.860 tftpy.TftpServer Session 192.168.0.18:1949 complete
2023-12-07 16:52:43.860 tftpy.TftpServer Transferred 1003136 bytes in 0.21 seconds
2023-12-07 16:52:43.860 tftpy.TftpServer Average rate: 37789.91 kbps
2023-12-07 16:52:43.861 tftpy.TftpServer 0.00 bytes in resent data
2023-12-07 16:52:43.861 tftpy.TftpServer 0 duplicate packets
2023-12-07 16:52:47.357 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:00, XID 2829844731
2023-12-07 16:52:47.358 DHCPd (67) DHCPDISCOVER discarded, MAC 00:A1:00:09:45:01, XID 2829844987
2023-12-07 16:52:47.359 DHCPd (67) DHCPDISCOVER discarded, MAC 00:73:88:1C:DE:02, XID 2484339195
2023-12-07 16:52:48.863 DHCPd (67) DHCPDISCOVER received, MAC 7C:10:C9:1C:79:F7, XID 2866058274
2023-12-07 16:52:48.865 DHCPd (67) msg is b'\x01\x01\x06\x00\xaa\xd4\x94"\x00\x08\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x019\x02\x05\xc0]\x02\x00\x07^\x03\x01\x03\n< PXEClient:Arch:00007:UNDI:003010M\x04iPXE7\x17\x01\x03\x06\x07\x0c\x0f\x11\x1a+<BCw\x80\x81\x82\x83\x84\x85\x86\x87\xaf\xcb\xaf$\xb1\x05\x01\x80\x86\x15\xfa\xeb\x03\x01\x15\x01\x17\x01\x01$\x01\x01\x13\x01\x01\x11\x01\x01\'\x01\x01\x15\x01\x01\x1b\x01\x01\x12\x01\x01=\x07\x01|\x10\xc9\x1cy\xf7a\x11\x00\xd9\x82)\xfdF\xf8$\xd6\xed\xa5|\x10\xc9\x1cy\xf7\xff'
2023-12-07 16:52:48.865 DHCPd (67) iPXE user-class detected
2023-12-07 16:52:48.866 DHCPd (67) DHCPOFFER sent, 255.255.255.255:68, XID 2866058274
2023-12-07 16:52:48.866 DHCPd (67) offer_packet is b'\x02\x01\x06\x00\xaa\xd4\x94"\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x11\x00\x00\x00\x00|\x10\xc9\x1cy\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Y017\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00boot.ipxe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x02\r\x02\x00\x006\x04\xc0\xa8\x00\x11<\tPXEClientB\x0c192.168.0.17\xff'
2023-12-07 16:52:48.867 DHCPd (67) DHCPREQUEST discarded, MAC 7C:10:C9:1C:79:F7, XID 2866058274
2023-12-07 16:52:53.211 DHCPc (68) stopped...
2023-12-07 16:52:53.212 DHCPd (67) stopped...
2023-12-07 16:52:53.212 PorxyDHCPd (4011) stopped...
2023-12-07 16:52:53.215 tftpy (69) stopped...
2023-12-07 16:52:53.216 HTTPd (80) stopped...
```