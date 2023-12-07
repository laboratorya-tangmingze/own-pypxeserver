# own-socket

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

## DOT

```plain
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| bootp client         bootp server |
|                                   |
| dhcp discover  ->                 |
| boot request                      |
| option 53                         |
| option 55                         |
| option 57                         |
| option 60                         |
| option 93                         |
| option 94                         |
| option 97                         |
|                         broadcast |
| packet         to         port 67 |
|                                   |
|                <-                 |
|                        boot reply |
|                            yiaddr |
|                            siaddr |
|                             sname |
|                              file |
|                          option 1 |
|                          option 3 |
|                          option 6 |
|                         option 13 |
|                         option 54 |
| broadcast                         |
| port 68        to          packet |
|                                   |
|                <-      dhcp offer |
|                        boot reply |
|                            yiaddr |
|                            siaddr |
|                             sname |
|                              file |
|                          option 1 |
|                          option 3 |
|                          option 6 |
|                         option 13 |
|                        +option 53 |
|                         option 54 |
| broadcast                         |
| port 68        to          packet |
|                                   |
| dhcp request   ->                 |
| boot request                      |
| +option 50                        |
| +option 53                        |
| +option 54                        |
| option 55                         |
| option 57                         |
| option 60                         |
| option 93                         |
| option 94                         |
| option 97                         |
|                         broadcast |
| packet         to         port 67 |
|                                   |
|                <-        dhcp ack |
|                        boot reply |
|                          option 1 |
|                          option 3 |
|                          option 6 |
|                        +option 51 |
|                        +option 53 |
|                         option 54 |
| broadcast                         |
| port 68        to          packet |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```