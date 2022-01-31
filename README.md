# 🅿🅾🆁🆃🅺🅻🅰🅽🅶

Simple port scanner I made that enumerates from a list of domains and retrieve their IP Address. 
For educational purpose only. Please don't use it on websites you don't own or have permission to do so.  

### Usage:
`python portklang.py domains.txt`

![image](https://user-images.githubusercontent.com/92495243/151784213-56a0e567-c2c6-40e6-a70e-47d8bc88076b.png)

### Settings:
If you wish to change the timeout time you can change from the script, there are Closed Ports and Ports that does not even established and it is set to off by default

#### Uncomment these to enumerate ports 1-1024
`# for x in range(1024):
`#   port_range.append(x+1)

#### Defaul Settings:
`port range = [22, 23, 80, 443, 445, 8080]`
`report_close_ports = False`
`report_unestablished_ports = False`
`timeout = 0.2`
