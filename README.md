# ipvstls  

## Introduction  
A Lvs module (Run in kernel 3.10/Centos 7).  
It's a simple TLS fw that can block specified TLS session.
Supported by tlsparser.
Ipvstls module now listens 443 by default, you can modify port in source code.
Ipvstls module now blocks the TLS session whose server name in ClientHello contains "google", you can add your code into source code.  
  

## Usage  
### Ipvsadm  
Add virtual server and realserver by `ipvsadm` which is listening the same port as ipvstls.  

For example:  
`sudo ipvsadm -A -t $YOURVIP:443 -s rr`  
`sudo ipvsadm -a -t $YOURVIP:443 -r $YOURRSIP:443 -m`  
  
Now you need to guarantee your virtual server is valid. Do `curl https://$YOURVIP:443/ -ik` to check.

### install ipvstls  
`git clone git@github.com:mrpre/ipvstls.git`  
`cd ipvstls`  
`git clone git@github.com:mrpre/tlsparser.git`  
`make`  
`sudo insmod ./tlsparser/tlspaser.ko;sudo insmod ./ipvstls/ip_vs_tls.ko`
