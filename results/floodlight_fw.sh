#!/bin/sh

# DENY all
curl http://localhost:8080/wm/firewall/module/enable/json
curl -X POST -d '{"src-ip": "123.123.1.2/32", "dst-ip": "123.123.1.2/32", "nw-proto":"ICMP", "action":"DENY"}' http://localhost:8080/wm/firewall/rules/json
curl -X POST -d '{"src-ip": "123.123.2.2/32", "dst-ip": "123.123.2.2/32", "nw-proto":"ICMP", "action":"DENY"}' http://localhost:8080/wm/firewall/rules/json

#curl -X POST -d '{"src-ip": "123.123.1.2/32", "dst-ip": "123.123.1.2/32", "nw-proto":"ICMP", "action":"ALLOW"}' http://localhost:8080/wm/firewall/rules/json
#curl -X POST -d '{"src-ip": "123.123.2.2/32", "dst-ip": "123.123.2.2/32", "nw-proto":"ICMP", "action":"ALLOW"}' http://localhost:8080/wm/firewall/rules/json

