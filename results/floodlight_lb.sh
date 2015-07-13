#!/bin/sh
curl -X POST -d '{"id":"1","name":"vip1","protocol":"icmp","address":"10.0.0.99","port":"8"}' http://localhost:8080/quantum/v1.0/vips/
curl -X POST -d '{"id":"1","name":"pool1","protocol":"icmp","vip_id":"1"}' http://localhost:8080/quantum/v1.0/pools/
curl -X POST -d '{"id":"1","address":"123.123.2.2","port":"8","pool_id":"1"}' http://localhost:8080/quantum/v1.0/members/
curl -X POST -d '{"id":"2","address":"123.123.2.3","port":"8","pool_id":"1"}' http://localhost:8080/quantum/v1.0/members/

