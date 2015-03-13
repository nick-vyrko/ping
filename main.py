import sys
import os
import socket
import struct
import time
import consts
import select

def ping(timeout=2, count=4):
    if len(sys.argv) < 2:
        return
    if len(sys.argv) > 2:
        if sys.argv[2]:
            consts.PACKET_SIZE = int(sys.argv[2])
        if sys.argv[3]:
            timeout = int(sys.argv[3])
        if sys.argv[4]:
            count = int(sys.argv[4])
    ip = sys.argv[1]


    for i in xrange(int(count)):
        print "ping {0}...".format(ip)
        try:
            delay = just_do_it(ip, timeout)
        except socket.error:
            print "failed"
            break

        if delay == None:
            print "failed, (timeout within {0} seconds)".format(timeout)
        else:
            delay *= 1000
            print "get ping in %0.2f ms" % delay


def just_do_it(ip, timeout):
    try:
       sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error:
        print "ERROR"
        return

    my_ID = os.getpid()

    send_package(sock, ip, my_ID)
    delay = recieve_package(sock, my_ID, timeout)

    sock.close()
    return delay

def send_package(sock, ip, my_id):
    dest_addr = socket.gethostbyname(ip)
    checksum = 0

    header = struct.pack("bbHHh", consts.ICMP_ECHO_REQUEST, 0, checksum, my_id, 1)

    data = (consts.PACKET_SIZE - struct.calcsize("d")) * "Z"
    data = struct.pack("d", time.time()) + data

    checksum = check_sum(header + data)
    header = struct.pack("bbHHh", consts.ICMP_ECHO_REQUEST, 0, socket.htons(checksum), my_id, 1)
    packet = header + data
    sock.sendto(packet, (dest_addr, 1))


def recieve_package(sock, id, timeout):
    timeleft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([sock], [], [], float(timeleft))
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:
            return

        timeRecieved = time.time()
        recPacket, addr = sock.recvfrom(consts.BUF_SIZE)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
        if packetID == id:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28+bytesInDouble])[0]
            return timeRecieved - timeSent

        timeleft -= howLongInSelect
        if timeleft <= 0:
            return


def check_sum(source_str):
    sum = 0
    countTo = (len(source_str)/2)*2
    count = 0
    while count < countTo:
        thisVal = ord(source_str[count+1])*256 + ord(source_str[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(source_str):
        sum = sum + ord(source_str[len(source_str)-1])
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

if __name__ == "__main__":
    ping()