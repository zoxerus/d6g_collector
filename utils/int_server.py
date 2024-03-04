#!/usr/bin/env python3
import sys, time
import argparse
import os

from scapy.all import sniff
from scapy.all import Packet
from scapy.all import UDP
from scapy.all import XByteField, ShortField, BitField
from scapy.all import bind_layers

import influxdb_client, os, time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
# import sswitch_CLI_2

parser = argparse.ArgumentParser(description='receive telmetry reports and store them in influxdb')
parser.add_argument('-if','--interface', help='interface to receive on',
                    type=str, action="store", default='veth0')
parser.add_argument('-p','--port', help='port to listen to',
                    type=int, action="store", default='35000')
args = parser.parse_args()


# a class for defining the INT header.
class INT_MD(Packet):
    name = 'INT_MD'
    fields_desc = [
        ShortField(name='node_id', default=0),
        ShortField(name='flow_id', default=0),
        BitField(name='delay', default=0, size=64)
    ]

# need to generate a token for influx_db and save it as a global system variable
token = os.environ.get("INFLUXDB_TOKEN")
# organisation and buckt need to be setup from the InfluxDB interface
org = "SSSUP"
url = "http://localhost:8086"
bucket="Juniper_INT"

# configure the api to write data into the database.
write_client = influxdb_client.InfluxDBClient(url=url, token=token, org=org)
write_api = write_client.write_api(write_options=SYNCHRONOUS)

# a callback function for handling received packets.
def handle_pkt(pkt):
    if UDP in pkt and pkt[UDP].dport == args.port:

        # get int data from received packet.
        data = pkt[INT_MD]
        
        # print the int data
        data.show2()
        
        # create a data point to write into the time series.
        point1 = (
            Point('INT')
                .field('delay', data.delay )
                .field('node_id', data.node_id)
                .field('flow_id', data.flow_id)
                )
        
        write_api.write(bucket=bucket, org=org, record=point1)

    sys.stdout.flush()


def main():
    # need to tell scapy where the INT header is located in the packet.
    # in this case it's after UDP header when the UDP dstPort is equal to
    # the set value in the bind_layers function 
    # (in this case the default port is 3500)
    bind_layers(UDP, INT_MD, dport=args.port)  
    
    iface = args.interface
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
