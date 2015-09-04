#
# Simple CANFW Manager
#
import sys
from rvilib import RVI
import jsonrpclib
import time
import threading
import os
import base64
import hashlib
import hmac
import can

#For testing purposes only
DEBUG = True

rvi_canfw_prefix = "jlr.com/backend/canfw"
available_packages = []



def usage():
    print ("Usage:", sys.argv[0], "<rvi_url> <service_id>")
    print ("  <rvi_url>         URL of  Service Edge on a local RVI node")
    print ("The RVI Service Edge URL can be found in")
    print ("[backend,vehicle].config as")
    print ("env -> rvi -> components -> service_edge -> url")
    print ("The Service Edge URL is also logged as a notice when the")
    print ("RVI node is started.")
    sys.exit(255)


def package_acceptor(package, payload, num_prio):

    if DEBUG:
        print ("Recieved rule set:", package)
        print ("Payload is:", payload)
        print ("Number of priorities is:", num_prio)

    for prio in range(num_prio):
        HMAC1 = payload[prio]['hmac_sig'][0:4]
        HMAC2 = payload[prio]['hmac_sig'][4:16]
        HMAC3 = payload[prio]['hmac_sig'][16:28]
        HMAC4 = payload[prio]['hmac_sig'][28:40]
        HMAC5 = payload[prio]['hmac_sig'][40:52]
        HMAC6 = payload[prio]['hmac_sig'][52:64]

        if DEBUG:
            print ("HMAC1:", HMAC1)
            print ("HMAC2:", HMAC2)
            print ("HMAC3:", HMAC3)
            print ("HMAC4:", HMAC4)
            print ("HMAC5:", HMAC5)
            print ("HMAC6:", HMAC6)

        PRIO = payload[prio]['sig_string'][0:2]
        MASK = payload[prio]['sig_string'][2:10]
        IDXFORM = payload[prio]['sig_string'][10:11]
        DATAXFORM = payload[prio]['sig_string'][11:12]
        RSVD = payload[prio]['sig_string'][12:14]
        FILTER = payload[prio]['sig_string'][14:22]
        IDOPERAND = payload[prio]['sig_string'][38:46]
        DATAOPERAND1 = payload[prio]['sig_string'][22:26]
        DATAOPERAND2 = payload[prio]['sig_string'][26:38]
        SEQUENCE = payload[prio]['sig_string'][46:54]
        UNUSED = payload[prio]['sig_string'][54:58]

        if DEBUG:
            print ("PRIO:", PRIO)
            print ("MASK:", MASK)
            print ("IDXFORM:", IDXFORM)
            print ("DATAXFORM:", DATAXFORM)
            print ("RSVD:", RSVD)
            print ("FILTER:", FILTER)
            print ("IDOPERAND:", IDOPERAND)
            print ("DATAOPERAND1:", DATAOPERAND1)
            print ("DATAOPERAND2:", DATAOPERAND2)
            print ("SEQUENCE:", SEQUENCE)
            print ("UNUSED:", UNUSED)

        can_conn_dead = True

        while can_conn_dead:
            try:
                can_interface='can0'
                bus = can.interface.Bus(can_interace, bustype='socketcan_native')
                can_conn_dead = False
            except:
                print("No can bus active. Wait and retry: ")
                time.sleep(2.0)
        try:
            #PREP_RULE1
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 1, int(MASK[0:2]), int(MASK[2:4]), int(MASK[4:6]),
                                    int(MASK[6:8]), int((IDXFORM+DATAXFORM)), int(RSVD)], extended_id=False))

            #PREP_RULE2
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 2, int(FILTER[0:2]), int(FILTER[2:4]), int(FILTER[4:6]),
                                    int(FILTER[6:8]), int(DATAOPERAND1[0:2]), int(DATAOPERAND1[2:4])], extended_id=False))

            #PREP_RULE3
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 3, int(DATAOPERAND2[0:2]), int(DATAOPERAND2[2:4]), int(DATAOPERAND2[4:6]),
                                    int(DATAOPERAND2[6:8]), int(DATAOPERAND2[8:10]), int(DATAOPERAND2[10:12])], extended_id=False))

            #PREP_RULE4
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 4, int(IDOPERAND[0:2]), int(IDOPERAND[2:4]), int(IDOPERAND[4:6]),
                                    int(IDOPERAND[6:8]), int(HMAC1[0:2]), int(HMAC1[2:4])], extended_id=False))

            #PREP_RULE5
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 5, int(HMAC2[0:2]), int(HMAC2[2:4]), int(HMAC2[4:6]),
                                    int(HMAC2[6:8]), int(HMAC2[8:10]), int(HMAC2[10:12])], extended_id=False))

            #PREP_RULE6
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 6, int(HMAC3[0:2]), int(HMAC3[2:4]), int(HMAC3[4:6]),
                                    int(HMAC3[6:8]), int(HMAC3[8:10]), int(HMAC3[10:12])], extended_id=False))

            #PREP_RULE7
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 7, int(HMAC4[0:2]), int(HMAC4[2:4]), int(HMAC4[4:6]),
                                    int(HMAC4[6:8]), int(HMAC4[8:10]), int(HMAC4[10:12])], extended_id=False))

            #PREP_RULE8
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 8, int(HMAC5[0:2]), int(HMAC5[2:4]), int(HMAC5[4:6]),
                                    int(HMAC5[6:8]), int(HMAC5[8:10]), int(HMAC5[10:12])], extended_id=False))

            #PREP_RULE9
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 9, int(HMAC5[0:2]), int(HMAC5[2:4]), int(HMAC5[4:6]),
                                    int(HMAC5[6:8]), int(HMAC5[8:10]), int(HMAC5[10:12])], extended_id=False))

            #STORE_RULE
            bus.send(can.Message(arbitration_id=0x01, data=[int(PRIO), 10, int(SEQUENCE[0:2]), int(SEQUENCE[2:4]), int(SEQUENCE[4:6]),
                                    int(SEQUENCE[6:8]), int(UNUSED[0:2]), int(UNUSED[2:4])], extended_id=False))
        except:
            print ("Could not send frames successfully")


    return {u'status': 0}



#
# Check that we have the correct arguments
#
#if len(sys.argv) != 2:
#    usage()

# Grab the URL to use
#[ progname, rvi_url ] = sys.argv
rvi_url = "http://localhost:8811"

# setup the service names we will register with
# The complete service name will be:
#  jlr.com/vin/1234/hvac/publish
#       - and -
#  jlr.com/vin/1234/hvac/subscribe
#
# Replace 1234 with the VIN number setup in the
# node_service_prefix entry in vehicle.config

# Setup an outbound JSON-RPC connection to the RVI Service Edge.
# Setup a connection to the local RVI node
rvi_server = RVI("http://localhost:8811")
rvi_server.start_serve_thread()


# We may see traffic immediately from the RVI node when
# we register. Let's sleep for a bit to allow the emulator service
# thread to get up to speed.
time.sleep(0.5)

# Repeat registration until we succeeed
rvi_dead = True

while rvi_dead:
    try:
        full_package_acceptor_service_name = rvi_server.register_service("/canfw/package_acceptor", package_acceptor )
        rvi_dead = False
    except:
        print ("No rvi. Wait and retry: ")
        time.sleep(2.0)


print ("FW Manager")
print ("Vehicle RVI node URL:       ", rvi_url)
print ("Full Package Acceptor service name :  ", full_package_acceptor_service_name)


try:
    while True:
        time.sleep(1.0)

except KeyboardInterrupt:
    print('^C received, shutting down server')
    # os.remove(canfw_manager.py)
