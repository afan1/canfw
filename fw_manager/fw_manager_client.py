#
# Simple CANFW Manager
#
import sys
import time
import threading
import os
import base64
import can
import websocket
import json
try:
    import thread
except ImportError:  #TODO use Threading instead of _thread in python3
    import _thread as thread

#For testing purposes only
DEBUG = True

service_name = "canfw/package_acceptor"
host="ws://localhost:8808"
counter = 0
SLEEP_TIME = 0.5
ARBITRATION = 0x7fe

def package_acceptor(package, payload, num_prio):

    can_conn_dead = True

    if DEBUG:
        print('package_acceptor called')

    while can_conn_dead:
        try:
            can_interface='can0'
            bus = can.interface.Bus(can_interface, bustype='socketcan_native')
            can_conn_dead = False
        except:
            if DEBUG:
                print("No can bus active. Wait and retry: ")
            time.sleep(2.0)

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

        try:
            #PREP_RULE1
            if DEBUG:
                print('rule1')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 1, int(MASK[0:2],16), int(MASK[2:4],16), int(MASK[4:6],16),
                                    int(MASK[6:8],16), int((IDXFORM+DATAXFORM),16), int(RSVD,16)], extended_id=False))
            time.sleep(SLEEP_TIME)

        except:
            print('rule1 failed')
        try:
            #PREP_RULE2
            if DEBUG:
                print('rule2')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 2, int(FILTER[0:2],16), int(FILTER[2:4],16), int(FILTER[4:6],16),
                                    int(FILTER[6:8],16), int(DATAOPERAND1[0:2],16), int(DATAOPERAND1[2:4],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule2 failed')

        try:
            #PREP_RULE3
            if DEBUG:
                print('rule3')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 3, int(DATAOPERAND2[0:2],16), int(DATAOPERAND2[2:4],16), int(DATAOPERAND2[4:6],16),
                                    int(DATAOPERAND2[6:8],16), int(DATAOPERAND2[8:10],16), int(DATAOPERAND2[10:12],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule3 failed')

        try:
            #PREP_RULE4
            if DEBUG:
                print('rule4')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 4, int(IDOPERAND[0:2],16), int(IDOPERAND[2:4],16), int(IDOPERAND[4:6],16),
                                    int(IDOPERAND[6:8],16), int(HMAC1[0:2],16), int(HMAC1[2:4],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule4 failed')

        try:
            #PREP_RULE5
            if DEBUG:
                print('rule5')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 5, int(HMAC2[0:2],16), int(HMAC2[2:4],16), int(HMAC2[4:6],16),
                                    int(HMAC2[6:8],16), int(HMAC2[8:10],16), int(HMAC2[10:12],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule5 failed')

        try:
            #PREP_RULE6
            if DEBUG:
                print('rule6')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 6, int(HMAC3[0:2],16), int(HMAC3[2:4],16), int(HMAC3[4:6],16),
                                    int(HMAC3[6:8],16), int(HMAC3[8:10],16), int(HMAC3[10:12],16)], extended_id=False))

            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule6 failed')

        try:
            #PREP_RULE7
            if DEBUG:
                print('rule7')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 7, int(HMAC4[0:2],16), int(HMAC4[2:4],16), int(HMAC4[4:6],16),
                                    int(HMAC4[6:8],16), int(HMAC4[8:10],16), int(HMAC4[10:12],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule7 failed')
            #PREP_RULE8

        try:
            if DEBUG:
                print('rule8')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 8, int(HMAC5[0:2],16), int(HMAC5[2:4],16), int(HMAC5[4:6],16),
                                    int(HMAC5[6:8],16), int(HMAC5[8:10],16), int(HMAC5[10:12],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule8 failed')

        try:
            #PREP_RULE9
            if DEBUG:
                print('rule9')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 9, int(HMAC6[0:2],16), int(HMAC6[2:4],16), int(HMAC6[4:6],16),
                                    int(HMAC6[6:8],16), int(HMAC6[8:10],16), int(HMAC6[10:12],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print('rule9 failed')

        try:
            #STORE_RULE
            if DEBUG:
                print('rule10')
            bus.send(can.Message(arbitration_id=ARBITRATION, data=[int(PRIO,16), 10, int(SEQUENCE[0:2],16), int(SEQUENCE[2:4],16), int(SEQUENCE[4:6],16),
                                    int(SEQUENCE[6:8],16), int(UNUSED[0:2],16), int(UNUSED[2:4],16)], extended_id=False))
            time.sleep(SLEEP_TIME)
     
        except:
            if DEBUG:
                print ("rule 10 failed Could not send frames successfully")


    return {u'status': 0}

def on_message(ws, message):
    message_dict = json.loads(message)


    if DEBUG:
        print(message)
        if message_dict['method'] == 'message':
            print("###########THIS IS A MESSAGE#############")
            for key, value in message_dict.items():
                print(key, value)
            print("############END OF MESSAGE###############")
##############################################################################################################
##############################################################################################################
########################################Check for the correct parameters######################################
    if message_dict['method'] == 'message':
        try:
            params = message_dict['params']['parameters']
            if DEBUG:
                print(params)
            package_name = params['package']
            str_payload = params['payload']
            number_prios = params['num_prio']
            if DEBUG:
                print('forwarding message payload to package_acceptor')
                print('package_name: ' + package_name)
                print('str_payload: ' + str(str_payload))
                print('number_prios: ' + str(number_prios))
            try:
                package_acceptor(package=package_name, payload=str_payload, num_prio=number_prios)
            except:
                if DEBUG:
                    print('package_acceptor forwarding failed')
        except:
            if DEBUG:
                print('Incorrect Parameters will not forward to package_acceptor')
##############################################################################################################
##############################################################################################################



def on_error(ws, error):
    if DEBUG:
        print(error)


def on_close(ws):
    if DEBUG:
        print("### closed ###")


def on_open(ws):
    def run(*args):
        payload = {}
        payload['json-rpc'] = "2.0"
        payload['id'] = counter
        payload['method'] = "register_service"
        payload['params'] = {"service_name":service_name}
        
        ws.send(json.dumps(payload))

    thread.start_new_thread(run, ())


if __name__ == "__main__":
    websocket.enableTrace(True)

    while True:
        if len(sys.argv) < 2:
            host = "ws://localhost:8808"
        else:
            host = sys.argv[1]
        ws = websocket.WebSocketApp(host,
                                    on_message = on_message,
                                    on_error = on_error,
                                    on_close = on_close)
        ws.on_open = on_open
        if ws.run_forever() is None:
            if DEBUG:
                print('No RVI. Wait and retry.')
                time.sleep(2)
            continue

    try:
        while True:
            time.sleep(1.0)

    except KeyboardInterrupt:
        print('^C received, shutting down server')
