import pandas
import websocket
import thread
import time
import calendar
import sys
import csv
import os
import argparse
import textwrap
import requests
import json
import yaml
import logging
import math
from collections import defaultdict

# Global variables
PAYLOADS = []

def on_message(ws, message):
    if json.JSONDecoder().decode(message)["statusCode"] != 202:
        print("Error sending packet to time-series service")
        print(message)
        #sys.exit(1)
    else:
        print("Packet Sent")

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("--- Socket Closed ---")

def prepareData(payloads, delimiter, timestamp, dpsize, eni, tni, tsi, vi, concat, metername, data):
    df = pandas.read_csv(data, sep=delimiter, header=None)
    if eni == -1:
        df.sort_values(by=[tni], ascending=True, inplace=True)
    else:
        df.sort_values(by=[eni, tni], ascending=True, inplace=True)

    i = 0
    m = 1
    datapoints = []
    meter = ""

    print("Generating packets with " + str(dpsize) + " data points...")

    for index, row in df.iterrows():
        # Create the packets to send it over WS
        # Define the tag name if none exists
        tagname = row[tni]
        
        if eni != -1:
            equipname = row[eni]

        if metername == -1:
            if meter == "":
                meter = equipname + concat + tagname
                print("Meter name: " + meter)

            # If current tag name is different than the tag name from the file, define another tag name
            elif meter != equipname + concat + tagname:
                payloads.append(payload(meter, datapoints, m))
                meter = equipname + concat + tagname
                print("Meter name: " + meter)
                m += 1
                i = 0
                datapoints = []

        else:
            if meter == "":
                if type(metername) is str or type(metername) is unicode:
                    meter = metername
                    print("Meter name: " + meter)
                else:
                    meter = row[metername]
                    print("Meter name: " + meter)

            # If current tag name is different than the tag name from the file, define another tag name
            elif type(metername) is not str:
                if meter != row[metername]:
                    payloads.append(payload(meter, datapoints, m))
                    meter = row[metername]
                    print("Meter name: " + meter)
                    m += 1
                    i = 0
                    datapoints = []
                    
        # Add the last point in the packet and exit the loop
        if i >= dpsize:
            payloads.append(payload(meter, datapoints, m))
            m += 1
            i = 0
            datapoints = []

        # Verifies if the value is a valid number or don't add the point
        try:
            value = float(row[vi])
            if math.isnan(value):
                continue
        except:
            print("Invalid reading: " + row)
            value = 0.0
            i += 1
            continue

        try:
            tstamp = calendar.timegm(time.strptime(row[tsi], timestamp)) * 1000
        except:
            try:
                tstamp = calendar.timegm(time.strptime(row[tsi], timestamp+".%f")) * 1000
            except:
                print("Error converting date " + row[tsi] + " using the provided time stamp " + timestamp)
                print("Terminating...")
                sys.exit(1)

        datapoints.append([tstamp, value])

        i += 1

    # Append last packet to payload list
    if i > 0:
        payloads.append(payload(meter, datapoints, m+1))

    return payloads


def payload(meter, datapoints, m):
    datapointsstr = ""
    for d in datapoints:
        datapointsstr += "[" + str(d[0]) + "," + str(d[1]) + "],"

    datapointsstr = datapointsstr[:-1]

    payload = '''{  
                   "messageId": ''' + str(m) + ''',
                   "body":[  
                      {  
                         "name":"''' + meter + '''",
                         "datapoints": [''' + datapointsstr + '''],
                         "attributes":{  
                         }
                      }
                   ]
                }'''
    return payload

def sendPayload(ws):
    global PAYLOADS
    print("--- Socket Opened ---")
    def run(*args):
        i = 0
        it = len(PAYLOADS)
        for p in PAYLOADS:
            i += 1
            ws.send(p)
            print("Sending packet " + str(i) + " of " + str(it))
            time.sleep(1)

        time.sleep(1)
        ws.close()
        print(str(i) + " packets sent.")
        print("Thread terminating...")

    thread.start_new_thread(run, ())

def openWSS(uaaToken, tsUri, tsZone, origin):
    websocket.enableTrace(False)
    host = tsUri
    headers = {
                'Authorization:bearer ' + uaaToken,
                'Predix-Zone-Id:' + tsZone,
                'Origin:' + origin
    }
    ws = websocket.WebSocketApp(
                                host,
                                header = headers,
                                on_message = on_message,
                                on_error = on_error,
                                on_close = on_close
    )
    ws.on_open = sendPayload
    ws.run_forever()