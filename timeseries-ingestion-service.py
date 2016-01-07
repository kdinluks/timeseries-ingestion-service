from flask import Flask, abort, request, url_for, redirect
from uuid import uuid4
from werkzeug import secure_filename
import urllib
import requests
import requests.auth
import os
import json
import redis
import pandas
import ingest

app = Flask(__name__)

port = int(os.getenv("VCAP_APP_PORT"))
appEnv = json.loads(os.getenv("VCAP_APPLICATION"))
appSvc = json.loads(os.getenv("VCAP_SERVICES"))

BASE_URI = "http://" + appEnv['application_uris'][0]
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TS_WSS = appSvc['predix-timeseries'][0]['credentials']['ingest']['uri']
TS_ZONE = appSvc['predix-timeseries'][0]['credentials']['ingest']['zone-http-header-value']
UAA_URI = appSvc['predix-uaa'][0]['credentials']['uri']
ALLOWED_EXTENSIONS = set(['csv'])
UPLOAD_FOLDER = '/temp'
APPLICATION_NAME = 'timeseries-ingestion-service'

DISK_SPACE = int(appEnv['limits']['disk'])

app.config['MAX_CONTENT_LENGTH'] = (DISK_SPACE - 256) * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.before_request
def before_request():
  print request.headers
  if 'Authorization' in request.headers.keys():
    if not authorized(request.headers['Authorization'][7:]):
      abort(401)
  else:
    abort(401)

@app.route('/')
def homepage():
    return '''
    <!doctype html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
        <title>Timeseries Ingestion Service</title>
      </head>
      <body>
        <h1>Timeseries Ingestion Service</h1>
        <p>You've reached the Timeseries Ingestion Service</p>
        <br>
        <p>To ingest timeseries data, send a post request to /upload with the following params:</p>
        <ul>
          <li>file(s) - the CSV file to be ingested.</li>
          <li>metername - the metername where the data will be saved.</li>
          <li>delimiter - the delimiter char used in the csv file.</li>
          <li>timestamp - the timestamp format used in the csv file. <a href="https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior">(Help)</a></li>
          <li>packetsize - the size of the packets to be sent. Maxium is 5000.</li>
          <li>equipment_index - the equipment name row index in the csv file.</li>
          <li>tagname_index- the source tag name row index in the csv file.</li>
          <li>timestamp_index - the timestamp row index in the csv file.</li>
          <li>value_index - the value row index in the csv file.</li>
          <li>metername_index - the meter name row index in the csv file.</li>
          <li>concat - the char to used for concatenating the equipment name and tag name.</li>
        </ul>
        <p>Note that all fields are required, but you can use metername and metername_index interchangeably.
        If metername_index is present it's going to used even if metername is also present.</p>
      </body>
    </html>
    '''

@app.route('/upload', methods=['POST'])
def upload_file():
  i = 0
  for key in request.files:
    file = request.files[key]
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        ingestFile(file, request.headers['Authorization'][7:], request.form)
        i+=1
    else:
      print(filename + ' not ingested. File type not allowed.')

  return 'All files processed. %i files ingested.' % i, 200

@app.errorhandler(401)
def unauthorized(error):
    return '''
    <!doctype html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
        <title>401 - Unauthorized</title>
      </head>
      <body>
        <h1>Unauthorized</h1>
        <p>The credentials provided don't give you access to this application.</p>
        <p>Verify the credentials and try again.</p>
      </body>
    </html>
    ''', 401

@app.errorhandler(415)
def unauthorized(error):
    return '''
    <!doctype html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
        <title>415 - Wrong File Type</title>
      </head>
      <body>
        <h1>File type not allowed</h1>
        <p>The file uploaded is not allowed.</p>
      </body>
    </html>
    ''', 415

@app.errorhandler(400)
def unauthorized(error):
    return '''
    <!doctype html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
        <title>400 - File not found</title>
      </head>
      <body>
        <h1>File not found</h1>
        <p>File file not found in the request</p>
        <p>Make sure to send a file named file in the request.</p>
      </body>
    </html>
    ''', 400

def allowed_file(filename):
  return '.' in filename and \
         filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def authorized(token):
  client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
  post_data = {"token": token}
  response = requests.post(UAA_URI + "/check_token",
                           auth=client_auth,
                           data=post_data)
  if response.status_code != 200:
    return False
  check_token = response.json()
  aud = check_token['aud']
  if APPLICATION_NAME in aud:
    return True
  return False

def ingestFile(file, token, config):
  delimiter = config["delimiter"].encode('ascii', 'ignore')
  timestamp = config["timestamp"].encode('ascii', 'ignore')
  dpsize = int(config["packetsize"])
  eni = int(config["equipment_index"])
  tni = int(config["tagname_index"])
  tsi = int(config["timestamp_index"])
  vi = int(config["value_index"])
  concat = config["concat"].encode('ascii', 'ignore')

  if 'metername' not in config.keys() and 'metername_index' not in config.keys():
    abort(400)

  if 'metername' in config.keys():
    metername = config["metername"].encode('ascii', 'ignore')

  if 'metername_index' in config.keys():
    metername = int(config["metername_index"])

  if dpsize > 5000:
    dpsize = 5000

  ingest.PAYLOADS = []
  ingest.PAYLOADS = ingest.prepareData(ingest.PAYLOADS, delimiter, timestamp, dpsize, eni, tni, tsi, vi, concat, metername, file)
  ingest.openWSS(token, TS_WSS, TS_ZONE, BASE_URI)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=port)