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

app = Flask(__name__)
@app.before_request
def before_request():
  print request.headers
  if 'Authorization' in request.headers.keys():
    if not authorized(request.headers['Authorization'][7:]):
      abort(401)
  else:
    abort(401)
  # if not authenticated() and request.endpoint != 'callback':
  #   return redirect(make_authorization_url())

port = int(os.getenv("VCAP_APP_PORT"))
appEnv = json.loads(os.getenv("VCAP_APPLICATION"))
appSvc = json.loads(os.getenv("VCAP_SERVICES"))

BASE_URI = "http://" + appEnv['application_uris'][0]
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
UAA_URI = appSvc['predix-uaa'][0]['credentials']['uri']
ALLOWED_EXTENSIONS = set(['csv'])
UPLOAD_FOLDER = '/temp'
APPLICATION_NAME = 'timeseries-ingestion-service'

REDIS_CONFIG = appSvc['redis-1'][0]
REDIS_INSTANCE = (redis.Redis(host=REDIS_CONFIG['credentials']['host'],
                              password=REDIS_CONFIG['credentials']['password'], 
                              port=REDIS_CONFIG['credentials']['port']))

DISK_SPACE = int(appEnv['limits']['disk'])

app.config['MAX_CONTENT_LENGTH'] = (DISK_SPACE - 256) * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def homepage():
  # text = '<a href="%s">Authenticate with Predix UAA</a>'
  # return text % make_authorization_url()
  return redirect(url_for('upload_file'))

@app.route('/callback')
def callback():
  error = request.args.get('error', '')
  if error:
      return "Error: " + error
  state = request.args.get('state', '')
  if not is_valid_state(state):
      # Uh-oh, this request wasn't started by us!
      abort(403)
  code = request.args.get('code')
  return get_token(code)

@app.route('/token')
def token():
  return "Here's the token: %s" % json.loads(REDIS_INSTANCE.get('getUaaToken'))['access_token']

@app.route('/deltoken')
def del_token():
  REDIS_INSTANCE.delete('getUaaToken')
  return "token deleted"

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
  if request.method == 'POST':
      file = request.files['file']
      if file and allowed_file(file.filename):
          filename = secure_filename(file.filename)
          df = pandas.read_csv(file, sep=';', header=None)
          df.sort_values(by=3, ascending=True, inplace=True)
          print df
          return filename + ' uploaded.'
      else:
        return 'No file found or file type not allowed.', 415

  return '''
  <!doctype html>
  <html>
    <head>
      <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
      <title>Ingest new File</title>
    </head>
    <body>
      <h1>Ingest new File</h1>
      <form action="" method=post enctype=multipart/form-data>
        <p><input type=file name=file>
           <input type=submit value=Upload>
      </form>
      <small><a href="%s">Show UAA Token</a></small>
      <small><a href="%s">Logout</a></small>
    </body>
  </html>
  ''' % (url_for('token'), url_for('logout'))

@app.route('/logout')
def logout():
  REDIRECT_URI = BASE_URI + url_for('homepage')
  params = { "redirect": REDIRECT_URI }
  url = UAA_URI + "/logout?" + urllib.urlencode(params)
  dt = del_token()
  return redirect(url)

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

def allowed_file(filename):
  return '.' in filename and \
         filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def authenticated():
  token = REDIS_INSTANCE.get('getUaaToken')
  if token != None and token != '':
    token = json.loads(token)
    return authorized(token['access_token'])
  return False

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

def make_authorization_url():
  # Generate a random string for the state parameter
  # Save it for use later to prevent xsrf attacks
  state = str(uuid4())
  save_created_state(state)
  REDIRECT_URI = BASE_URI + url_for('callback')
  params = {"client_id": CLIENT_ID,
            "response_type": "code",
            "state": state,
            "redirect_uri": REDIRECT_URI
            }
  url = UAA_URI + '/oauth/' + "authorize?" + urllib.urlencode(params)
  return url

# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache,
# or perhaps cryptographically sign them and verify upon retrieval.
def save_created_state(state):
  REDIS_INSTANCE.set('getUaaTokenState',state)

def is_valid_state(state):
  savedState = REDIS_INSTANCE.get('getUaaTokenState')
  if (savedState == state):
    return True
  else:
    return False

def get_token(code):
  client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
  REDIRECT_URI = BASE_URI + url_for('callback')
  post_data = {"grant_type": "authorization_code",
               "code": code,
               "redirect_uri": REDIRECT_URI}
  response = requests.post(UAA_URI + '/oauth/' + "token",
                           auth=client_auth,
                           data=post_data)
  token_json = response.json()
  if not authorized(token_json['access_token']):
    abort(401)
  REDIS_INSTANCE.setex('getUaaToken', json.dumps(token_json), int(token_json['expires_in']))
  return redirect(url_for('homepage'))

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=port)