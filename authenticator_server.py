#!/usr/bin/env python3
import json
import random
import string

import wsgiserver

from saml_config import *
from flask import Flask, url_for, redirect, request, make_response
from flask_saml2.sp import ServiceProvider
from flask_saml2.utils import certificate_from_string, private_key_from_string

class PAMServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for('index', _external=True)

    def get_default_login_return_url(self):
        return url_for('process_auth', _external=True)

def get_random_string(length):
    letters = string.ascii_lowercase + string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

sp = PAMServiceProvider()
app = Flask(__name__)
values = dict()

@app.route('/ready')
def ready():
    return "true"

@app.route('/')
def index():
    return "authentication server"

@app.route('/retrieve')
def retrieve():
    data = request.args

    if (data["secret"] is None or str(data["secret"]) != SECRET):
        #bad secret
        return json.dumps({'error': "bad secret"}), 401

    token = get_random_string(32)
    if (token in values.keys()):
        #generate another
        return retrieve()
    values[token] = {'proved':False,'user':""}
    return json.dumps({'token': token}), 200

@app.route('/get')
def get():
    data = request.args

    if (data["secret"] is None or str(data["secret"]) != SECRET):
        #bad secret
        return json.dumps({'error': "bad secret"}), 401

    if (data["token"] is not None and len(data["token"]) == 32):
        # valid token
        token = data["token"]
        if (token in values.keys()):
            # valid
            output = json.dumps(values[token],sort_keys=True)
            if values[token]["proved"]:
                values.pop(token)
            return output, 200
        else:
            return json.dumps({'error': "bad token"}), 404
    else:
        return json.dumps({'error': "bad token format"}), 400

@app.route('/prove')
def prove():
    data = request.args
    if (data["token"] is not None and len(data["token"]) == 32):
        #valid token
        token = data["token"]
        if (token in values.keys()):
            #valid
            tokenobj = values[token]
            if (not tokenobj["proved"]):
                #unproved
                resp = redirect(url_for('flask_saml2_sp.login'))
                resp.set_cookie('token', token)
                return resp
            else:
                return "This token has already been proven.", 200
        else:
            return "bad token value", 404
    else:
        return "bad token value format", 400

@app.route('/auth_action')
def process_auth():
    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()

        message = f'''
        <p>Your identity has been proved as <strong>{auth_data.nameid}</strong>.
        '''

        token = request.cookies.get('token')
        if (token in values.keys()):
            values[token] = {'proved':True,'user':auth_data.nameid}

        logout_url = url_for('flask_saml2_sp.logout')
        logout = f'<form action="{logout_url}" method="POST"><input type="submit" value="Log out"></form>'

        return message + logout
    else:
        #logged out page, redirect to idp
        login_url = url_for('flask_saml2_sp.login')
        return redirect(login_url)

app.debug = False
app.secret_key = "debuguseonly"
app.config['SERVER_NAME'] = HTTP_HOSTNAME + ":" + str(HTTP_PORT)
app.config['SAML2_SP'] = {
    'certificate': certificate_from_string(SP_CERTIFICATE),
    'private_key': private_key_from_string(SP_CERTIFICATE_KEY),
}

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'flask_saml2.sp.idphandler.IdPHandler',
        'OPTIONS': {
            'display_name': IDP_DISPLAY_NAME,
            'entity_id': IDP_ENTITY_ID,
            'sso_url': IDP_SSO_URL,
            'slo_url': IDP_SLO_URL,
            'certificate': certificate_from_string(IDP_CERTIFICATE),
        },
    },
]

app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')

server = wsgiserver.WSGIServer(app, host=HTTP_BIND_ADDRESS, port=HTTP_PORT)
server.start()