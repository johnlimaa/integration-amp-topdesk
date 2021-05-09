import requests
import base64
from tinydb import TinyDB, Query
from os import environ
from time import sleep

def encode_64(plain_text):
    text_bytes = plain_text.encode('ascii')
    base64_bytes = base64.b64encode(text_bytes)

    return base64_bytes.decode('ascii')

def decode_64(encoded_text):
    base64_bytes = encoded_text.encode('ascii')
    text_bytes = base64.b64decode(base64_bytes)
    
    return text_bytes.decode('ascii')

def create_header(user, key):
    cred = [user, key]
    divider = ':'

    encoded_cred = encode_64(divider.join(cred))

    return { 'Authorization': f'Basic { encoded_cred }' }

def check_registry(reg_list, host, sha):
    found = False
    for r in reg_list:
        if r['SHA'] == sha and r['computer'] == host:
            found = True
            break

    return found

class Event_AMP:
    def __init__(self, r_obj):
        self.ID = r_obj['id']
        self.date = r_obj['date']
        self.event_type = r_obj['event_type']
        self.detection = r_obj['detection']
        self.connector_guid = r_obj['connector_guid']
        self.severity = r_obj['severity']
        self.computer = r_obj['computer']['hostname']
        if r_obj['computer'].get('user', 0):
            self.user = r_obj['computer']['user']
        else:
            self.user = "None"
        self.file = {
            'SHA': r_obj['file']['identity']['sha256'],
            'threat': r_obj['file']['disposition'],
            'name': r_obj['file']['file_name'],
            'path': r_obj['file']['file_path']
        }

header_AMP = create_header(environ['AMP_id'], environ['AMP_key'])
header_TOPdesk = create_header(environ['TOPdesk_user'], environ['TOPdesk_key'])

database = TinyDB(r'.\\db\\db.json')
threats_table = database.table('threats')
event_table = database.table('events_id')
user_table = database.table('user')

has_event = Query()
user_config = user_table.all()[0]

while True:

    for event in threats_table:
        payload_AMP = { 'limit': '10', 'event_type': event['id'] }

        # Update the API url according that you have
        response_AMP = requests.get('https://api.amp.com/events', headers=header_AMP, params=payload_AMP)

        for r in response_AMP.json()['data']:
            r_obj = Event_AMP(r)

            if event_table.get(has_event.id == r_obj.ID):            
                print('I\'d registered this event ID')
                continue
            else:
                if (check_registry(event_table.search(has_event.SHA == r_obj.file['SHA']), r_obj.computer, r_obj.file['SHA'])):
                    print('I\'ve registered this SHA on this computer')
                    continue
                else:
                    print('I don\'t have registry of this event')

                    txt = [
                        f'<b>Detection</b> { r_obj.detection }<br><br>',
                        f'<b>Endpoint</b> { r_obj.computer }<br>',
                        f'<b>Connector GUID</b> { r_obj.connector_guid } <br>',
                        f'<b>User</b> { r_obj.user } <br><br>',
                        f"<b>File Name</b> { r_obj.file['name'] } <br>",
                        f"<b>File Path</b> { r_obj.file['path'] } <br>",
                        f"<b>SHA</b> { r_obj.file['SHA'] } <br><br>",
                        f"<b>Virus Total</b> <a href='https://www.virustotal.com/gui/file/{ r_obj.file['SHA'] }'>link para o site</a>"
                    ]

                    req_txt = ''.join(str(w) for w in txt)

                    payload_Ticket = {
                        "briefDescription": f"AMP | { r_obj.severity } alert - { r_obj.event_type } ",
                        "request" : f'{ req_txt }',
                        "callerLookup":{
                                "email": user_config['callerLookup']
                        },
                        "operatorGroup" : {
                            "id" : user_config['operatorGroup']
                        },
                        "category" : {
                            "id" : user_config['category']
                        },
                        "subcategory": {
                            "id" : user_config['subcategory']
                        },
                        "callType": {
                            "id" : user_config['callType']
                        }
                    }

                    # Update the API url according that you have
                    response_TOPdesk = requests.post(f'https://topdesk.com/api/incidents', headers=header_TOPdesk, json=payload_Ticket)

                    if int(response_TOPdesk.status_code) == 201:                        
                        event_table.insert({ 'id':r_obj.ID, 'SHA':r_obj.file['SHA'], 'computer':r_obj.computer })    
                        print('New registry created!')
                
        sleep(5)

    sleep(900)
