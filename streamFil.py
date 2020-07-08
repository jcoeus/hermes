import os, requests, json, time
from pprint import pprint
from requests.auth import AuthBase
from requests.auth import HTTPBasicAuth

consumer_key = input("key: ")
consumer_secret = input("secret: ")

stream_url = "https://api.twitter.com/labs/1/tweets/stream/filter"
rules_url = "https://api.twitter.com/labs/1/tweets/stream/filter/rules"

sample_rules = [
    { 'value' : 'dog has:images', 'tag': 'dog pictures' },
    { 'value' : 'cat has:images -grumpy', 'tag': 'cat pictures' },
]


sample_rules = [
        { 'value':'deep learning'},
]

class BearerTokenAuth(AuthBase):
    def __init__(self, consumer_key, consumer_secret):
        self.bearer_token_url = "https://api.twitter.com/oauth2/token"
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.bearer_token = self.get_bearer_token()

    def get_bearer_token(self):
        response = requests.post(
                self.bearer_token_url,
                auth=(self.consumer_key, self.consumer_secret),
                data={'grant_type': 'client_credentials'},
                headers={'User-Agent': 'TwitterDevFilteredStreamQuickStartPython'})

        if response.status_code is not 200:
            raise Exception(f"Cannot get a Bearer token (HTTP %d): %ss" % (response.status_code, response.text))

        body = response.json()
        return body['access_token']

    def __call__(self, r):
        r.headers['Authorization'] = f"Bearer %s" % self.bearer_token
        r.headers['User-Agent'] = 'TwitterDevFilteredStreamQuickStartPython'
        return r

def get_all_rules(auth):
    response = requests.get(rules_url, auth=auth)

    if response.status_code is not 200:
        raise Exception(f"Cannot get rules (HTTP %d): %s" % (response.status_code, response.text))

    return response.json()

def delete_all_rules(rules, auth):
    if rules is None or 'data' not in rules:
        return None

    ids = list(map(lambda rule: rule['id'], rules['data']))

    payload = {
        'delete': {
            'ids': ids
        }
    }

    response = requests.post(rules_url, auth=auth, json=payload)

    if response.status_code is not 200:
        raise Exception(f"Cannot delete rules (HTTP %d): %s" % (response.status_code, response.text))

def set_rules(rules, auth):
    if rules is None:
        return

    payload = {
        'add': rules
    }

    response = requests.post(rules_url, auth=auth, json=payload)

    if response.status_code is not 201:
        raise Exception(f"Cannot create rules (HTTP %d): %s" % (response.status_code, response.text))

def stream_connect(auth):
    response = requests.get(stream_url, auth=auth, stream=True)
    for response_line in response.iter_lines():
        if response_line:
            pprint(json.loads(response_line))
            print(json.loads(response_line))

bearer_token = BearerTokenAuth(consumer_key, consumer_secret)

def setup_rules(auth):
    current_rules = get_all_rules(auth)
    delete_all_rules(current_rules, auth)
    set_rules(sample_rules, auth)

setup_rules(bearer_token)

timeout = 0
while True:
    stream_connect(bearer_token)
    time.sleep(2 ** timeout)
    timeout += 1

