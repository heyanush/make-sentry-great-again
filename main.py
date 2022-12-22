#!/usr/bin/env python
# -*- coding: utf-8 -*-
from jira import JIRA
from flask import Flask, request
import requests
import json
import hashlib
import hmac

app = Flask(__name__)

JIRA_PROJECT_NAME = 'YUV'
JIRA_USERNAME = 'yuval'
JIRA_PASSWORD = 'jira123'
JIRA_SERVER_URL = 'http://localhost:8080'
SENTRY_CLIENT_SECRET = 'ea51effb5a54466a93996ac0128c94df35859e5c66534daab7ce273dff18577d'
SENTRY_AUTH_TOKEN = '26953a0fb8a646f294a04f93cce6b444417682be27384d769bd30ab93f3a172a'
SENTRY_EXTERNAL_ISSUE_API = 'https://sentry.io/api/0/sentry-app-installations/'
SENTRY_UPDATE_ISSUE_API = 'https://sentry.io/api/0/issues/'
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + SENTRY_AUTH_TOKEN
}

jira = JIRA(
    basic_auth=(JIRA_USERNAME, JIRA_PASSWORD),
    server=JIRA_SERVER_URL
)

def sanitize_summary(text):
    text.strip()
    text.replace("\r", "")
    text.replace("\n", "")
    return text[:255]

def authenticate(req):
    expected_digest = req.headers.get('sentry-hook-signature')  # returns None if header is missing
    digest = hmac.new(
        key=SENTRY_CLIENT_SECRET.encode('utf-8'),
        msg=request.data,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not expected_digest:  # The signature is missing
        raise Exception("Permission denied: The signature is missing")

    if not hmac.compare_digest(digest, expected_digest):
        raise Exception("Permission denied: The signature doesn't match")


@app.route('/update_sentry', methods=['POST']) #Webhook for incoming request from JIRA server
def update_sentry():
    print("Incoming request from JIRA server")
    payload = request.json
    #print(payload)
    if payload['issue']['fields']['status']['name'] == "Done":
        status = "resolved"
        issue_id = payload['issue']['fields']['labels'][0]
        data = json.dumps({
            "issueId": issue_id,
            "status": status
        })
        print(data)
        api_endpoint = SENTRY_UPDATE_ISSUE_API + issue_id + '/'
        print(api_endpoint)
        response = requests.request("PUT", api_endpoint, headers=headers, data=data)
        print(response)
    
    elif payload['issue']['fields']['status']['name'] == "To Do":
        status = "unresolved"
        issue_id = payload['issue']['fields']['labels'][0]
        data = json.dumps({
            "issueId": issue_id,
            "status": status
        })
        print(data)
        api_endpoint = SENTRY_UPDATE_ISSUE_API + issue_id + '/'
        print(api_endpoint)
        response = requests.request("PUT", api_endpoint, headers=headers, data=data)
        print(response)

    return ("", 200, None)
    


@app.route('/', methods=['POST']) #Webhook for incoming request from Sentry
def webhook():
    payload = request.json
    #print(payload)
    authenticate(request)
    action = payload['action']
    data = payload['data']
    print(action)
    sentry_integration_uuid = payload['installation']['uuid']
    print(sentry_integration_uuid)
    if action == 'triggered': #Issue alert has been triggered in Sentry
        print("Issue alert has been triggered in Sentry")
        new_issue = createIssueTicket(data)
        externalWebUrl = JIRA_SERVER_URL + '/browse/' + new_issue.key
        issue_id = data['event']['issue_id']
        createExternalIssue(issue_id, externalWebUrl, JIRA_PROJECT_NAME, new_issue.key, sentry_integration_uuid)

    elif action == 'critical': #Critical metric alert has been triggered in Sentry
        print("Critical metric alert has been triggered in Sentry")
        # TODO: Your logic

    elif action == 'warning': #Warning metric alert has been triggered in Sentry
        print("Warning metric alert has been triggered in Sentry")
        # TODO: Your logic

    elif action == 'resolved' and 'metric_alert' in data: #Metric alert has been resolved in Sentry
        print("Metric alert has been resolved in Sentry")
        # TODO: Your logic

    elif action == 'resolved' and 'issue' in data: #ISSUE has been resolved in Sentry
        print("ISSUE has been resolved in Sentry")
        # TODO: Your logic
        # If you are not using Sentry's official Jira Server Integration, you can use here the JIRA SDK in order to mark the ticket as "DONE"

    elif action == 'assigned' and 'issue' in data: #An issue has been assigned in Sentry
        print("An issue has been assigned in Sentry")
        # TODO: Your logic
        # Update the ticket assignee in JIRA


    return ("", 200, None)



def createIssueTicket(data):
    web_url = data['event']['web_url']
    description = "Sentry link: " + web_url.split("events")[0] + "?referrer=jira_integration"
    error_values = data['event']['exception']['values'][0]
    
    if 'value' in error_values:
        exception_value = error_values['value']
    else:
        exception_value = ""
    issue_id = data['event']['issue_id']
    summary = error_values['type'] + ": " + exception_value
    sanitized_summary = sanitize_summary(summary)
    print(sanitized_summary) #log issue summary
    issue_dict = {
        'project': {'key': JIRA_PROJECT_NAME},
        'summary': sanitized_summary,
        'description': description,
        'issuetype': {'name': 'Bug'},
        'labels': [issue_id]
    }
    new_issue = jira.create_issue(fields=issue_dict)
    print(new_issue) #log jira issue name
    return new_issue



def createExternalIssue(issueId, webUrl, project, identifier, sentry_integration_uuid):
    print(issueId)
    payload = json.dumps({
        "issueId": issueId,
        "webUrl": webUrl,
        "project": project,
        "identifier": identifier
    })
    api_endpoint = SENTRY_EXTERNAL_ISSUE_API + sentry_integration_uuid + '/external-issues/'
    print(api_endpoint)
    response = requests.request("POST", api_endpoint, headers=headers, data=payload)
    print(response.text)
    return response



if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)