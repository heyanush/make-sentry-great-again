#!/usr/bin/env python
# -*- coding: utf-8 -*-
from jira import JIRA
from flask import Flask, request
import requests
import json
import hashlib
import hmac
import os

if not os.environ.get("PRODUCTION"):
    from dotenv import load_dotenv

    load_dotenv()

app = Flask(__name__)

JIRA_USERNAME = os.environ.get("JIRA_USERNAME") #Your JIRA username
JIRA_TOKEN = os.environ.get("JIRA_TOKEN") #Your JIRA password
JIRA_SERVER_URL = os.environ.get("JIRA_SERVER_URL") #Your JIRA server URL
SENTRY_CLIENT_SECRET = None #Client secret key is provided in the internal integration page in Sentry
SENTRY_AUTH_TOKEN = None #Sentry auth token is provided in the internal integration page in Sentry
SENTRY_EXTERNAL_ISSUE_API = 'https://sentry.io/api/0/sentry-app-installations/'
SENTRY_UPDATE_ISSUE_API = 'https://sentry.io/api/0/issues/'

jira = JIRA(
    basic_auth=(JIRA_USERNAME, JIRA_TOKEN),
    server=JIRA_SERVER_URL
)

def getHeaderForSentry():
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + SENTRY_AUTH_TOKEN
    }

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


# This endpoint will only be called if the 'alert-rule-action' is present in the schema.
@app.route("/api/sentry/alert-rule-action/", methods=["POST"])
def alert_rule_action():

    return ("", 200, None)

@app.route('/update_sentry', methods=['POST']) #Webhook for incoming request from JIRA server
def update_sentry():
    print("Incoming request from JIRA server")
    payload = request.json
    #print(payload)
    if payload['issue']['fields']['status']['name'] == "Done": #Marking the issue as Done in JIRA will resolve the issue in Sentry
        status = "resolved"
        issue_id = payload['issue']['fields']['labels'][0]
        data = json.dumps({
            "issueId": issue_id,
            "status": status
        })
        print(data)
        api_endpoint = SENTRY_UPDATE_ISSUE_API + issue_id + '/'
        print(api_endpoint)
        response = requests.request("PUT", api_endpoint, headers=getHeaderForSentry(), data=data)
        print(response)
    
    elif payload['issue']['fields']['status']['name'] == "To Do": #Marking the issue as To Do in JIRA will unresolved the issue in Sentry
        status = "unresolved"
        issue_id = payload['issue']['fields']['labels'][0]
        data = json.dumps({
            "issueId": issue_id,
            "status": status
        })
        print(data)
        api_endpoint = SENTRY_UPDATE_ISSUE_API + issue_id + '/'
        print(api_endpoint)
        response = requests.request("PUT", api_endpoint, headers=getHeaderForSentry(), data=data)
        print(response)

    return ("", 200, None)
    


@app.route('/api/sentry/log/<project>', methods=['POST']) #Webhook for incoming requests from Sentry
def webhook(project):
    global SENTRY_CLIENT_SECRET, SENTRY_AUTH_TOKEN
    SENTRY_CLIENT_SECRET = os.environ.get("SENTRY_CLIENT_SECRET_" + project.upper())
    SENTRY_AUTH_TOKEN = os.environ.get("SENTRY_AUTH_TOKEN_" + project.upper())

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
        createExternalIssue(issue_id, externalWebUrl, new_issue.key, sentry_integration_uuid)

    #Metric Alert payload object: https://docs.sentry.io/product/integrations/integration-platform/webhooks/metric-alerts/
    elif action == 'critical': #Critical metric alert has been triggered in Sentry
        print("Critical metric alert has been triggered in Sentry")
        # TODO: Your logic

    elif action == 'warning': #Warning metric alert has been triggered in Sentry
        print("Warning metric alert has been triggered in Sentry")
        # TODO: Your logic

    elif action == 'resolved' and 'metric_alert' in data: #Metric alert has been resolved in Sentry
        print("Metric alert has been resolved in Sentry")
        # TODO: Your logic

    #Issue payload object: https://docs.sentry.io/product/integrations/integration-platform/webhooks/issues/
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
    #Issue Alert payload object specs: https://docs.sentry.io/product/integrations/integration-platform/webhooks/issue-alerts/
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
        'summary': sanitized_summary,
        'description': description,
        'labels': [issue_id]
    }

    try:
        params = data['issue_alert']['settings']
        for value in params:
            if value['name'] == 'project':
                issue_dict['project'] = {'key': value['value']}
            elif value['name'] == 'parent':
                issue_dict['parent'] = {'key': value['value']}
            elif value['name'] == 'issuetype':
                issue_dict['issuetype'] = {'name': value['value']}
            else:
                try:
                    issue_dict[value['name']] = json.loads(value['value'])
                except ValueError as e:
                    issue_dict[value['name']] = [value['value']]
    except KeyError:
        pass

    new_issue = jira.create_issue(fields=issue_dict)
    print(new_issue) #log jira issue name
    return new_issue



def createExternalIssue(issueId, webUrl, identifier, sentry_integration_uuid):
    #Linking the JIRA ticket to a Sentry issue: https://docs.sentry.io/api/integration/create-an-external-issue/
    print(issueId)
    project = 'Jira'
    payload = json.dumps({
        "issueId": issueId,
        "webUrl": webUrl,
        "project": project,
        "identifier": identifier
    })
    api_endpoint = SENTRY_EXTERNAL_ISSUE_API + sentry_integration_uuid + '/external-issues/'
    print(api_endpoint)
    response = requests.request("POST", api_endpoint, headers=getHeaderForSentry(), data=payload)
    print(response.text)
    return response



if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)