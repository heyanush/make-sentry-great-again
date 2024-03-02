#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import json
import requests
import hashlib
import hmac
from jira import JIRA
from flask import Flask, request

if not os.environ.get("PRODUCTION"):
    from dotenv import load_dotenv

    load_dotenv()

app = Flask(__name__)

# Constants and Configuration
JIRA_USERNAME = os.environ.get("JIRA_USERNAME") # Default JIRA username
JIRA_TOKEN = os.environ.get("JIRA_TOKEN")  # Your JIRA password
JIRA_SERVER_URL = os.environ.get("JIRA_SERVER_URL") # Your JIRA server URL
SENTRY_CLIENT_SECRET = None # Client secret key is provided in the internal integration page in Sentry
SENTRY_AUTH_TOKEN = None # Sentry auth token is provided in the internal integration page in Sentry
SENTRY_EXTERNAL_ISSUE_API = 'https://sentry.io/api/0/sentry-app-installations/'
SENTRY_UPDATE_ISSUE_API = 'https://sentry.io/api/0/issues/'

if not (JIRA_USERNAME and JIRA_TOKEN and JIRA_SERVER_URL):
    raise ValueError("Required environment variables are not set.")


def get_header_for_sentry():
    return {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {SENTRY_AUTH_TOKEN}'
    }


def sanitize(text):
    text = text.strip().replace("\r", "").replace("\n", "")
    return text[:255]


def authenticate(req):
    expected_digest = req.headers.get('sentry-hook-signature')
    if not expected_digest:
        raise Exception("Permission denied: The signature is missing")
    digest = hmac.new(
        key=SENTRY_CLIENT_SECRET.encode('utf-8'),
        msg=request.data,
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(digest, expected_digest):
        raise Exception("Permission denied: The signature doesn't match")


# This endpoint will only be called if the 'alert-rule-action' is present in the schema.
@app.route("/api/sentry/alert-rule-action/", methods=["POST"])
@app.route("/<project>/api/sentry/alert-rule-action/", methods=["POST"])
def alert_rule_action(project=None):
    return ("", 200, None)


@app.route('/<project>/', methods=['POST'])
def webhook(project):
    global SENTRY_CLIENT_SECRET, SENTRY_AUTH_TOKEN

    SENTRY_CLIENT_SECRET = os.environ.get("SENTRY_CLIENT_SECRET_" + project.upper())
    SENTRY_AUTH_TOKEN = os.environ.get("SENTRY_AUTH_TOKEN_" + project.upper())
    if not (SENTRY_CLIENT_SECRET and SENTRY_AUTH_TOKEN):
        raise ValueError("Required environment variables are not set for this project.")

    payload = request.json
    authenticate(request)
    action = payload['action']
    data = payload['data']

    if action == 'triggered':
        new_issue = create_jira_ticket(data)
        external_web_url = JIRA_SERVER_URL + '/browse/' + new_issue.key
        issue_id = data['event']['issue_id']
        link_sentry_to_jira(issue_id, external_web_url, new_issue.key, payload['installation']['uuid'])

    return ("", 200, None)


def create_jira_ticket(data):
    global JIRA_USERNAME, JIRA_TOKEN

    event = data['event']
    issue_title = event['title']
    issue_url = event['web_url']
    issue_id = event['issue_id']
    issue_description = event['culprit']
    
    summary = sanitize(issue_title)
    description = "*Culprit:* {}\n".format(issue_description) \
                + "*Sentry Issue:* {}\n".format(issue_id) \
                + "*Sentry Issue URL:* {}\n".format(issue_url)

    issue_dict = {
        'summary': summary,
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
            elif value['name'] == 'jirausername':
                JIRA_USERNAME = value['value']
            elif value['name'] == 'jiratoken':
                JIRA_TOKEN = value['value']
            else:
                try:
                    issue_dict[value['name']] = json.loads(value['value'])
                except ValueError as e:
                    issue_dict[value['name']] = [value['value']]
    except KeyError:
        pass

    jira = JIRA(
        basic_auth=(JIRA_USERNAME, JIRA_TOKEN),
        server=JIRA_SERVER_URL
    )
    
    # Find if the issue already existy by issue summary
    issues = jira.search_issues(f'summary ~ "\\"{summary}\\""')
    if issues:
        return issues[0]

    new_issue = jira.create_issue(fields=issue_dict)
    return new_issue


def link_sentry_to_jira(issue_id, web_url, identifier, sentry_integration_uuid):
    payload = json.dumps({
        "issueId": issue_id,
        "webUrl": web_url,
        "project": 'Jira',
        "identifier": identifier
    })
    api_endpoint = SENTRY_EXTERNAL_ISSUE_API + sentry_integration_uuid + '/external-issues/'
    response = requests.request("POST", api_endpoint, headers=get_header_for_sentry(), data=payload)
    return response


if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)
