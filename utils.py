#!/usr/bin/env python

__author__ = 'Luca Tartarini'
__date__ = "30/07/14"
__license__ = "GPL"
__email__ = "ltartarini90@gmail.com"

import json
import headers

verbose = None


class Identifiers:

    def __init__(self):
        self.domain_id = None
        self.project_id = None
        self.group_id = None
        self.role_id = None
        self.idp_id = None
        self.mapping_id = None
        self.protocol_id = None


class Headers:

    def __init__(self):
        self.header_post = headers.HEADER_POST
        self.header_get = headers.HEADER_GET
        self.header_delete = headers.HEADER_GET
        self.header_put = headers.HEADER_PUT
        self.header_patch = headers.HEADER_PATCH


class URLStrings:

    def __init__(self):
        self.api_version = "/v3"
        self.domains_string = "/domains/"
        self.projects_string = "/projects/"
        self.groups_string = "/groups/"
        self.roles_string = "/roles/"
        self.federation_string = "/OS-FEDERATION"
        self.idps_string = "/identity_providers/"
        self.mappings_string = "/mappings/"
        self.protocols_string = "/protocols/"


################# check response #################

def check_response(resp, expected_status):
    return resp.status_code == expected_status


################ expose reason error response ################

def expose_reason(resp):
    print("Error: HTTP status code: %(err_code)d, response body: %(response)s" % {
        'err_code': resp.status_code,
        'response': resp.text
    })


################# read entity id/name by name/id #################

def read_domain_id_by_name(domains, domain_name):
    for domain in domains["domains"]:
        if domain["name"] == domain_name:
            return domain["id"]


def read_domain_name_by_id(domains, domain_id):
    for domain in domains["domains"]:
        if domain["id"] == domain_id:
            return domain["name"]


def read_project_id_by_name(projects, project_name):
    for project in projects["projects"]:
        if project["name"] == project_name:
            return project["id"]


def read_group_id_by_name(groups, group_name):
    for group in groups["groups"]:
        if group["name"] == group_name:
            return group["id"]


def read_group_name_by_id(groups, group_id):
    for group in groups["groups"]:
        if group["id"] == group_id:
            return group["name"]


def read_role_id_by_name(roles, role_name):
    for role in roles["roles"]:
        if role["name"] == role_name:
            return role["id"]


def read_role_name_by_id(roles, role_id):
    for role in roles["roles"]:
        if role["id"] == role_id:
            return role["name"]


################# print entities #################

def print_domains(resp):
    if check_response(resp, 200):
        print("HTTP Status Code: 200\nDomains:")
        print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        expose_reason(resp)


def print_projects(resp):
    if check_response(resp, 200):
        print("HTTP Status Code: 200\nProjects:")
        print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        expose_reason(resp)


def print_groups(resp):
    if check_response(resp, 200):
        print("HTTP Status Code: 200\nGroups:")
        print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        expose_reason(resp)


def print_roles(resp):
    if check_response(resp, 200):
        print("HTTP Status Code: 200\nRoles:")
        print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        expose_reason(resp)