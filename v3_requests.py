#!/usr/bin/env python

__author__ = 'Luca Tartarini'
__date__ = "20/07/14"
__license__ = "GPL"
__email__ = "ltartarini90@gmail.com"

import requests
import json_objects
import headers
import host_url
import federation_entities_id
import json
import sys
import argparse


class Infrastructure:

    # constructor for the class
    def __init__(self):

        # v3 entities
        self.domain = json_objects.DOMAIN
        self.project = json_objects.PROJECT
        self.role = json_objects.ROLE
        self.group = json_objects.GROUP

        # federation entities
        self.idp = json_objects.IDP
        self.mapping = json_objects.MAPPING
        self.protocol = json_objects.PROTOCOL

        # federation entities id
        self.idp_id = federation_entities_id.idp_id
        self.mapping_id = federation_entities_id.mapping_id
        self.protocol_id = federation_entities_id.protocol_id

        # host url
        self.host_url = host_url.URL

        # string to concatenate
        self.api_version = "/v3"
        self.domains_string = "/domains/"
        self.projects_string = "/projects/"
        self.groups_string = "/groups/"
        self.roles_string = "/roles/"
        self.federation_string = "/OS-FEDERATION"
        self.idps_string = "/identity_providers/"
        self.mappings_string = "/mappings/"
        self.protocols_string = "/protocols/"

        # headers
        self.post_header = headers.HEADER_POST
        self.get_header = headers.HEADER_GET
        self.delete_header = headers.HEADER_DELETE
        self.put_header = headers.HEADER_PUT
        self.patch_header = headers.HEADER_PATCH

    ################# check response #################

    @staticmethod
    def check_response(resp, expected_status):
        return resp.status_code == expected_status

    ################ expose reason error response ################

    @staticmethod
    def expose_reason(resp):
        print("Error: HTTP status code: %(err_code)d, response body: %(response)s" % {
            'err_code': resp.status_code,
            'response': resp.text
        })

    ################# read entity id by name #################

    def read_domain_id_by_name(self, domain_name):
        domains = self.get_domains().json()
        for domain in domains["domains"]:
            if domain["name"] == domain_name:
                return domain["id"]

    def read_project_id_by_name(self, project_name):
        projects = self.get_projects().json()
        for project in projects["projects"]:
            if project["name"] == project_name:
                return project["id"]

    def read_group_id_by_name(self, group_name):
        groups = self.get_groups().json()
        for group in groups["groups"]:
            if group["name"] == group_name:
                return group["id"]

    def read_role_id_by_name(self, role_name):
        roles = self.get_roles().json()
        for role in roles["roles"]:
            if role["name"] == role_name:
                return role["id"]

    ################# print entities #################

    def print_domains(self, resp):
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nDomains:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def print_projects(self, resp):
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProjects:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def print_groups(self, resp):
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nGroups:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def print_roles(self, resp):
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nRoles:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    ################# configure all #################

    def configure_all(self):
        # create domain
        domain_name = self.create_domain()
        # create project
        project_name = self.add_project(domain_name)
        # create role
        role_name = self.create_role()
        # create group
        group_name = self.add_group(domain_name)
        # grant role
        self.grant_role_group_domain(domain_name, group_name, role_name)
        # create identity provider
        if federation_entities_id.idp_id is None:
            idp_id = raw_input("Insert IdP id: ")
        self.create_idp(idp_id)
        # create mapping
        if federation_entities_id.mapping_id is None:
            mapping_id = raw_input("Insert Mapping id: ")
        self.create_mapping(mapping_id)
        # create protocol
        protocol_id= raw_input("Insert Protocol id: ")
        self.create_protocol(protocol_id, idp_id, mapping_id)

    ################# domains #################

    def create_domain(self):
        url = self.host_url + self.api_version + self.domains_string
        body = self.domain
        resp = requests.post(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.domain = (resp.json().get("domain"))
            print("HTTP Status Code: 201\nDomain created:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def update_domain(self, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        body = self.domain
        resp = requests.patch(url, data=json.dumps(body), headers=self.patch_header)
        if self.check_response(resp, 200):
            self.domain = resp.json().get("domain")
            print("HTTP Status Code: 200\nDomain updated:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_domain(self, domain_name, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        resp = requests.delete(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nDomain deleted:")
            print("\tName: " + domain_name + "\n\tid: " + domain_id)
        else:
            self.expose_reason(resp)

    def get_domain(self, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.domain = resp.json().get("domain")
            print("HTTP Status Code: 200\nDomain:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_domains(self):
        url = self.host_url + self.api_version + self.domains_string
        resp = requests.get(url, headers=self.get_header)
        return resp

    def grant_role_group_domain(self, domain_name, domain_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id + self.groups_string + group_id + \
            self.roles_string + role_id
        resp = requests.put(url, headers=self.put_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nGranted role to group on domain:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Domain:\n\tname: " + domain_name + "\n\tid: " + domain_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
        else:
            self.expose_reason(resp)

    def revoke_role_group_domain(self, domain_name, domain_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id + self.groups_string + group_id + \
            self.roles_string + role_id
        resp = requests.put(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nRevoked role to group on domain:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Domain:\n\tname: " + domain_name + "\n\tid: " + domain_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
        else:
            self.expose_reason(resp)

    ################# projects #################

    def create_project(self):
        url = self.host_url + self.api_version + self.projects_string
        body = self.project
        if body["project"]["domain_id"] is None:
            domain_name = raw_input("Insert domain name: ")
            domain_id = self.read_domain_id_by_name(domain_name)
            body["project"]["domain_id"] = domain_id
        resp = requests.post(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.project = (resp.json().get("project"))
            print("HTTP Status Code: 201\nProject created:")
            print(json.dumps(self.project, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def update_project(self, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        body = self.project
        resp = requests.patch(url, data=json.dumps(body), headers=self.patch_header)
        if self.check_response(resp, 200):
            self.project = resp.json().get("project")
            print("HTTP Status Code: 200\nProject updated:")
            print(json.dumps(self.project, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_project(self, project_name, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        resp = requests.delete(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nProject deleted:")
            print("\tName: " + project_name + "\n\tid: " + project_id)
        else:
            self.expose_reason(resp)

    def get_project(self, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProject:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_projects(self):
        v3_projects_url = self.host_url + self.api_version + self.projects_string
        resp = requests.get(v3_projects_url, headers=self.get_header)
        return resp

    def grant_role_group_project(self, project_name, project_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.projects_string + project_id + self.groups_string + group_id + \
            self.roles_string + role_id
        resp = requests.put(url, headers=self.put_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nGranted role to group on project:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
            print("Project:\n\tname: " + project_name + "\n\tid: " + project_id)
        else:
            self.expose_reason(resp)

    def revoke_role_group_project(self, project_name, project_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.projects_string + project_id + self.groups_string + group_id + \
            self.roles_string + role_id
        resp = requests.put(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nRevoked role to group on project:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
            print("Project:\n\tname: " + project_name + "\n\tid: " + project_id)
        else:
            self.expose_reason(resp)

    ################# roles #################

    def create_role(self):
        url = self.host_url + self.api_version + self.roles_string
        body = self.role
        resp = requests.post(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.role = resp.json().get("role")
            print("HTTP Status Code: 201\nRole created:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def update_role(self, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        body = self.role
        resp = requests.patch(url, data=json.dumps(body), headers=self.patch_header)
        if self.check_response(resp, 200):
            self.role == resp.json().get("role")
            print("HTTP Status Code: 200\nRole updated:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_role(self, role_name, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        resp = requests.delete(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nRole deleted:")
            print("\tName: " + role_name + "\n\tid: " + role_id)
        else:
            self.expose_reason(resp)

    def get_role(self, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.role = resp.json().get("role")
            print("HTTP Status Code: 200\nRole:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_roles(self):
        url = self.host_url + self.api_version + self.roles_string
        resp = requests.get(url, headers=self.get_header)
        return resp

    ################# groups #################

    def create_group(self):
        url = self.host_url + self.api_version + self.groups_string
        body = self.group
        if body['group']['domain_id'] is None:
            domain_name = raw_input("Insert domain name: ")
            domain_id = self.read_domain_id_by_name(domain_name)
            body['group']['domain_id'] = domain_id
        resp = requests.post(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.group = resp.json().get("group")
            print("HTTP Status Code: 201\nGroup created:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def update_group(self, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        body = self.group
        resp = requests.patch(url, data=json.dumps(body), headers=self.patch_header)
        if self.check_response(resp, 200):
            self.group = (resp.json().get("group"))
            print("HTTP Status Code: 200\nGroup updated:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_group(self, group_name, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        resp = requests.delete(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nGroup deleted:")
            print("\tName: " + group_name + "\n\tid: " + group_id)
        else:
            self.expose_reason(resp)

    def get_group(self, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.group = resp.json().get("group")
            print("HTTP Status Code: 200\nGroup:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_groups(self):
        url = self.host_url + self.api_version + self.groups_string
        resp = requests.get(url, headers=self.get_header)
        return resp

    ################# identity providers #################
    def create_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        body = self.idp
        resp = requests.put(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.idp = resp.json().get("identity_provider")
            print("HTTP Status Code: 201\nIdP created:")
            print(json.dumps(self.idp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        resp = requests.delete(url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nIdentity provider deleted:")
            print("\tId: " + idp_id)
        else:
            self.expose_reason(resp)

    def get_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.idp = resp.json().get("identity_provider")
            print("HTTP Status Code: 200\nIdentity provider:")
            print(json.dumps(self.idp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_idps(self):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nIdentity providers:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    ################# mappings #################

    def create_mapping(self, mapping_id):
        url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        body = self.mapping
        if body["mapping"]["rules"][0]["local"][1]["group"]["id"] is None:
            group_name = raw_input("Insert group name: ")
            group_id = self.read_group_id_by_name(group_name)
            body["mapping"]["rules"][0]["local"][1]["group"]["id"] = group_id
        resp = requests.put(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 201\nMapping created:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        resp = requests.delete(v3_mappings_url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nMapping deleted:")
            print("\tId: " + mapping_id)
        else:
            self.expose_reason(resp)

    def get_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        resp = requests.get(v3_mappings_url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 200\nMapping:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_mappings(self):
        url = self.host_url + self.api_version + self.federation_string + self.mappings_string
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nMappings:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def update_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        body = self.mapping
        resp = requests.patch(v3_mappings_url, data=json.dumps(body), headers=self.patch_header)
        if self.check_response(resp, 200):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 200\nMapping updated:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    ################# protocols #################

    def create_protocol(self, protocol_id, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
            self.protocols_string + protocol_id
        body = self.protocol
        if body["protocol"]["mapping_id"] is None:
            mapping_id = raw_input("Insert mapping_id: ")
            body["protocol"]["mapping_id"] = mapping_id
        print(body)
        resp = requests.put(url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.protocol = resp.json().get("protocol")
            print("HTTP Status Code: 201\nProtocol created:")
            print(json.dumps(self.protocol, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_protocol(self, protocol_id, idp_id):
        v3_protocols_url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
            self.protocols_string + protocol_id
        resp = requests.delete(v3_protocols_url, headers=self.delete_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nProtocol deleted:")
            print("\tId: " + protocol_id)
        else:
            self.expose_reason(resp)

    def get_protocol(self, protocol_id, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
            self.protocols_string + protocol_id
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            self.protocol = resp.json().get("protocol")
            print("HTTP Status Code: 200\nProtocol:")
            print(json.dumps(self.protocol, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def get_protocols(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
            self.protocols_string
        resp = requests.get(url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProtocols:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)


if __name__ == "__main__":

    i = Infrastructure()

    parser = argparse.ArgumentParser()

    if len(sys.argv) >= 2:

        ################# configure all #################
        parser.add_argument("--configure-all", action="store_true")

        ################# domains #################

        parser.add_argument("--domain-get", nargs=1, metavar="<domain_name>")
        parser.add_argument("--domains-get", action="store_true")
        parser.add_argument("--domain-create", action="store_true")
        parser.add_argument("--domain-update", nargs=1, metavar="<domain_name>")
        parser.add_argument("--domain-delete", nargs=1, metavar="<domain_name>")
        parser.add_argument("--grant-role-group-domain", nargs=3, metavar=("<domain_name>", "<group_name>",
                                                                           "<role_name>"))
        parser.add_argument("--revoke-role-group-domain", nargs=3, metavar=("<domain_name>", "<group_name>",
                                                                            "<role_name>"))

        ################# projects #################

        parser.add_argument("--project-get", nargs=1, metavar="<project_name>")
        parser.add_argument("--projects-get", action="store_true")
        parser.add_argument("--project-create", action="store_true")
        parser.add_argument("--project-update", nargs=1, metavar="<project_name>")
        parser.add_argument("--project-delete", nargs=1, metavar="<project_name>")
        parser.add_argument("--grant-role-group-project", nargs=3, metavar=("<project_name>", "<group_name>",
                                                                            "<role_name>"))
        parser.add_argument("--revoke-role-group-project", nargs=3, metavar=("<project_name>", "<group_name>",
                                                                             "<role_name>"))

        ################# roles #################

        parser.add_argument("--role-get", nargs=1, metavar="<role_name>")
        parser.add_argument("--roles-get", action="store_true")
        parser.add_argument("--role-create", action="store_true")
        parser.add_argument("--role-update", nargs=1, metavar="<role_name>")
        parser.add_argument("--role-delete", nargs=1, metavar="<role_name>")

        ################# groups #################

        parser.add_argument("--group-get", nargs=1, metavar="<group_name>")
        parser.add_argument("--groups-get", action="store_true")
        parser.add_argument("--group-create", action="store_true")
        parser.add_argument("--group-update", nargs=1, metavar="<group_name>")
        parser.add_argument("--group-delete", nargs=1, metavar="<group_name>")

        ################# identity providers #################

        parser.add_argument("--idp-get", nargs=1, metavar="<idp_id>")
        parser.add_argument("--idps-get", action="store_true")
        parser.add_argument("--idp-create", nargs=1, metavar="<idp_id>")
        parser.add_argument("--idp-delete", nargs=1, metavar="<idp_id>")

        ################# mappings #################
        parser.add_argument("--mapping-get", nargs=1, metavar="<mapping_id>")
        parser.add_argument("--mappings-get", action="store_true")
        parser.add_argument("--mapping-create", nargs=1, metavar="<mapping_id>")
        parser.add_argument("--mapping-delete", nargs=1, metavar="<mapping_id>")
        parser.add_argument("--mapping-update", nargs=1, metavar="<mapping_id>")

        ################# protocols #################

        parser.add_argument("--protocol-get", nargs=2, metavar=("<protocol_id>", "<idp_id>"))
        parser.add_argument("--protocols-get", nargs=1, metavar="<idp_id>")
        parser.add_argument("--protocol-create", nargs=2, metavar=("<protocol_id>", "<idp_id>"))
        parser.add_argument("--protocol-delete", nargs=2, metavar=("<protocol_id>", "<idp_id>"))

        ns = parser.parse_args()

        ################# configure all #################
        if ns.configure_all:
            i.configure_all()

        ################# domains #################

        elif ns.domain_get:
            domain_identifier = i.read_domain_id_by_name(ns.domain_get[0])
            i.get_domain(domain_identifier)
        elif ns.domains_get:
            response = i.get_domains()
            i.print_domains(response)
        elif ns.domain_create:
            i.create_domain()
        elif ns.domain_update:
            domain_identifier = i.read_domain_id_by_name(ns.domain_update[0])
            i.update_domain(domain_identifier)
        elif ns.domain_delete:
            domain_identifier = i.read_domain_id_by_name(ns.domain_delete[0])
            i.delete_domain(ns.domain_delete[0], domain_identifier)
        elif ns.grant_role_group_domain:
            domain_identifier = i.read_domain_id_by_name(ns.grant_role_group_domain[0])
            group_identifier = i.read_group_id_by_name(ns.grant_role_group_domain[1])
            role_identifier = i.read_role_id_by_name(ns.grant_role_group_domain[2])
            i.grant_role_group_domain(ns.grant_role_group_domain[0], domain_identifier, ns.grant_role_group_domain[1],
                                      group_identifier, ns.grant_role_group_domain[2], role_identifier)
        elif ns.revoke_role_group_domain:
            domain_identifier = i.read_domain_id_by_name(ns.revoke_role_group_domain[0])
            group_identifier = i.read_group_id_by_name(ns.revoke_role_group_domain[1])
            role_identifier = i.read_role_id_by_name(ns.revoke_role_group_domain[2])
            i.revoke_role_group_domain(ns.revoke_role_group_domain[0], domain_identifier,
                                       ns.revoke_role_group_domain[1], group_identifier, ns.revoke_role_group_domain[2],
                                       role_identifier)

        ################# projects #################

        elif ns.project_get:
            project_identifier = i.read_project_id_by_name(ns.project_get[0])
            i.get_project(project_identifier)
        elif ns.projects_get:
            response = i.get_projects()
            i.print_projects(response)
        elif ns.project_create:
            i.create_project()
        elif ns.project_update:
            project_identifier = i.read_project_id_by_name(ns.project_update[0])
            i.update_project(project_identifier)
        elif ns.project_delete:
            project_identifier = i.read_project_id_by_name(ns.project_delete[0])
            i.delete_project(ns.project_delete[0], project_identifier)
        elif ns.grant_role_group_project:
            project_identifier = i.read_project_id_by_name(ns.grant_role_group_project[0])
            group_identifier = i.read_group_id_by_name(ns.grant_role_group_project[1])
            role_identifier = i.read_role_id_by_name(ns.grant_role_group_project[2])
            i.grant_role_group_project(ns.grant_role_group_project[0], project_identifier,
                                       ns.grant_role_group_project[1], group_identifier, ns.grant_role_group_project[2],
                                       role_identifier)
        elif ns.revoke_role_group_project:
            project_identifier = i.read_project_id_by_name(ns.revoke_role_group_project[0])
            group_identifier = i.read_group_id_by_name(ns.revoke_role_group_project[1])
            role_identifier = i.read_role_id_by_name(ns.revoke_role_group_project[2])
            i.revoke_role_group_project(ns.revoke_role_group_project[0], project_identifier,
                                        ns.revoke_role_group_project[1], group_identifier,
                                        ns.revoke_role_group_project[2], role_identifier)

        ################# roles #################

        elif ns.role_get:
            role_identifier = i.read_role_id_by_name(ns.role_get[0])
            i.get_role(role_identifier)
        elif ns.roles_get:
            response = i.get_roles()
            i.print_roles(response)
        elif ns.role_create:
            i.create_role()
        elif ns.role_update:
            role_identifier = i.read_role_id_by_name(ns.role_update[0])
            i.update_role(role_identifier)
        elif ns.role_delete:
            role_identifier = i.read_role_id_by_name(ns.role_delete[0])
            i.delete_role(ns.role_delete[0], role_identifier)

        ################# groups #################

        elif ns.group_get:
            group_identifier = i.read_group_id_by_name(ns.group_get[0])
            i.get_group(group_identifier)
        elif ns.groups_get:
            response = i.get_groups()
            i.print_roles(response)
        elif ns.group_create:
            i.create_group()
        elif ns.group_update:
            group_identifier = i.read_group_id_by_name(ns.group_update[0])
            i.update_group(group_identifier)
        elif ns.group_delete:
            group_identifier = i.read_group_id_by_name(ns.group_delete[0])
            i.delete_group(ns.group_delete[0], group_identifier)

        ################# identity providers #################

        elif ns.idp_get:
            i.get_idp(ns.idp_get[0])
        elif ns.idps_get:
            i.get_idps()
        elif ns.idp_create:
            i.create_idp(ns.idp_create[0])
        elif ns.idp_delete:
            i.delete_idp(ns.idp_delete[0])

        ################# mappings #################

        elif ns.mapping_get:
            i.get_mapping(ns.mapping_get[0])
        elif ns.mappings_get:
            i.get_mappings()
        elif ns.mapping_create:
            i.create_mapping(ns.mapping_create[0])
        elif ns.mapping_delete:
            i.delete_mapping(ns.mapping_delete[0])
        elif ns.mapping_update:
            i.update_mapping(ns.mapping_modify[0])

        ################# protocols #################

        elif ns.protocol_get:
            i.get_protocol(ns.protocol_get[0], ns.protocol_get[1])
        elif ns.protocols_get:
            i.get_protocols(ns.protocols_get[0])
        elif ns.protocol_create:
            i.create_protocol(ns.protocol_create[0], ns.protocol_create[1])
        elif ns.protocol_delete:
            i.delete_protocol(ns.protocol_delete[0], ns.protocol_delete[1])

    else:
        print("Help: v3_requests.py -h")