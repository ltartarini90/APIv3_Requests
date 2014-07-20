#!/usr/bin/env python

__author__ = 'Luca Tartarini'
__date__ = "20/07/14"
__license__ = "GPL"
__email__ = "ltartarini90@gmail.com"

import requests
import json_objects
import headers
import url
import json
import sys
import os
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

        # host url
        self.url = url.URL

        # headers
        self.post_header = headers.HEADER_POST
        self.get_header = headers.HEADER_GET
        self.delete_header = headers.HEADER_DELETE
        self.put_header = headers.HEADER_PUT
        self.patch_header = headers.HEADER_PATCH

    @staticmethod
    def check_response(resp, expected_status):
        return resp.status_code == expected_status

    @staticmethod
    def expose_reason(resp):
        print "Error: HTTP status code: %(err_code)d, response body: %(response)s" % {
            'err_code': resp.status_code,
            'response': resp.text
        }

    @staticmethod
    def read_id(filename):
        filename = "./" + filename + "_id"
        in_file = open(filename, "r")
        entity_id = in_file.readline()
        in_file.close()
        return entity_id

    @staticmethod
    def write_id(filename, entity_id):
        out_file = open("./" + filename + "_id", "w")
        out_file.write(entity_id)
        out_file.close()

    ################# domains #################
    def add_domain(self):
        v3_domains_url = self.url + "/v3/domains"
        body = self.domain
        print(body)
        resp = requests.post(v3_domains_url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 201):
            self.domain.update(resp.json().get('domain'))
            print(self.domain)
            self.write_id(self.domain["name"], self.domain["id"])
            print("HTTP Status Code: 201\nDomain added:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            self.expose_reason(resp)

    def delete_domain(self, domain_name):
        domain_id = self.read_id(domain_name)
        v3_domains_url = self.url + "/v3/domains/" + domain_id
        resp = requests.delete(v3_domains_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nDomain deleted:")
            print("\tName: " + domain_name + "\n\tid: " + domain_id)
            os.remove("./" + domain_name + "_id")
        else:
            print("Error")

    def modify_domain(self, domain_name):
        domain_id = self.read_id(domain_name)
        v3_domains_url = self.url + "/v3/domains/" + domain_id
        body = self.domain
        resp = requests.patch(v3_domains_url, data=json.dumps(body), headers=self.post_header)
        if self.check_response(resp, 200):
            self.domain.update(resp.json().get('domain'))
            print("HTTP Status Code: 200\nDomain modified:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_domain(self, domain_name):
        domain_id = self.read_id(domain_name)
        v3_domains_url = self.url + "/v3/domains/" + domain_id
        resp = requests.get(v3_domains_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nDomain:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_domains(self):
        v3_domains_url = self.url + "/v3/domains/"
        resp = requests.get(v3_domains_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nDomains:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def grant_role(self, domain_name, group_name, role_name):
        domain_id = self.read_id(domain_name)
        group_id = self.read_id(group_name)
        role_id= self.read_id(role_name)
        v3_url = self.url + "/v3/domains/" + domain_id + "/groups/" + group_id + "/roles/" + role_id
        resp = requests.put(v3_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nGranted role to domain group:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Domain:\n\tname: " + domain_name + "\n\tid: " + domain_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
        else:
            print("Error")

    ################# projects #################
    def add_project(self, domain_name):
        domain_id = self.read_id(domain_name)
        v3_projects_url = self.url + "/v3/projects"
        body = self.project
        if body['project']['domain_id'] is None:
            body['project']['domain_id'] = domain_id
        resp = requests.post(v3_projects_url, data=json.dumps(body), headers=self.post_header)
        project = resp.json().get("project")
        project_id = project["id"]
        project_name = project["name"]
        self.write_id(project_name, project_id)
        if (self.check_response(resp, 201)):
            print("HTTP Status Code: 201\nProject added:")
            print(json.dumps(project, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print "Error"

    def delete_project(self, project_name):
        project_id = self.read_id(project_name)
        v3_projects_url = self.url + "/v3/projects/" + project_id
        resp = requests.delete(v3_projects_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nProject deleted:")
            print("\tName: " + project_name + "\n\tid: " + project_id)
            os.remove("./" + project_name + "_id")
        else:
            print("Error")

    def get_projects(self):
        v3_projects_url = self.url + "/v3/projects/"
        resp = requests.get(v3_projects_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProjects:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_project(self, project_name):
        project_id = self.read_id(project_name)
        v3_projects_url = self.url + "/v3/projects/" + project_id
        resp = requests.get(v3_projects_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProject:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    ################# roles #################
    def add_role(self):
        v3_roles_url = self.url + "/v3/roles"
        body = self.role
        resp = requests.post(v3_roles_url, data=json.dumps(body), headers=self.post_header)
        role = resp.json().get("role")
        role_id = role["id"]
        role_name = role["name"]
        self.write_id(role_name, role_id)
        if self.check_response(resp, 201):
            self.role.update(resp.json().get('role'))
            print("HTTP Status Code: 201\nRole added:")
            print(self.role)
        else:
            print("Error")

    def delete_role(self, role_name):
        role_id = self.read_id(role_name)
        v3_roles_url = self.url + "/v3/roles/" + role_id
        resp = requests.delete(v3_roles_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nRole deleted:")
            print("\tName: " + role_name + "\n\tid: " + role_id)
            os.remove("./" + role_name + "_id")
        else:
            print "Error"

    ################# groups #################
    def add_group(self, domain_name):
        domain_id = self.read_id(domain_name)
        v3_groups_url = self.url + "/v3/groups"
        body = self.group
        if body['group']['domain_id'] is None:
            body['group']['domain_id'] = domain_id
        resp = requests.post(v3_groups_url, data=json.dumps(body), headers=self.post_header)
        group = resp.json().get("group")
        group_id = group["id"]
        group_name = group["name"]
        self.write_id(group_name, group_id)
        if self.check_response(resp, 201):
            self.group.update(resp.json().get('group'))
            print("HTTP Status Code: 201\nGroup added:")
            print(self.group)
        else:
            print("Error")

    def delete_group(self, group_name):
        group_id = self.read_id(group_name)
        v3_groups_url = self.url + "/v3/groups/" + group_id
        resp = requests.delete(v3_groups_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nGroup deleted:")
            print("Name: " + group_name + "\nid: " + group_id)
            os.remove("./" + group_name + "_id")
        else:
            print("Error")

    def get_groups(self):
        v3_groups_url = self.url + "/v3/groups/"
        resp = requests.get(v3_groups_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nGroups:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    ################# identity providers #################
    def add_idp(self, idp_id):
        v3_idps_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id
        body = self.idp
        resp = requests.put(v3_idps_url, data=json.dumps(body), headers=self.post_header)
        self.idp = resp.json().get("identity_provider")
        self.write_id(self.idp["id"], self.idp["id"])
        if self.check_response(resp, 201):
            print("HTTP Status Code: 201\nIdP added:")
            print(json.dumps(self.idp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def delete_idp(self, idp_id):
        v3_idps_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id
        resp = requests.delete(v3_idps_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nIdentity provider deleted:")
            print("\tId: " + idp_id)
            os.remove("./" + idp_id + "_id")
        else:
            print("Error, can not delete identity provider: " + idp_id)

    def get_idp(self, idp_id):
        v3_idps_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id
        resp = requests.get(v3_idps_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nIdentity provider:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_idps(self):
        v3_idps_url = self.url + "/v3/OS-FEDERATION/identity_providers/"
        resp = requests.get(v3_idps_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nIdentity providers:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    ################# mappings #################
    def add_mapping(self, mapping_id, group_name):
        group_id = self.read_id(group_name)
        v3_mappings_url = self.url + "/v3/OS-FEDERATION/mappings/" + mapping_id
        body = self.mapping
        if body['mapping']['rules'][0]['local'][1]['group']['id'] is None:
            body['mapping']['rules'][0]['local'][1]['group']['id'] = group_id
        resp = requests.put(v3_mappings_url, data=json.dumps(body), headers=self.post_header)
        self.mapping = resp.json().get("mapping")
        self.write_id(self.mapping["id"], self.mapping["id"])
        if self.check_response(resp, 201):
            print("HTTP Status Code: 201\nMapping added:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def delete_mapping(self, mapping_id):
        v3_mappings_url = self.url + "/v3/OS-FEDERATION/mappings/" + mapping_id
        resp = requests.delete(v3_mappings_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nMapping deleted:")
            print("\tId: " + mapping_id)
            os.remove("./" + mapping_id + "_id")
        else:
            print("Error, can not delete mapping: " + mapping_id)

    def get_mapping(self, mapping_id):
        v3_mappings_url = self.url + "/v3/OS-FEDERATION/mappings/" + mapping_id
        resp = requests.get(v3_mappings_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nMapping:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_mappings(self):
        v3_mappings_url = self.url + "/v3/OS-FEDERATION/mappings/"
        resp = requests.get(v3_mappings_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nMappings:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    ################# protocols #################
    def add_protocol(self, protocol_id, idp_id, mapping_id):
        v3_protocols_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id + "/protocols/" + protocol_id
        body = self.protocol
        if body["protocol"]["mapping_id"] is None:
            body["protocol"]["mapping_id"] = mapping_id
        print(body)
        resp = requests.put(v3_protocols_url, data=json.dumps(body), headers=self.post_header)
        self.protocol = resp.json().get("protocol")
        self.write_id(self.protocol["id"], self.protocol["id"])
        if self.check_response(resp, 201):
            print("HTTP Status Code: 201\nProtocol added:")
            print(json.dumps(self.protocol, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def delete_protocol(self, protocol_id, idp_id):
        v3_protocols_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id + "/protocols/" + protocol_id
        resp = requests.delete(v3_protocols_url, headers=self.get_header)
        if self.check_response(resp, 204):
            print("HTTP Status Code: 204\nProtocol deleted:")
            print("\tId: " + protocol_id)
            os.remove("./" + protocol_id + "_id")
        else:
            print("Error, can not delete mapping: " + protocol_id)

    def get_protocol(self, protocol_id, idp_id):
        v3_protocols_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id + "/protocols/" + protocol_id
        resp = requests.get(v3_protocols_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProtocol:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")

    def get_protocols(self, idp_id):
        v3_protocols_url = self.url + "/v3/OS-FEDERATION/identity_providers/" + idp_id + "/protocols"
        resp = requests.get(v3_protocols_url, headers=self.get_header)
        if self.check_response(resp, 200):
            print("HTTP Status Code: 200\nProtocols:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("Error")


if __name__ == "__main__":

    i = Infrastructure()

    parser = argparse.ArgumentParser()

    if len(sys.argv) >= 2:

        # domains
        parser.add_argument("--domain-get", nargs=1, metavar="<domain_name>")
        parser.add_argument("--domains-get", action="store_true")
        parser.add_argument("--domain-add", action="store_true")
        parser.add_argument("--domain-delete", nargs=1, metavar="<domain_name>")
        parser.add_argument("--grant-role", nargs=3, metavar=("<domain_name>","<group_name>", "<role_name>"))

        # projects
        parser.add_argument("--project-get", nargs=1)
        parser.add_argument("--projects-get", action="store_true")
        parser.add_argument("--project-add", nargs=1, metavar="<domain_name>")
        parser.add_argument("--project-delete", nargs=1, metavar="<project_name>")

        # roles
        parser.add_argument("--role-add", action="store_true")
        parser.add_argument("--role-delete", nargs=1, metavar="<role_name>")

        # groups
        parser.add_argument("--groups-get", action="store_true")
        parser.add_argument("--group-add", nargs=1, metavar="<domain_name>")
        parser.add_argument("--group-delete", nargs=1, metavar="<group_name>")


        # identity providers
        parser.add_argument("--idp-get", nargs=1, metavar="<idp_id>")
        parser.add_argument("--idps-get", action="store_true")
        parser.add_argument("--idp-add", nargs=1, metavar="<idp_id>")
        parser.add_argument("--idp-delete", nargs=1, metavar="<idp_id>")

        # mappings
        parser.add_argument("--mapping-get", nargs=1, metavar="<mapping_id>")
        parser.add_argument("--mappings-get", action="store_true")
        parser.add_argument("--mapping-add", nargs=2, metavar=("<mapping_id>", "<group_name>"))
        parser.add_argument("--mapping-delete", nargs=1, metavar="<mapping_id>")

        # protocols
        parser.add_argument("--protocol-get", nargs=2, metavar=("<protocol_id>", "<idp_id>"))
        parser.add_argument("--protocols-get", nargs=1, metavar="<idp_id>")
        parser.add_argument("--protocol-add", nargs=3, metavar=("<protocol_id>", "<idp_id>", "<mapping_id>"))
        parser.add_argument("--protocol-delete", nargs=2, metavar=("<protocol_id>", "<idp_id>"))

        ns = parser.parse_args()

        # domains
        if ns.domain_get:
            i.get_domain(ns.domain_get[0])
        elif ns.domains_get:
            i.get_domains()
        elif ns.domain_add:
            i.add_domain()
        elif ns.domain_delete:
            i.delete_domain(ns.domain_delete[0])
        elif ns.grant_role:
            i.grant_role(ns.grant_role[0], ns.grant_role[1], ns.grant_role[2])

        # projects
        elif ns.project_get:
            i.get_project(ns.project_get[0])
        elif ns.projects_get:
            i.get_projects()
        elif ns.project_add:
            i.add_project(ns.project_add[0])

        # roles
        elif ns.role_add:
            i.add_role()
        elif ns.role_delete:
            i.delete_role(ns.role_delete[0])

        # groups
        elif ns.groups_get:
            i.get_groups()
        elif ns.group_add:
            i.add_group(ns.group_add[0])
        elif ns.group_delete:
            i.delete_group(ns.group_delete[0])

        # identity providers
        elif ns.idp_get:
            i.get_idp(ns.idp_get[0])
        elif ns.idps_get:
            i.get_idps()
        elif ns.idp_add:
            i.add_idp(ns.idp_add[0])
        elif ns.idp_delete:
            i.delete_idp(ns.idp_delete[0])

        # mappings
        elif ns.mapping_get:
            i.get_mapping(ns.mapping_get[0])
        elif ns.mappings_get:
            i.get_mappings()
        elif ns.mapping_add:
            i.add_mapping(ns.mapping_add[0], ns.mapping_add[1])
        elif ns.mapping_delete:
            i.delete_mapping(ns.mapping_delete[0])

        # protocols
        elif ns.protocol_get:
            i.get_protocol(ns.protocol_get[0], ns.protocol_get[1])
        elif ns.protocols_get:
            i.get_protocols(ns.protocols_get[0])
        elif ns.protocol_add:
            i.add_protocol(ns.protocol_add[0], ns.protocol_add[1], ns.protocol_add[2])
        elif ns.protocol_delete:
            i.delete_protocol(ns.protocol_delete[0], ns.protocol_delete[1])

    else:
        print("Usage: v3_requests.py <entity> <operation> <arguments>")