#!/usr/bin/env python

__author__ = 'Luca Tartarini'
__date__ = "05/08/14"
__license__ = "GPL"
__email__ = "ltartarini90@gmail.com"

import requests
import json
import json_objects
import utils
import host_url


class IdentityAPIv3:

    # constructor for the class
    def __init__(self):
        ################# APIv3 entities #################
        self.domain = json_objects.DOMAIN
        self.project = json_objects.PROJECT
        self.role = json_objects.ROLE
        self.group = json_objects.GROUP
        ################# APIv3 federation entities #################
        self.idp = json_objects.IDP
        self.mapping = json_objects.MAPPING
        self.protocol = json_objects.PROTOCOL
        ################# keystone URL #################
        self.host_url = host_url.URL
        ################# headers #################
        self.headers = utils.Headers()
        ################# token management #################
        self.auth_token = None
        self.auth_token_file = "./x_auth_token"
        ################# API strings URL #################
        self.api_version = "/v3"
        self.domains_string = "/domains/"
        self.projects_string = "/projects/"
        self.groups_string = "/groups/"
        self.roles_string = "/roles/"
        self.federation_string = "/OS-FEDERATION"
        self.idps_string = "/identity_providers/"
        self.mappings_string = "/mappings/"
        self.protocols_string = "/protocols/"
        ################# identifiers #################
        self.ids = utils.Identifiers()

    ################# check auth_token #################

    def _check_header_auth_token(self, header):
        if header["X-Auth-Token"] is None:
            header["X-Auth-Token"] = self.auth_token
        return header

    ################# configure all #################

    def configure_all(self):
        # create domain
        self.create_domain()
        print self.ids.domain_id
        # create project
        self.create_project()
        # create role
        self.create_role()
        # create group
        self.create_group()
        # grant role
        domain_name = utils.read_domain_name_by_id(self.list_domains().json(), self.ids.domain_id)
        group_name = utils.read_group_name_by_id(self.list_groups().json(), self.ids.group_id)
        role_name = utils.read_role_name_by_id(self.list_roles().json(), self.ids.role_id)
        self.grant_role_group_domain(domain_name, self.ids.domain_id, group_name, self.ids.group_id, role_name,
                                     self.ids.role_id)
        # create identity provider
        idp_id = raw_input("Insert identity_provider_id: ")
        self.create_idp(idp_id)
        # create mapping
        mapping_id = raw_input("Insert mapping_id: ")
        self.create_mapping(mapping_id)
        # create protocol
        protocol_id = raw_input("Insert protocol_id: ")
        self.create_protocol(protocol_id, idp_id)

    ################# domains #################

    def create_domain(self):
        url = self.host_url + self.api_version + self.domains_string
        header = self.headers.header_post
        header = self._check_header_auth_token(header)
        body = self.domain
        resp = requests.post(url, data=json.dumps(body), headers=header)
        if utils.check_response(resp, 201):
            self.domain = (resp.json().get("domain"))
            print("HTTP Status Code: 201\nDomain created:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.domain_id = self.domain["id"]

    def update_domain(self, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        header = self.headers.header_patch
        header = self._check_header_auth_token(header)
        body = self.domain
        resp = requests.patch(url, data=json.dumps(body), headers=header)
        if utils.check_response(resp, 200):
            self.domain = resp.json().get("domain")
            print("HTTP Status Code: 200\nDomain updated:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def delete_domain(self, domain_name, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        header = self.headers.header_delete
        header = self._check_header_auth_token(header)
        resp = requests.delete(url, headers=header)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nDomain deleted:")
            print("\tName: " + domain_name + "\n\tid: " + domain_id)
        else:
            utils.expose_reason(resp)

    def get_domain(self, domain_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id
        header = self.headers.header_get
        header = self._check_header_auth_token(header)
        resp = requests.get(url, headers=header)
        if utils.check_response(resp, 200):
            self.domain = resp.json().get("domain")
            print("HTTP Status Code: 200\nDomain:")
            print(json.dumps(self.domain, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_domains(self):
        url = self.host_url + self.api_version + self.domains_string
        header = self.headers.header_get
        header = self._check_header_auth_token(header)
        resp = requests.get(url, headers=header)
        return resp

    def grant_role_group_domain(self, domain_name, domain_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id + self.groups_string + group_id + \
              self.roles_string + role_id
        header = self.headers.header_put
        header = self._check_header_auth_token(header)
        resp = requests.put(url, headers=header)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nGranted role to group on domain:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Domain:\n\tname: " + domain_name + "\n\tid: " + domain_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
        else:
            utils.expose_reason(resp)

    def revoke_role_group_domain(self, domain_name, domain_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.domains_string + domain_id + self.groups_string + group_id + \
              self.roles_string + role_id
        header = self.headers.header_delete
        header = self._check_header_auth_token(header)
        resp = requests.put(url, headers=header)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nRevoked role to group on domain:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Domain:\n\tname: " + domain_name + "\n\tid: " + domain_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
        else:
            utils.expose_reason(resp)

    ################# projects #################

    def create_project(self):
        url = self.host_url + self.api_version + self.projects_string
        body = self.project
        if body["project"]["domain_id"] is None:
            if self.ids.domain_id is None:
                domain_name = raw_input("Insert domain name: ")
                domain_id = utils.read_domain_id_by_name(self.list_domains().json(), domain_name)
                body["project"]["domain_id"] = domain_id
            else:
                body["project"]["domain_id"] = self.ids.domain_id
        resp = requests.post(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.project = (resp.json().get("project"))
            print("HTTP Status Code: 201\nProject created:")
            print(json.dumps(self.project, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.project_id = self.project["id"]

    def update_project(self, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        body = self.project
        resp = requests.patch(url, data=json.dumps(body), headers=headers.HEADER_PATCH)
        if utils.check_response(resp, 200):
            self.project = resp.json().get("project")
            print("HTTP Status Code: 200\nProject updated:")
            print(json.dumps(self.project, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def delete_project(self, project_name, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        resp = requests.delete(url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nProject deleted:")
            print("\tName: " + project_name + "\n\tid: " + project_id)
        else:
            utils.expose_reason(resp)

    def get_project(self, project_id):
        url = self.host_url + self.api_version + self.projects_string + project_id
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            print("HTTP Status Code: 200\nProject:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_projects(self):
        v3_projects_url = self.host_url + self.api_version + self.projects_string
        resp = requests.get(v3_projects_url, headers=headers.HEADER_GET)
        return resp

    def list_projects_federation(self):
        v3_projects_url = self.host_url + self.api_version + self.federation_string + self.projects_string
        header = self.header_get
        if header["X-Auth-Token"] is None:
            print("None")
            header["X-Auth-Token"] = self.auth_token
        resp = requests.get(v3_projects_url, headers=header)
        return resp

    def grant_role_group_project(self, project_name, project_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.projects_string + project_id + self.groups_string + group_id + \
              self.roles_string + role_id
        resp = requests.put(url, headers=headers.HEADER_PUT)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nGranted role to group on project:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
            print("Project:\n\tname: " + project_name + "\n\tid: " + project_id)
        else:
            utils.expose_reason(resp)

    def revoke_role_group_project(self, project_name, project_id, group_name, group_id, role_name, role_id):
        url = self.host_url + self.api_version + self.projects_string + project_id + self.groups_string + group_id + \
              self.roles_string + role_id
        resp = requests.put(url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nRevoked role to group on project:")
            print("Role:\n\tname: " + role_name + "\n\tid: " + role_id)
            print("Group:\n\tname: " + group_name + "\n\tid: " + group_id)
            print("Project:\n\tname: " + project_name + "\n\tid: " + project_id)
        else:
            utils.expose_reason(resp)

    ################# roles #################

    def create_role(self):
        url = self.host_url + self.api_version + self.roles_string
        body = self.role
        resp = requests.post(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.role = resp.json().get("role")
            print("HTTP Status Code: 201\nRole created:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.role_id = self.role["id"]

    def update_role(self, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        body = self.role
        resp = requests.patch(url, data=json.dumps(body), headers=headers.HEADER_PATCH)
        if utils.check_response(resp, 200):
            self.role == resp.json().get("role")
            print("HTTP Status Code: 200\nRole updated:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def delete_role(self, role_name, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        resp = requests.delete(url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nRole deleted:")
            print("\tName: " + role_name + "\n\tid: " + role_id)
        else:
            utils.expose_reason(resp)

    def get_role(self, role_id):
        url = self.host_url + self.api_version + self.roles_string + role_id
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            self.role = resp.json().get("role")
            print("HTTP Status Code: 200\nRole:")
            print(json.dumps(self.role, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_roles(self):
        url = self.host_url + self.api_version + self.roles_string
        resp = requests.get(url, headers=headers.HEADER_GET)
        return resp

    ################# groups #################

    def create_group(self):
        url = self.host_url + self.api_version + self.groups_string
        body = self.group
        if body["group"]["domain_id"] is None:
            if self.ids.domain_id is None:
                domain_name = raw_input("Insert domain name: ")
                domain_id = utils.read_domain_id_by_name(self.list_groups().json(), domain_name)
                body["group"]["domain_id"] = domain_id
            else:
                body["group"]["domain_id"] = self.ids.domain_id
        resp = requests.post(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.group = resp.json().get("group")
            print("HTTP Status Code: 201\nGroup created:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.group_id = self.group["id"]

    def update_group(self, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        body = self.group
        resp = requests.patch(url, data=json.dumps(body), headers=headers.HEADER_PATCH)
        if utils.check_response(resp, 200):
            self.group = (resp.json().get("group"))
            print("HTTP Status Code: 200\nGroup updated:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def delete_group(self, group_name, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        resp = requests.delete(url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nGroup deleted:")
            print("\tName: " + group_name + "\n\tid: " + group_id)
        else:
            utils.expose_reason(resp)

    def get_group(self, group_id):
        url = self.host_url + self.api_version + self.groups_string + group_id
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            self.group = resp.json().get("group")
            print("HTTP Status Code: 200\nGroup:")
            print(json.dumps(self.group, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_groups(self):
        url = self.host_url + self.api_version + self.groups_string
        resp = requests.get(url, headers=headers.HEADER_GET)
        return resp

    ################# identity providers #################

    def create_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        body = self.idp
        resp = requests.put(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.idp = resp.json().get("identity_provider")
            print("HTTP Status Code: 201\nIdP created:")
            print(json.dumps(self.idp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.idp_id = idp_id

    def delete_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        resp = requests.delete(url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nIdentity provider deleted:")
            print("\tId: " + idp_id)
        else:
            utils.expose_reason(resp)

    def get_idp(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            self.idp = resp.json().get("identity_provider")
            print("HTTP Status Code: 200\nIdentity provider:")
            print(json.dumps(self.idp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_idps(self):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            print("HTTP Status Code: 200\nIdentity providers:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    ################# mappings #################

    def create_mapping(self, mapping_id):
        url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        body = self.mapping
        if body["mapping"]["rules"][0]["local"][1]["group"]["id"] is None:
            if self.ids.group_id is None:
                group_name = raw_input("Insert group name: ")
                group_id = utils.read_group_id_by_name(self.list_groups().json(), group_name)
                body["mapping"]["rules"][0]["local"][1]["group"]["id"] = group_id
            else:
                body["mapping"]["rules"][0]["local"][1]["group"]["id"] = self.ids.group_id
        resp = requests.put(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 201\nMapping created:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.mapping_id = mapping_id

    def delete_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        resp = requests.delete(v3_mappings_url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nMapping deleted:")
            print("\tId: " + mapping_id)
        else:
            utils.expose_reason(resp)

    def get_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        resp = requests.get(v3_mappings_url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 200\nMapping:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_mappings(self):
        url = self.host_url + self.api_version + self.federation_string + self.mappings_string
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            print("HTTP Status Code: 200\nMappings:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def update_mapping(self, mapping_id):
        v3_mappings_url = self.host_url + self.api_version + self.federation_string + self.mappings_string + mapping_id
        body = self.mapping
        resp = requests.patch(v3_mappings_url, data=json.dumps(body), headers=headers.HEADER_PATCH)
        if utils.check_response(resp, 200):
            self.mapping = resp.json().get("mapping")
            print("HTTP Status Code: 200\nMapping updated:")
            print(json.dumps(self.mapping, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    ################# protocols #################

    def create_protocol(self, protocol_id, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
              self.protocols_string + protocol_id
        body = self.protocol
        if body["protocol"]["mapping_id"] is None:
            if self.ids.mapping_id is None:
                mapping_id = raw_input("Insert mapping_id: ")
                body["protocol"]["mapping_id"] = mapping_id
            else:
                body["protocol"]["mapping_id"] = self.ids.mapping_id
        print(body)
        resp = requests.put(url, data=json.dumps(body), headers=headers.HEADER_POST)
        if utils.check_response(resp, 201):
            self.protocol = resp.json().get("protocol")
            print("HTTP Status Code: 201\nProtocol created:")
            print(json.dumps(self.protocol, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)
        self.ids.protocol_id = protocol_id

    def delete_protocol(self, protocol_id, idp_id):
        v3_protocols_url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
                           self.protocols_string + protocol_id
        resp = requests.delete(v3_protocols_url, headers=headers.HEADER_DELETE)
        if utils.check_response(resp, 204):
            print("HTTP Status Code: 204\nProtocol deleted:")
            print("\tId: " + protocol_id)
        else:
            utils.expose_reason(resp)

    def get_protocol(self, protocol_id, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
              self.protocols_string + protocol_id
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            self.protocol = resp.json().get("protocol")
            print("HTTP Status Code: 200\nProtocol:")
            print(json.dumps(self.protocol, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    def list_protocols(self, idp_id):
        url = self.host_url + self.api_version + self.federation_string + self.idps_string + idp_id + \
              self.protocols_string
        resp = requests.get(url, headers=headers.HEADER_GET)
        if utils.check_response(resp, 200):
            print("HTTP Status Code: 200\nProtocols:")
            print(json.dumps(resp.json(), sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            utils.expose_reason(resp)

    ################# tokens #################

    def set_auth_token(self, token):
        token_file = open(self.auth_token_file,"w")
        token_file.write(token)
        token_file.close()

    def get_auth_token(self):
        token_file = open(self.auth_token_file,"r")
        self.auth_token = token_file.read()
        token_file.close()
        return self.auth_token