#!/usr/bin/env python

__author__ = 'Luca Tartarini'
__date__ = "20/07/14"
__license__ = "GPL"
__email__ = "ltartarini90@gmail.com"

import identityAPIv3
import argparse
import utils


def build_parser():

    parser = argparse.ArgumentParser(description='APIv3Parser')

    parser.add_argument("-v", "--verbose", action="store_true")

    ################# configure all #################

    parser.add_argument("--configure-all", action="store_true")

    ################# domains #################

    parser.add_argument("--domain-get", nargs=1, metavar="<domain_name>")
    parser.add_argument("--domains-list", action="store_true")
    parser.add_argument("--domain-create", action="store_true")
    parser.add_argument("--domain-update", nargs=1, metavar="<domain_name>")
    parser.add_argument("--domain-delete", nargs=1, metavar="<domain_name>")
    parser.add_argument("--grant-role-group-domain", nargs=3, metavar=("<domain_name>", "<group_name>",
                                                                       "<role_name>"))
    parser.add_argument("--revoke-role-group-domain", nargs=3, metavar=("<domain_name>", "<group_name>",
                                                                        "<role_name>"))

    ################# projects #################

    parser.add_argument("--project-get", nargs=1, metavar="<project_name>")
    parser.add_argument("--projects-list", action="store_true")
    parser.add_argument("--projects-list-fed", action="store_true")
    parser.add_argument("--project-create", action="store_true")
    parser.add_argument("--project-update", nargs=1, metavar="<project_name>")
    parser.add_argument("--project-delete", nargs=1, metavar="<project_name>")
    parser.add_argument("--grant-role-group-project", nargs=3, metavar=("<project_name>", "<group_name>",
                                                                        "<role_name>"))
    parser.add_argument("--revoke-role-group-project", nargs=3, metavar=("<project_name>", "<group_name>",
                                                                         "<role_name>"))

    ################# roles #################

    parser.add_argument("--role-get", nargs=1, metavar="<role_name>")
    parser.add_argument("--roles-list", action="store_true")
    parser.add_argument("--role-create", action="store_true")
    parser.add_argument("--role-update", nargs=1, metavar="<role_name>")
    parser.add_argument("--role-delete", nargs=1, metavar="<role_name>")

    ################# groups #################

    parser.add_argument("--group-get", nargs=1, metavar="<group_name>")
    parser.add_argument("--groups-list", action="store_true")
    parser.add_argument("--group-create", action="store_true")
    parser.add_argument("--group-update", nargs=1, metavar="<group_name>")
    parser.add_argument("--group-delete", nargs=1, metavar="<group_name>")

    ################# identity providers #################

    parser.add_argument("--idp-get", nargs=1, metavar="<idp_id>")
    parser.add_argument("--idps-list", action="store_true")
    parser.add_argument("--idp-create", nargs=1, metavar="<idp_id>")
    parser.add_argument("--idp-delete", nargs=1, metavar="<idp_id>")

    ################# mappings #################

    parser.add_argument("--mapping-get", nargs=1, metavar="<mapping_id>")
    parser.add_argument("--mappings-list", action="store_true")
    parser.add_argument("--mapping-create", nargs=1, metavar="<mapping_id>")
    parser.add_argument("--mapping-delete", nargs=1, metavar="<mapping_id>")
    parser.add_argument("--mapping-update", nargs=1, metavar="<mapping_id>")

    ################# protocols #################

    parser.add_argument("--protocol-get", nargs=2, metavar=("<protocol_id>", "<idp_id>"))
    parser.add_argument("--protocols-list", nargs=1, metavar="<idp_id>")
    parser.add_argument("--protocol-create", nargs=2, metavar=("<protocol_id>", "<idp_id>"))
    parser.add_argument("--protocol-delete", nargs=2, metavar=("<protocol_id>", "<idp_id>"))

    ################# token #################

    parser.add_argument("--token-set", nargs=1, metavar="<token>")
    parser.add_argument("--token-get", action="store_true")

    return parser


def main():
    i = identityAPIv3.IdentityAPIv3()

    p = build_parser()
    args = p.parse_args()

    if args.verbose:
        utils.verbose = True
        # TODO

    ################# token-set #################

    if args.token_set:
        i.set_auth_token(args.token_set[0])
    else:

        ################# token check #################

        # load the auth_token - the token configured in x_auth_token has more priority than the token/s configured in
        # headers,py
        if i.get_auth_token():
            i.auth_token = i.get_auth_token()
            i.headers.header_post["X-Auth-Token"] = i.auth_token
            i.headers.header_get["X-Auth-Token"] = i.auth_token
            i.headers.header_delete["X-Auth-Token"] = i.auth_token
            i.headers.header_patch["X-Auth-Token"] = i.auth_token
            i.headers.header_put["X-Auth-Token"] = i.auth_token
        # check if headers.py is correctly configured
        elif (i.headers.header_post["X-Auth-Token"] is i.headers.header_get["X-Auth-Token"] is
                i.headers.header_delete["X-Auth-Token"] is i.headers.header_put["X-Auth-Token"] is
                i.headers.header_patch["X-Auth-Token"]) and i.headers.header_post["X-Auth-Token"] is not None:
            i.set_auth_token(i.headers.header_post["X-Auth-Token"])
        else:
            print("Set the auth_token!")
            exit()

        ################# token-get #################

        if args.token_get:
            print(i.get_auth_token())

        ################# configure all #################

        elif args.configure_all:
            i.configure_all()

        ################# domains #################

        elif args.domain_get:
            domain_identifier = utils.read_domain_id_by_name(i.list_domains().json(), args.domain_get[0])
            i.get_domain(domain_identifier)
        elif args.domains_list:
            response = i.list_domains()
            utils.print_domains(response)
        elif args.domain_create:
            i.create_domain()
        elif args.domain_update:
            domain_identifier = utils.read_domain_id_by_name(i.list_domains().json(), args.domain_update[0])
            i.update_domain(domain_identifier)
        elif args.domain_delete:
            domain_identifier = utils.read_domain_id_by_name(i.list_domains().json(), args.domain_delete[0])
            i.delete_domain(args.domain_delete[0], domain_identifier)
        elif args.grant_role_group_domain:
            domain_identifier = utils.read_domain_id_by_name(i.list_domains().json(), args.grant_role_group_domain[0])
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.grant_role_group_domain[1])
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.grant_role_group_domain[2])
            i.grant_role_group_domain(args.grant_role_group_domain[0], domain_identifier, args.grant_role_group_domain[1],
                                      group_identifier, args.grant_role_group_domain[2], role_identifier)
        elif args.revoke_role_group_domain:
            domain_identifier = utils.read_domain_id_by_name(i.list_domains().json(), args.revoke_role_group_domain[0])
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.revoke_role_group_domain[1])
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.revoke_role_group_domain[2])
            i.revoke_role_group_domain(args.revoke_role_group_domain[0], domain_identifier,
                                       args.revoke_role_group_domain[1], group_identifier, args.revoke_role_group_domain[2],
                                       role_identifier)

        ################# projects #################

        elif args.project_get:
            project_identifier = utils.read_project_id_by_name(i.list_projects().json(), args.project_get[0])
            i.get_project(project_identifier)
        elif args.projects_list:
            response = i.list_projects()
            utils.print_projects(response)
        elif args.projects_list_fed:
            response = i.list_projects_federation()
            utils.print_projects(response)
        elif args.project_create:
            i.create_project()
        elif args.project_update:
            project_identifier = utils.read_project_id_by_name(i.list_projects().json(), args.project_update[0])
            i.update_project(project_identifier)
        elif args.project_delete:
            project_identifier = utils.read_project_id_by_name(i.list_projects().json(), args.project_delete[0])
            i.delete_project(args.project_delete[0], project_identifier)
        elif args.grant_role_group_project:
            project_identifier = utils.read_project_id_by_name(i.list_projects().json(), args.grant_role_group_project[0])
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.grant_role_group_project[1])
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.grant_role_group_project[2])
            i.grant_role_group_project(args.grant_role_group_project[0], project_identifier,
                                       args.grant_role_group_project[1], group_identifier, args.grant_role_group_project[2],
                                       role_identifier)
        elif args.revoke_role_group_project:
            project_identifier = utils.read_project_id_by_name(i.list_projects().json(), args.revoke_role_group_project[0])
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.revoke_role_group_project[1])
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.revoke_role_group_project[2])
            i.revoke_role_group_project(args.revoke_role_group_project[0], project_identifier,
                                        args.revoke_role_group_project[1], group_identifier,
                                        args.revoke_role_group_project[2], role_identifier)

        ################# roles #################

        elif args.role_get:
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.role_get[0])
            i.get_role(role_identifier)
        elif args.roles_list:
            response = i.list_roles()
            utils.print_roles(response)
        elif args.role_create:
            i.create_role()
        elif args.role_update:
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.role_update[0])
            i.update_role(role_identifier)
        elif args.role_delete:
            role_identifier = utils.read_role_id_by_name(i.list_roles().json(), args.role_delete[0])
            i.delete_role(args.role_delete[0], role_identifier)

        ################# groups #################

        elif args.group_get:
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.group_get[0])
            i.get_group(group_identifier)
        elif args.groups_list:
            response = i.list_groups()
            utils.print_roles(response)
        elif args.group_create:
            i.create_group()
        elif args.group_update:
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.group_update[0])
            i.update_group(group_identifier)
        elif args.group_delete:
            group_identifier = utils.read_group_id_by_name(i.list_groups().json(), args.group_delete[0])
            i.delete_group(args.group_delete[0], group_identifier)

        ################# identity providers #################

        elif args.idp_get:
            i.get_idp(args.idp_get[0])
        elif args.idps_list:
            i.list_idps()
        elif args.idp_create:
            i.create_idp(args.idp_create[0])
        elif args.idp_delete:
            i.delete_idp(args.idp_delete[0])

        ################# mappings #################

        elif args.mapping_get:
            i.get_mapping(args.mapping_get[0])
        elif args.mappings_list:
            i.list_mappings()
        elif args.mapping_create:
            i.create_mapping(args.mapping_create[0])
        elif args.mapping_delete:
            i.delete_mapping(args.mapping_delete[0])
        elif args.mapping_update:
            i.update_mapping(args.mapping_modify[0])

        ################# protocols #################

        elif args.protocol_get:
            i.get_protocol(args.protocol_get[0], args.protocol_get[1])
        elif args.protocols_list:
            i.list_protocols(args.protocols_get[0])
        elif args.protocol_create:
            i.create_protocol(args.protocol_create[0], args.protocol_create[1])
        elif args.protocol_delete:
            i.delete_protocol(args.protocol_delete[0], args.protocol_delete[1])

        exit()

if __name__ == '__main__':
    main()