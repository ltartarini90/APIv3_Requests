DOMAIN = {
    "domain": {
        "description": "My domain",
        "enabled": False,
        "name": "domain4"
    }
}

PROJECT = {
    "project": {
        "description": "My project",
        "domain_id": None,
        "enabled": True,
        "name": "project1"
    }
}

ROLE = {
    "role": {
        "name": "role1"
    }
}

GROUP = {
    "group": {
        "domain_id": None,
        "description": "My group",
        "name": "group1"
    }
}

IDP = {
    "identity_provider": {
        "description": "idpopen @ https://idpopen.garr.it/",
        "enabled": True
    }
}

MAPPING = {
    "mapping": {
        "rules":[
            {
                "local": [
                    {
                        "user": {
                            "name": "idpopen user"
                        }
                    },
                    {
                        "group": {
                            "id": "5e845737a3d646e6b32c173ef5a3cbe4"
                        }
                    }
                ],
                "remote": [
                    {
                        "type": "UserName",
                        "any_one_of": [
                            "openstackfederation",
                            "openstackfederation@idpopen.garr.it"
                        ]
                    }
                ]
            }
        ]
    }
}

PROTOCOL = {
    "protocol": {
        "mapping_id": None
    }
}