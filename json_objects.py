DOMAIN = {
    "domain": {
        "description": "My domain",
        "enabled": False,
        "name": "domain1"
    }
}

PROJECT = {
    "project": {
        "description": "My Project",
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
        "description": "My idp",
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
                            "name": "user"
                        }
                    },
                    {
                    "group": {
                    "id": None
                    }
                    }
                ],
                "remote": [
                    {
                        "type": "eppn",
                        "any_one_of": [
                            "user1",
                            "user2"
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