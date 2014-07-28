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
        "domain_id": "95f6682017514156824be98dc7fbab2c",
        "description": "My group123",
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
                            "myself@testshib.org",
                            "alterego@testshib.org"
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