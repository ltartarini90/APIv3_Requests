DOMAIN = {
    "domain": {
        "description": "My domain1",
        "enabled": False,
        "name": "domain1"
    }
}

PROJECT = {
    "project": {
        "description": "Test",
        #"domain_id": "default",
        "enabled": True,
        "name": "test-project"
    }
}

ROLE = {
    "role": {
        "name": "adfs-role"
    }
}

GROUP = {
    "group": {
        "domain_id": "default",
        "description": "Test group",
        "name": "test-group"
    }
}

IDP = {
    "identity_provider": {
        "description": "CERN adfs",
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
                            "name": "adfs user"
                        }
                    },
                    {
                    "group": {
                    "id": "6aabf7cc860e401890047d9ec6336a3c"
                    }
                    }
                ],
                "remote": [
                    {
                        "type": "ADFS_LOGIN",
                        "any_one_of": [
                            "ltartari",
                            "luca.tartarini@cern.ch"
                        ]
                    }
                ]
            }
        ]
    }
}

PROTOCOL = {
    "protocol": {
        "mapping_id": "adfs_mapping"
    }
}