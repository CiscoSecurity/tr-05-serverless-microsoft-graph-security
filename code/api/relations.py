def network_connections(data):
    return [
        {
            'origin': data['vendorInformation']['provider'],
            'related': {
                'type': 'domain',
                'value': connection['destinationDomain']
            },
            'relation': 'Connected_To',
            'source': {
                'type': 'ip',
                'value': connection['sourceAddress']
            }
        }
        for connection in data['networkConnections']
        if (
            connection['destinationDomain'] is not None and
            connection['sourceAddress'] is not None
        )
    ]


def file_states(data):
    return [
        {
            "origin": data["vendorInformation"]["provider"],
            "related": {
                "type": "sha256",
                "value": state['fileHash']['hashValue']
            },
            "relation": "File_Name_Of",
            "source": {
                "type": "file_name",
                "value": state['name']
            }
        }
        for state in data['fileStates']
        if (
            state['name'] is not None and
            state['fileHash'] is not None and
            state['fileHash']['hashValue'] is not None
        )
    ] + [
        {
            "origin": data["vendorInformation"]["provider"],
            "related": {
                "type": "sha256",
                "value": state['fileHash']['hashValue']
            },
            "relation": "File_Path_Of",
            "source": {
                "type": "file_path",
                "value": state['path']
            }
        }
        for state in data['fileStates']
        if (
            state['path'] is not None and
            state['fileHash'] is not None and
            state['fileHash']['hashValue'] is not None
        )
    ]
