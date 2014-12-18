region_endpoints = {'us-east-1'      : 's3.amazonaws.com',
                    'US'             : 's3.amazonaws.com',
                    'us-west-1'      : 's3-us-west-1.amazonaws.com',
                    'us-west-2'      : 's3-us-west-2.amazonaws.com',
                    'eu-west-1'      : 's3-eu-west-1.amazonaws.com',
                    'EU'             : 's3-eu-west-1.amazonaws.com',
                    'eu-central-1'   : 's3-eu-central-1.amazonaws.com',
                    'ap-southeast-1' : 's3-ap-southeast-1.amazonaws.com',
                    'ap-southeast-2' : 's3-ap-southeast-2.amazonaws.com',
                    'ap-northeast-1' : 's3-ap-northeast-1.amazonaws.com',
                    'sa-east-1'      : 's3-sa-east-1.amazonaws.com',
                    }

def region_endpoint(region):
    if region in region_endpoints:
        return region_endpoints[region]
    return None
