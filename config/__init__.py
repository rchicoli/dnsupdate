import json

class Config(object):
    """
    Config loads JSON config file to config variable
    Args:
        config_file: /tmp/config.json
        config: {
                "key": {
                    "rndc-key": {
                        "algorithm": "hmac-md5",
                        "secret": "63fT/4K3NrA0I9Sxo/v79A=="
                    }
                },
                "zones": {
                    "home.local": "rndc-key"
                }
            }

    """

    def __init__(self):
        self.config_file = ''
        self.config = {}
        self.verbose = False

    def parse_json(self, config_file):
        self.config_file = config_file

        with open(self.config_file) as cfg:
            self.config = json.load(cfg)
        try:
            if self.config['zones'] is not None or self.config['key'] is not None:
                # print self.config['zones']
                pass
        except KeyError:
            print "error parsing json file"
            print "key do not exist"
            exit()

        return self.config
