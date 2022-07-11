INDICATOR_PARAM_MAP = {'FileHash-SHA1': 'file:hashes.\'SHA-1\'', 'FileHash-SHA256': 'file:hashes.\'SHA-256\'',
                       'FileHash-MD5': 'file:hashes.MD5', 'Domain': 'domain-name:value', 'URL': 'url:value',
                       'IPv4 Address': 'ipv4-addr:value', 'IP Address': 'ipv4-addr:value',
                       'IPv6 Address': 'ipv6-addr:value', 'Email Address': 'email-message:sender_ref.value',
                       'Email Address': 'email-message:from_ref.value', 'Host': 'domain-name:value',
                       'Registry': 'windows-registry-key:key', 'User': 'user-account:account_login',
                       'User': 'user-account:value', 'File': 'file:name', 'Process': 'process:name'}

REPUTATION_MAP = {'Suspicious': '/api/3/picklists/50bfd06c-9aff-4f7d-b6d9-821339e31fe7',
                  'Malicious': '/api/3/picklists/7074e547-7785-4979-be32-c6d0c863e4bd',
                  'No Reputation Available': '/api/3/picklists/9a611980-1b5e-4ae9-8062-eb2c0c433cff',
                  'TBD': '/api/3/picklists/ae98ebc6-beef-4882-9980-1d88fc6d87cd',
                  'Good': '/api/3/picklists/b19b42aa-aee4-47df-9cda-894537dacb2a'}

TLP_MAP = {'Red': '/api/3/picklists/0472d368-bd15-4f52-a119-d403470cbe43',
           'Amber': '/api/3/picklists/7bff95b7-6438-4b01-b23a-0fe8cb5b33d3',
           'Green': '/api/3/picklists/47004ad3-721e-43e0-b729-2ad8ee6441c0',
           'White': '/api/3/picklists/815d21f7-787b-4480-8009-558aa64fe776'}