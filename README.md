# bgp-hijacks-classifier

- `collectors.py`: collects historical AS paths, corresponding AS hegemony scores, and all announced IP prefixes for given events
  - `hegemony.py`: gets AS hegemony from Internet Health Report
  - `histobgpstream.py`: gets AS paths and IP prefixes from CAIDA BGPStream
- `datasets`: list of hijack events
- `collections`: pickle files of each event in `datasets`
