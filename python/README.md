# Python OA Utils
There are two python scripts that can be used to query process groups based on different criteria (MZ, Tag, name, host) and then enable or disable the OA features for Code Level vulnerabilities. 

## How to use

### [dt-entities.py](dt-entities.py)
First get the list of PGs for which the OA feature should be toggled using the [dt-entities.py](dt-entities.py) script. 

Usage (can be displayed using the --help option)
```bash 
usage: dt-entities.py [-h] -e ENVIRONMENT -t TOKEN [--tag TAG] [--mz MZ] [--host HOST] [--name NAME]

options:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --env ENVIRONMENT
                        The Dynatrace Environment to query
  -t TOKEN, --token TOKEN
                        The Dynatrace API Token to use
  --tag TAG             Process Group Tag to filter by
  --mz MZ               Management Zone to filter by
  --host HOST           Management Zone to filter by
  --name NAME           Filters by the name of the PG, uses a startswith logic
```

#### Examples
Get all PGs for a given Management Zone
```bash
python3 dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --mz "Unguard"
```

Get PGs based on the name 
```bash
python3 dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --name "microblog"
```

Combine several filters
```bash
python3 dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --mz "Unguard" --name "microblog"
```

The result will be a comma separated list of PGs:
```CSV
PROCESS_GROUP-8469F7BDC9D1BDC8,microblog-service.unguard, HOST-9FE4E8F23E9B5340 HOST-520AC7683F7D9960
PROCESS_GROUP-8F62F48713E9AA48,microblog-service.unguard-local, HOST-9FE4E8F23E9B5340
```

To use this with the second script, they should be written to a file
```bash
python3 dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --mz "Unguard" --name "microblog" > pgs.csv
```

### [dt-settings.py](dt-settings.py)
Using the [dt-settings.py](dt-settings.py) script, the OA features can be toggled, based on the entities retrieved by the first script. 

Usage 
```bash
usage: dt-settings.py [-h] -e ENVIRONMENT -t TOKEN [-p PROCESS_GROUPS [PROCESS_GROUPS ...]] [-f FILE] command

positional arguments:
  command

options:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --env ENVIRONMENT
                        The Dynatrace Environment to query
  -t TOKEN, --token TOKEN
                        The Dynatrace API Token to use
  -p PROCESS_GROUPS [PROCESS_GROUPS ...], --process-groups PROCESS_GROUPS [PROCESS_GROUPS ...]
                        List of Process Group IDs
  -f FILE, --file FILE  CSV file containing the Process Group in the first column (no header)
```
The command supports
- `enable` to enable the OA feature
- `disable` to disable it again
- `list` to show the status

#### Examples
Enable it for PGs stored in CSV file (see step above to generate the CSV):
```bash
python3 enable dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --file pgs.csv"
```
Disable it again
```bash
python3 disable dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --file pgs.csv"
```
Show the status
```bash
python3 list dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX --file pgs.csv"
```
Instead of a CSV, a list of PGs can also be provided
```bash
python3 list dt-entities.py -e https://XXX.dynatrace.com -t dt0c01.XXX -p PROCESS_GROUP_1,PROCESS_GROUPS_2,..."
```
