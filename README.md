**Archiving this repo because there are other better tools.** 

# pyort
Command line tool for monitoring and logging all foreign network connections(ipv4). Best way to use this tool is along with other network monitoring tools such as `iftop`

## Installation (python 2.7 or above)
`pip install pyort` 
   or 
`pip install git+https://github.com/Gananath/pyort.git`
   or
`python3.5 -m pip install pyort`

 
## Usage

###### Monitoring and Logging
Help: `pyort -h`

Start: `pyort --start`

Save: `pyort -s -Sv` (need to install sqlite manually)

Custom: `pyort -s --kind tcp6`

Silent: `pyort -s -Sv -x`

###### Database viewing 
Incidence = `pyort -d -l 100`

Ip = `pyort -d -o ip -c xxx.xxx.xxx.xxx` 

## Configuration
`config.ini` and database files exists in the directory `$HOME/.config/pyort`. 
```
db_path = database path
db_name = database name
interval = time interval for updating ip's
kind = kind of connections all,tcp,udp etc
geo_ip = for getting geo location info
project_honey_pot_key = projecthoneypot.org's api key
threat_update_count = interval for updating the threat score from projecthoneypot.org
table_format = organize the output table
version = show the version number
```
###### table_format
```
+--------+-------------+-------------------------------------------------------------------+
| Code   |     Name    |                           Description                             |
+--------+-------------+-------------------------------------------------------------------+
| r      |   Recent    | Will show the date if database enabled                            |
| l      |   Local     | Local IP                                                          |
| p      |   L Port    | Port used by the local IP                                         |
| f      |   Foregin   | Remote IP                                                         |
| fp     |   F Port    | Port used by the remote IP                                        |
| pid    |   PID       | Process ID associated with the connections                        |
| t      |   Threat    | Project honey pot's threat score                                  |
| c      |   Count     | Number of times remote ip tried to connect (only with db enabled) |
| p      |   Process   | Process associated with the connections                           |
| loc    |   Location  | Geo location of the remote ip (need Maxmind's GeoIP)              |
| fd     |   File Desc | File Descriptor (refer psutil documentation)                      |
| fam    |   Family    | Address family (refer psutil documentation)                       |
| typ    |   Type      | Address Type (refer psutil documentation)                         |
| sc     |   Status    | Connection establishment status                                   |
| do     |   Domain    | Gets Domain name if PTR exists                                    |
+--------+-------------+-------------------------------------------------------------------+
```
## Optional

###### Database
You can save the logs in a sqlite database and the `--save` option only works with sqlite installed. You can install sqlite by `pip install pysqlite` for pyhton 2.7.

###### Project Honey pot
If wanted you can also get [project honey pot's](https://www.projecthoneypot.org/) threat score for foreign ip's but needs project honey pot's api key and `pip install httpbl` then add api key to `config.ini` without quotes. This only works when `--save` option is enabled.

###### Maxmind's GeoIP
If you needed the geo location of foreign ip's first install `pip install geoip2` then in the `config.ini` file change `geo_ip =` to `geo_ip = True` without quotes.

## Notice
If anything goes wrong to pyort afer updating to a newer version of pyort then try to delete the config and database files inside `$HOME/.config/pyort/` and then reinstall the new version.
