# pyort
Command line tool for monitoring and logging all foreign network connections. Best way to use this tool is along with other network monitoring tools such as `iftop`

## Installation (python 2.7)
`pip install pyort` 
   or 
`pip install git+https://github.com/Gananath/pyort.git`

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
version = show the version number
```
## Optional

###### Database
You can save the logs in a sqlite database and the `--save` option only works with sqlite installed. You can install sqlite by `pip install pysqlite` for pyhton 2.7.

###### Project Honey pot
If wanted you can also get [project honey pot's](https://www.projecthoneypot.org/) threat score for foreign ip's but needs project honey pot's api key and `pip install httpbl` then add api key to `config.ini` without quotes. This only works when `--save` option is enabled.

###### Maxmind's GeoIP
If you needed the geo location of foreign ip's then in the `config.ini` file change `geo_ip =` to `geo_ip = True` without quotes.

## Notice
If anything goes wrong afer updating to a newer version of pyort then try to delete the config and database files inside `$HOME/.config/pyort/` and then reinstall the new version.
