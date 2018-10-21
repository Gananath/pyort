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

Custom: `pyort -s --kind tcp6`

Silent: `pyort -s -x`

###### Database
Incidence = `pyort -d -l 100`

Ip = `pyort -d -o IP -c xxx.xxx.xxx.xxx` 

## Configuration
`config.ini` and database files exists in the directory `$HOME/.config/pyort`. 
```
db_path = database path
db_name = database name
interval = time interval for updating ip's
kind = kind of connections all,tcp,udp etc
project_honey_pot_key = projecthoneypot.org's api key
threat_update_count = interval for updating the threat score from projecthoneypot.org
```
## Optional
If wanted you can also get [project honey pot's](https://www.projecthoneypot.org/) threat score for foreign ip's but needs project honey pot's api and `pip install httpbl`. Add the api key to `config.ini` without quotes.


