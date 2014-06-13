OSCARS JSON Topology Publisher
==============================

This project shares the OSCARS NMWG topology and circuit list as a JSON file.

System Requirements
-------------------
 * CentOS 6 or newer
 * Python 2.6 or newer
 * OSCARS 0.6 or newer

Installing
----------

 1. Checkout the project from git:
```
git clone https://github.com/esnet/oscars-topology-json.git ./oscars-topology-json
```
 1. Move to */opt/topology_publisher*
```
mv oscars-topology-json /opt/topology_publisher
```
 1. Edit database and XML file properties in *bin/topology_publisher.py*
```python
class EomplsIDRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    dbhost='localhost' #database host
    dbuser='oscars' #database user
    dbpass='mypass' #database password
    dbname='eomplspss' #don't change
    rmdbname='rm' #don't change
    xml_files = [ #NMWG files to publish
        "/opt/topology_publisher/topologies/esnet-cp.xml",
        "/opt/topology_publisher/topologies/esnet-ps.xml"
    ]
```
 1. Install the start-up scripts
```
mv init_scripts/topology_publisher /etc/init.d/topology_publisher
```
 1. Set to boot on start-up
```
chkconfig --add topology_publisher
chkconfig topology_publisher on
```

Running
-------

###Starting the service

```
/etc/init.d/topology-publisher start
```

###Stopping the service

```
/etc/init.d/topology-publisher stop
```
###Restarting the service

```
/etc/init.d/topology-publisher restart
```

###Checking if service is running

```
/etc/init.d/topology-publisher status

```

