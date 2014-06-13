#!/usr/bin/env python

"""
Script that spawns an HTTP daemon capable of accepting requests and querying the 'eomplspss'
mysql database in OSCARS. It returns the contents of srl table as JSON. That JSON can then 
be used by scripts like the one at https://stats.es.net/cgi-bin/topology.cgi to get the
IDs used by network hardware to identify circuits
"""

import BaseHTTPServer
import MySQLdb
import json
import xml.etree.ElementTree as ET
import sys

"""
Class that handles HTTP requests by querying the mysql database and returning EOMPLS PSS
dataplane ids as JSON
"""
class EomplsIDRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    dbhost='localhost'
    dbuser='oscars'
    dbpass='mypass'
    dbname='eomplspss'
    rmdbname='rm'
    xml_files = [
        "/opt/topology_publisher/topologies/esnet-cp.xml",
        "/opt/topology_publisher/topologies/esnet-ps.xml"
    ]
    
    def do_GET(self):
        con = 0;
        http_status=200
        http_body=""
        domains = []
        dataplane_ids = {};
        circuits = []

        try:
            # Parse XML topologies
            for xml_file in self.xml_files:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for child in root:
                    if "domain" == self.normalize_tag(child.tag):
                        domains.append(self.parse_domain(child))
            
            #Query database for circuit information        
            ##get database ids
            con = MySQLdb.connect(self.dbhost, self.dbuser, self.dbpass, self.dbname)
            cur = con.cursor()
            cur.execute("SELECT gri, resource, scope FROM srl")
            rows = cur.fetchall()
            for row in rows:
                if row[0] not in dataplane_ids:
                    dataplane_ids[row[0]] = []
                dataplane_ids[row[0]].append({'resource':  row[1], 'scope': row[2]})
            
            ##get reservations
            rmcon = MySQLdb.connect(self.dbhost, self.dbuser, self.dbpass, self.rmdbname)
            rmcur = rmcon.cursor()
            rmcur.execute("SELECT id, globalReservationId, description, bandwidth, startTime, endTime FROM reservations WHERE status in ('ACTIVE', 'RESERVED')")
            resvrows = rmcur.fetchall()
            for rmcur in resvrows:
                circuit_obj = {
                    'id': self.generate_circuit_id(rmcur[1]),
                    'name': rmcur[1],
                    'description': rmcur[2],
                    'capacity': int(rmcur[3]),
                    'start': int(rmcur[4]),
                    'end': int(rmcur[5])
                }
                pathcur = rmcon.cursor()
                pathcur.execute("SELECT pe.id, pe.urn FROM stdConstraints " +
                    "AS sc INNER JOIN paths AS p ON p.id=sc.pathId INNER JOIN pathElems AS " +
                    "pe ON pe.pathId=p.id WHERE sc.constraintType='reserved' AND sc.reservationId=%d ORDER BY pe.seqNumber" % rmcur[0])
                pathrows = pathcur.fetchall()
                forwardPath = []
                reversePath = []
                for pathrow in pathrows:
                    urn = self.format_port_urn(pathrow[1])
                    pepcur = rmcon.cursor()
                    pepcur.execute("SELECT value FROM pathElemParams WHERE pathElemId=%d AND type = 'vlanRangeAvailability'" % pathrow[0])
                    peprows = pepcur.fetchall()
                    if len(peprows) > 0:
                        urn = "%s.%s" % (urn, peprows[0][0])
                    forwardPath.append(urn)
                    reversePath.insert(0, urn)
                fwdpathid = self.generate_segment_id(rmcur[1], False)
                revpathid = self.generate_segment_id(rmcur[1], True)
                circuit_obj["segment_ids"] = [fwdpathid, revpathid]
                circuit_obj["segments"] = [{'id': fwdpathid, 'ports': forwardPath}, {'id': revpathid, 'ports': reversePath}]
                if rmcur[1] in dataplane_ids:
                    circuit_obj["dataplane_ids"] = dataplane_ids[rmcur[1]]
                circuits.append(circuit_obj)
            http_body = json.dumps({
                'status': 'success',
                'domains': domains,
                'circuits': circuits
            })
        except MySQLdb.Error, e:
            http_status = 500
            http_body = "MySQL Error: %d - %s" % (e.args[0], e.args[1])
        except:
            http_status = 500
            http_body = "Error: %s" % str(sys.exc_info()[1])
        finally:
            if con:
                con.close()
        
        #Output HTTP response
        self.send_response(http_status)
        self.end_headers()
        self.wfile.write(http_body)
        return
    
    def normalize_tag(self, name):
        if name[0] == "{":
            uri, tag = name[1:].split("}")
            return tag.lower()
        else:
            return name.lower()
    
    def parse_domain(self, domain):
        domainobj = {};
        domainobj["id"] = domain.attrib["id"]
        domainobj["nodes"] = []
        for child in domain:
            if "node" == self.normalize_tag(child.tag):
                domainobj["nodes"].append(self.parse_node(child))
        
        return domainobj
    
    def parse_node(self, node):
        nodeobj = {}
        fields = {
            'address': 'address',
            'name': 'name',
            'description': 'description',
            'hostname': 'hostName',
            'latitude': 'latitude',
            'longitude': 'longitude',
        }
        nodeobj["id"] = node.attrib["id"]
        nodeobj["ports"] = []
        for child in node:
            tag = self.normalize_tag(child.tag)
            if tag in fields:
                nodeobj[fields[tag]] = child.text if child.text != None else ""
            elif tag == "port":
                nodeobj["ports"].append(self.parse_port(child))
        
        return nodeobj
    
    def parse_port(self, port):
        portobj = {}
        fields = {
            'capacity': 'capacity', 
            'ifname': 'ifName', 
            'ifdescription': 'ifDescription', 
            'ipaddress': 'ipAddress', 
            'netmask': 'netmask', 
            'maximumreservablecapacity': 'maximumReservableCapacity',
            'minimumReservablecapacity': 'minimumReservableCapacity',
            'granularity': 'granularity',
        }
        portobj["id"] = port.attrib["id"]
        portobj["links"] = []
        for child in port:
            tag = self.normalize_tag(child.tag)
            if tag in fields:
                portobj[fields[tag]] = child.text if child.text != None else ""
            elif tag == "link":
                portobj["links"].append(self.parse_link(child))
            elif tag == "relation":
                self.parse_port_relation(child, portobj)
        
        return portobj
    
    def parse_link(self, link):
        linkobj = {}
        fields = {
            'remotelinkid': 'remoteLinkId',
            'trafficengineeringmetric': 'trafficEngineeringMetric',
            'capacity': 'capacity', 
            'maximumreservablecapacity': 'maximumReservableCapacity',
            'minimumreservablecapacity': 'minimumReservableCapacity',
            'granularity': 'granularity',
        }
        linkobj["id"] = link.attrib["id"]
        if "type" in link.attrib:
            linkobj["type"] = link.attrib["type"]
        else:
            linkobj["type"] = None
        for child in link:
            tag = self.normalize_tag(child.tag)
            if tag in fields:
                linkobj[fields[tag]] = child.text if child.text != None else ""
            elif tag == "name":
                linkobj["name"] = child.text
                linkobj["nameType"] = child.attrib["type"]
            elif tag == "switchingcapabilitydescriptors":
                self.parse_link_swcap(child, linkobj)
            elif tag == "relation":
                self.parse_link_relation(child, linkobj)
        
        return linkobj
    
    def parse_link_swcap(self, swcap, linkobj):
        fields = {
            'switchingcaptype': 'switchingcapType', 
            'encodingtype': 'encodingType',
        }
        for child in swcap:
            tag = self.normalize_tag(child.tag)
            if tag in fields:
                linkobj[fields[tag]] = child.text if child.text != None else ""
            elif tag == "switchingcapabilityspecificinfo":
                self.parse_link_swcap_info(child, linkobj)

    def parse_link_swcap_info(self, swcapinfo, linkobj):
        fields = {
            'vlanrangeavailability': 'vlanRangeAvailability', 
            'interfacemtu': 'interfaceMTU',
        }
        for child in swcapinfo:
            tag = self.normalize_tag(child.tag)
            if tag in fields:
                linkobj[fields[tag]] = child.text
            elif tag == "vlantranslation":
                if child.text.lower() in ['1', 'true']:
                    linkobj["vlanTranslation"] = True 
                else: 
                    linkobj["vlanTranslation"] = False
    
    def parse_port_relation(self, relation, portobj):
        if "type" not in relation.attrib:
            return
        elif relation.attrib["type"] == "over":
            for child in relation:
                tag = self.normalize_tag(child.tag)
                if tag == 'idref':
                    portobj['over'] = child.text
        elif relation.attrib["type"] == "contained-in":
            for child in relation:
                tag = self.normalize_tag(child.tag)
                if tag == 'node':
                    portobj['containedInType'] = 'node'
                    portobj['containedIn'] = child.text
                elif tag == 'port':
                    portobj['containedInType'] = 'port'
                    portobj['containedIn'] = child.text
    
    def parse_link_relation(self, relation, linkobj):
        if "type" not in relation.attrib:
            return
        elif relation.attrib["type"] == "sibling":
            for child in relation:
                tag = self.normalize_tag(child.tag)
                if tag == 'idref':
                    linkobj['remoteLinkId'] = child.text
    
    def generate_circuit_id(self, gri):
        domain = gri[0:gri.rindex('-')]
        idNum = gri[gri.rindex('-')+1:]
        
        return "urn:glif:%s:circuit_%s-%s" % (domain, domain, idNum)
    
    def generate_segment_id(self, gri, reverse):
        domain = gri[0:gri.rindex('-')]
        idNum = gri[gri.rindex('-')+1:]
        
        direction = "atoz"
        if(reverse):
            direction = "ztoa"

        return "urn:glif:%s:circuit_%s-%s_%s" % (domain, domain, idNum, direction)
    
    def format_port_urn(self, urn):
        urn = urn.replace("urn:ogf:network:", "")
        urn = urn.replace("domain=", "")
        urn = urn.replace("node=", "")
        urn = urn.replace("port=", "")
        urparts = urn.split(":")
        
        return "urn:ogf:network:domain=%s:node=%s:port=%s" % (urparts[0], urparts[1], urparts[2])

"""
Starts HTTP server that listens on "server_address" and uses EomplsIDRequestHandler for 
requests when script is called directly
"""
if __name__ == '__main__':
    server_address = ('', 8001)
    httpd = BaseHTTPServer.HTTPServer(server_address, EomplsIDRequestHandler)
    print "Starting HTTP server on", (server_address[0] if server_address[0] else '*'), "port", server_address[1], "..."
    httpd.serve_forever()


