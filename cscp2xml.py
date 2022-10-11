#!/usr/bin/env python3

import sys, subprocess
import xml.etree.ElementTree as ET

## NOTES:
# Default server is set to the last one to be read
# /proxycap_ruleset/routing_rules/routing_rule[n]/@transports defaults to TCP and UDP ("all");
# /proxycap_ruleset/routing_rules/routing_rule[n]/@remote_dns defaults to 'false';
# /proxycap_ruleset/routing_rule[n]/ports/port_range[m]/@type defaults to TCP (same as OpenText);
# /proxycap_ruleset/proxy_servers/proxy_server[n]/@auth_method defaults to none if set to anything other than anonymous or user/password;
# /proxycap_ruleset/routing_rules/routing_rule[n]/@action defaults to proxy if set to Bind or Socksify with direct fallback;
# /proxycap_ruleset/routing_rule[n]/ip_addresses/ip_range[m]/@mask defaults to 1;
# Won't work with IPV4 or hexadecimal IPs for the server hostname;
# If a rule does not have a defined "proxy_or_chain" (it has no ProxyServerID) it is set to the default server.


## HOW TO USE:
# python3 [this_script_name] [OpenText_profile] [output_XML_name (default = profile.xml)](optional) [xml2prs executable name (default = xml2prs.exe)](optional)
# If the xml2prs executable is not specified the script will only convert to an XML that can later be converted to .prs


# Argument handler
if len(sys.argv) == 1:
	print("ERROR! Please specify the input file name")
	print(f"Syntax: 'python3 {sys.argv[0]} [OpenText_profile] [output_XML_name (default = profile.xml)](optional) [xml2prs_executable_name (default = xml2prs.exe)](optional)'")
	exit()
elif len(sys.argv) == 2:
	sourceFileName = sys.argv[1]
	targetFileName = "profile.xml"
elif len(sys.argv) == 3:
	sourceFileName = sys.argv[1]
	if sys.argv[2].endswith('.xml'):
		targetFileName = sys.argv[2]
	elif sys.argv[2].endswith('.exe'):
		xml2prsExeName = sys.argv[2]
		targetFileName = "profile.xml"
	else:
		print(f"ERROR! The parameter '{sys.argv[2]}' must be a .exe or .xml file")
		print(f"Syntax: 'python3 {sys.argv[0]} [OpenText_profile] [output_XML_name (default = profile.xml)](optional) [xml2prs_executable_name (default = xml2prs.exe)](optional)'")
		exit()

elif len(sys.argv) == 4:
	sourceFileName = sys.argv[1]
	targetFileName = sys.argv[2]
	xml2prsExeName = sys.argv[3]
elif len(sys.argv) > 4:
	print("ERROR! Too many arguments")
	print(f"Syntax: 'python3 {sys.argv[0]} [OpenText_profile] [output_XML_name (default = profile.xml)](optional) [xml2prs_executable_name (default = xml2prs.exe)](optional)'")
	exit()

# Open files
try:
	cscpSource = open(sourceFileName,"r")
except FileNotFoundError:
		print(f"ERROR! The file {sourceFileName} does not exist or it cannot be opened. Aborting...")
		exit()
	
try:
	xmlTarget = open(targetFileName, "a+")
except FileNotFoundError:
		print(f"ERROR! The file {targetFileName} does not exist or it cannot be opened. Aborting...")
		exit()
	
# Create XML elements and subelements
ruleset = ET.Element("proxycap_ruleset", version="537")

servers = ET.SubElement(ruleset, "proxy_servers")
chains = ET.SubElement(ruleset, "proxy_chains")
rules = ET.SubElement(ruleset, "routing_rules")
rde = ET.SubElement(ruleset, "remote_dns_exceptions")

# Reading and parsing loop
serverIDnameDict = {}
reading = ""
namelessServerNumber = 1
for nLine, line in enumerate(cscpSource):
	line = line.rstrip()
	if line.startswith('['):
		reading = ""
		line = line.replace('[', '').replace(']', '')
		words = line.split()

		try:
			if tmpRule.find('proxy_or_chain') is None and tmpRule.attrib["action"] == "proxy":
				tmpProxyOrChain = ET.SubElement(tmpRule, "proxy_or_chain", name="(default)")
		except:
			pass

		if words[2] == "Servers" and len(words) > 3 and words[-1] != "User":
			tmpServer = ET.SubElement(servers, "proxy_server")
			reading = "server"
		elif words[2] == "Servers" and words[-1] == "User":
			reading = "serverUser"
		elif words[2] == "Rules" and len(words) > 3:
			tmpRule = ET.SubElement(rules, "routing_rule", name="Rule" + words[-1], transports="all", remote_dns="false")
			reading = "rule"
			
	else:
		lAttrib = str(line.split("=")[0].lower())
		attribValue = str(line.split("=")[1])
		if reading == "server":
			tmpServer.set("is_default", "false")

			if lAttrib == "name":
				tmpServer.set("name", attribValue)
			
			elif lAttrib == "id":
				try:
					serverIDnameDict[attribValue] = tmpServer.attrib["name"]
				except:
					namelessServerName = "Server " + str(namelessServerNumber)
					serverIDnameDict[attribValue] = namelessServerName
					tmpServer.set("name", namelessServerName)
					namelessServerNumber =+ 1
			elif lAttrib == "ipaddress":
				tmpServer.set("hostname", attribValue)

			elif lAttrib == "port":
				tmpServer.set("port", attribValue)

			elif lAttrib == "type":
				if attribValue == "0":
					tmpServer.set("type", "socks5")
				elif attribValue == "1":
					tmpServer.set("type", "socks4")

			elif lAttrib == "authenticationtype":
				if attribValue == "0":
					tmpServer.set("auth_method", "none")
				elif attribValue == "1":
					tmpServer.set("auth_method", "password")
				if attribValue == "3":
					print("WARNING! Could not convert line " + str(nLine + 1))
					print("Reason: This authentication method does not exist in ProxyCap. It will be converted to 'Anonymous'")
					tmpServer.set("auth_method", "none")
				if attribValue == "4":
					print("WARNING! Could not convert line " + str(nLine + 1))
					print("Reason: This authentication method does not exist in ProxyCap. It will be converted to 'Anonymous'")
					tmpServer.set("auth_method", "none")
				if attribValue == "5":
					print("WARNING! Could not convert line " + str(nLine + 1))
					print("Reason: This authentication method does not exist in ProxyCap. It will be converted to 'Anonymous'")
					tmpServer.set("auth_method", "none")

		elif reading == "serverUser":
			if lAttrib == "name":
				tmpServer.set("username", attribValue)

			elif lAttrib == "password":
				tmpServer.set("password", attribValue)

		elif reading == "rule":
			if lAttrib == "enable":
				if attribValue == "0":
					tmpRule.set("disabled", "true")
				elif attribValue == "1":
					tmpRule.set("disabled", "false")
			elif lAttrib == "action":
				if attribValue == "0":
					tmpRule.set("action", "proxy")
				elif attribValue == "1":
					tmpRule.set("action", "direct")
				elif attribValue == "2":
					tmpRule.set("action", "block")
				elif attribValue == "3":
					print("WARNING! Could not convert line " + str(nLine + 1))
					print("Reason: The action 'Bind' does not exist in ProxyCap. It will be converted to the equivalent of Socksify\n")
					tmpRule.set("action", "proxy")
				elif attribValue == "4":
					print("WARNING! Could not convert line" + str(nLine + 1))
					print("Reason: The action 'Socksify with direct fallback' does not exist in ProxyCap. It will be converted to the equivalent of Socksify\n")
					tmpRule.set("action", "proxy")
			elif lAttrib == "name":
				if '*' in attribValue:
					attribValue = attribValue.replace('*', '0') + '-' + attribValue.replace('*', '255')
				if attribValue.split('.')[-1].isnumeric():
					if tmpRule.find('ip_addresses') is None:
						tmpIPadresses = ET.SubElement(tmpRule, "ip_addresses")
					if '-' in attribValue:
						tmpIPrange = ET.SubElement(tmpIPadresses, "ip_range", first_ip=attribValue.split('-')[0], last_ip=attribValue.split('-')[1])
					else:
						tmpIPrange = ET.SubElement(tmpIPadresses, "ip_range", ip=attribValue, mask="1")
				elif '\\' in attribValue:
					if tmpRule.find('programs') is None:
						tmpPrograms = ET.SubElement(tmpRule, "programs")
					tmpProgram = ET.SubElement(tmpPrograms, "program", dir_included="true", path=attribValue)
				else:
					if tmpRule.find('hostnames') is None:
						tmpHostnames = ET.SubElement(tmpRule, "hostnames")
					tmpHostname = ET.SubElement(tmpHostnames, "hostname", wildcard=attribValue)

			elif lAttrib == "startport":
				startport = attribValue

			elif lAttrib == "endport":
				if startport != "0":
					if tmpRule.find('ports') is None:
						tmpPorts = ET.SubElement(tmpRule, "ports")
					tmpPortrange = ET.SubElement(tmpPorts, "port_range", type="tcp", first=startport, last=attribValue)

			elif lAttrib == "proxyserverid":
				tmpProxyOrChain = ET.SubElement(tmpRule, "proxy_or_chain", name=serverIDnameDict[attribValue])

try:
	tmpServer.set("is_default", "true")
except:
	print("INFO! This ruleset has no servers")


# Exporting to pretty XML
finalTree = ET.ElementTree(ruleset)
ET.indent(finalTree, space="  ", level=0)
finalTree.write(targetFileName, encoding="utf-8", xml_declaration=True)

xmlTarget.write('\n\n<!-- Created automatically with cscp2xml.py-->')
xmlTarget.write('\n<!-- By: Levi Oliveira  -->')


# Close files
cscpSource.close()
xmlTarget.close()
print("INFO! The .cscp to XML conversion has ended without errors")

# XML to prs
try:
	xml2prsExeName
except NameError:
	print(f"INFO! The file {targetFileName} will NOT be converted to .prs")
else:
	if xml2prsExeName:
		if sys.platform.startswith('linux'):
			try:
				subprocess.run(["wine", xml2prsExeName, targetFileName, targetFileName.split('.')[0] + ".prs"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
			except Exception as exc:
				if "No such file or directory: 'wine'" in str(exc):
					print("ERROR! The 'wine' package is not installed. Please install it and re-run the script")
					exit()
				else:
					print("ERROR! The XML to .prs conversion has failed with the following exception:")
					print(exc)
					exit()
		elif sys.platform.startswith('win'):
			try:
				subprocess.run([xml2prsExeName, targetFileName, targetFileName.split('.')[0] + ".prs"])
			except Exception as exc:
				print("ERROR! The XML to .prs conversion has failed with the following exception:")
				print(exc)
				exit()
		else:
			print(f"ERROR! The converter {xml2prsExeName} either cannot be executed on this OS or this script isn't compatible with it (yet)")
			exit()

print("SUCCESS! The script has ended without errors")
