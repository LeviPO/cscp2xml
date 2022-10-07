# CSCP2XML
CSCP2XML is an OpenText Socks Client profile to XML converter compatible with Windows and Linux. It was developed with the conversion to ProxyCap in mind so it can be used with xml2prs.exe to converto to a .prs profile.

## Usage
### Parameters
* Input filename (.cscp)
* [*optional*] Output filename (.xml). The default name is profile.xml 
* [*optional*] xml2prs converter (.exe)

### Execution examples:
*Executing it on Windows with custom xml filename and conversion to prs included:*
```sh
python3 cscp2xml.py profile.cscp myprofile.xml xml2prs.exe
```
*Simpler execution on Linux without convertion to ProxyCap profile:*
```sh
./cscp2xml.py profile.cscp
```

## Compatibility
| OS      | Compatibility                |
|---------|------------------------------|
| Linux   | :heavy_check_mark:           |
| Windows | :heavy_check_mark:           |
| MacOS   | The exe converter won't work |
| *BSD    | Not tested                   |

## Extra notes
* Default server is set to the last one to be read
* /proxycap_ruleset/routing_rules/routing_rule[n]/@transports defaults to TCP and UDP ("all");
* /proxycap_ruleset/routing_rules/routing_rule[n]/@remote_dns defaults to 'false';
* /proxycap_ruleset/routing_rule[n]/ports/port_range[m]/@type defaults to TCP (same as OpenText);
* /proxycap_ruleset/proxy_servers/proxy_server[n]/@auth_method defaults to none if set to anything other than anonymous or user/password;
* /proxycap_ruleset/routing_rules/routing_rule[n]/@action defaults to proxy if set to Bind or Socksify with direct fallback;
* /proxycap_ruleset/routing_rule[n]/ip_addresses/ip_range[m]/@mask defaults to 1;
* Won't work with IPV4 or hexadecimal IPs for the server hostname;
* If a rule does not have a defined "proxy_or_chain" (it has no ProxyServerID) it is set to the default server.