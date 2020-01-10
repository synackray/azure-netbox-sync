| Azure            | NetBox                                     | Supports Tags |
|------------------|--------------------------------------------|---------------|
| Regions          | Sites                                      | Yes           |
| Subnets          | Prefixes                                   | Yes           |
| Virtual Machines | Interfaces, IP Addresses, Virtual Machines | Yes           |
| Virtual Networks | Prefixes                                   | Yes           |

# Sites = /dcim/sites/
name*
slug*
status
description
latitude
longitude
tags

# Cluster  - /virtualization/clusters/
name*
type*
group
site
comments
tags

# Prefixes - /ipam/prefixes/
prefix*
site
vrf
tenant
status
role
description
tags

# Virtual Machines - /virtualization/virtual-machines/
name*
status
site
cluster*
role
tenant
platform
primary_ip4
vcpus
memory
disk
comments
tags

# Interfaces (VM) - /virtualization/interfaces/
virtual_machine
name*
type
enabled
mtu
mac_address
description
tags

# IP Addresses - /ipam/ip-addresses/
adresss*
vrf
tenant
status
role
interface
dns_name
description
tags
