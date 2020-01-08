#!/usr/bin/env python3

# Program Settings
LOG_LEVEL = "info" # Valid options are debug, info, warning, error, critical
LOG_CONSOLE = True # Logs to console if True, disables console logging if False
LOG_FILE = True # Places all logs in a rotating file if True
IPV4_ALLOWED = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"] # IPv4 networks eligible to be synced to NetBox
IPV6_ALLOWED = ["fe80::/10"] # IPv6 networks eligible to be synced to NetBox

# Azure Settings
AZURE_SP_ID = "" # Service principle ID
AZURE_SP_KEY = "" # Service principle key
AZURE_TENANT_ID = "" # Azure Tenant ID

# NetBox Settings
NB_API_KEY = "" # NetBox API Key
NB_DISABLE_TLS = False # Disables SSL/TLS and uses HTTP for requests. Not ever recommended.
NB_FQDN = "netbox.example.com" # The fully qualified domain name to reach NetBox
NB_INSECURE_TLS = False # Leverage SSL/TLS but ignore certificate errors (ex. expired, untrusted)
NB_PORT = 443 # [optional] NetBox port to connect to if changed from the default
NB_PRUNE_ENABLED = True # Automatically orphan and delete objects if they are no longer in their source system
NB_PRUNE_DELAY_DAYS = 0 # How many days should we wait before pruning an orphaned object
