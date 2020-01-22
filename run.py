#!/usr/bin/env python3
"""Collects Azure resources and syncs them to Netbox via Python3"""

from datetime import date, datetime
from ipaddress import ip_network
import argparse
import requests
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from msrestazure import azure_exceptions
import settings
from logger import log


def main():
    """Main function to run if script is called directly"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--cleanup", action="store_true",
        help="Remove all Azure synced objects which support tagging. This is "
             "helpful if you want to start fresh or stop using this script."
        )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output. This overrides the log level in the "
             "settings file. Intended for debugging purposes only."
        )
    args = parser.parse_args()
    nb = NetBoxHandler()
    if args.verbose:
        log.setLevel("DEBUG")
        log.debug("Log level has been overriden by the --verbose argument.")
    if args.cleanup:
        start_time = datetime.now()
        nb.remove_all()
        log.info(
            "Completed removal of Azure tenant ID '%s' objects. Total "
            "execution time %s.",
            settings.AZURE_TENANT_ID, (datetime.now() - start_time)
            )
    else:
        start_time = datetime.now()
        nb.verify_dependencies()
        nb.sync_objects(az_obj_type="vms")
        nb.sync_objects(az_obj_type="vnets")
        log.info(
            "Completed sync with Azure tenant ID '%s'! Total "
            "execution time %s.", settings.AZURE_TENANT_ID,
            (datetime.now() - start_time)
            )

def az_slug(text):
    """
    Prefix string with 'azure-' and then format for NetBox.

    returns string
    """
    return format_slug("azure-{}".format(text))


def compare_dicts(dict1, dict2, dict1_name="d1", dict2_name="d2", path=""):
    """
    Compares the key value pairs of two dictionaries and match boolean.

    dict1 keys and values are compared against dict2. dict2 may have keys and
    values that dict1 does not care evaluate.
    dict1_name and dict2_name allow you to overwrite dictionary name for logs.
    """
    # Setup paths to track key exploration. The path parameter is used to allow
    # recursive comparisions and track what's being compared.
    result = True
    for key in dict1.keys():
        dict1_path = "{}{}[{}]".format(dict1_name, path, key)
        dict2_path = "{}{}[{}]".format(dict2_name, path, key)
        if key not in dict2.keys():
            log.debug("%s not a valid key in %s.", dict1_path, dict2_path)
            result = False
        elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            log.debug(
                "%s and %s contain dictionary. Evaluating.", dict1_path,
                dict2_path
                )
            result = compare_dicts(
                dict1[key], dict2[key], dict1_name, dict2_name,
                path="[{}]".format(key)
                )
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            log.debug(
                "%s and %s key '%s' contains list. Validating dict1 items "
                "exist in dict2.", dict1_path, dict2_path, key
                )
            if not all([bool(item in dict2[key]) for item in dict1[key]]):
                log.debug(
                    "Mismatch: %s value is '%s' while %s value is '%s'.",
                    dict1_path, dict1[key], dict2_path, dict2[key]
                    )
                result = False
        # Hack for NetBox v2.6.7 requiring integers for some values
        elif key in ["status", "type"]:
            if dict1[key] != dict2[key]["value"]:
                log.debug(
                    "Mismatch: %s value is '%s' while %s value is '%s'.",
                    dict1_path, dict1[key], dict2_path, dict2[key]["value"]
                    )
                result = False
        elif dict1[key] != dict2[key]:
            log.debug(
                "Mismatch: %s value is '%s' while %s value is '%s'.",
                dict1_path, dict1[key], dict2_path, dict2[key]
                )
            result = False
        if result:
            log.debug("%s and %s values match.", dict1_path, dict2_path)
        else:
            log.debug("%s and %s values do not match.", dict1_path, dict2_path)
            return result
    log.debug("Final dictionary compare result: %s", result)
    return result

def find_resource_name(resource_id, resource_type):
    """
    Determine an Azure resource name by parsing its resource ID.

    resource_id = String of URI path for the resource ID
    resource_type = String of the Azure resource type
    returns string
    """
    resource_id = resource_id.split("/")
    resource_type_index = resource_id.index(resource_type)
    return resource_id[resource_type_index+1]

def format_slug(text):
    """
    Format string to comply to NetBox slug acceptable pattern and max length.

    NetBox slug pattern: ^[-a-zA-Z0-9_]+$
    NetBox slug max length: 50 characters
    """
    allowed_chars = (
        "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # Alphabet
        "01234567890" # Numbers
        "_-" # Symbols
        )
    # Replace seperators with dash
    seperators = [" ", ",", "."]
    for sep in seperators:
        text = text.replace(sep, "-")
    # Strip unacceptable characters
    text = "".join([c for c in text if c in allowed_chars])
    # Enforce max length
    return truncate(text, max_len=50).lower()

def format_tag(tag):
    """
    Format string to comply to NetBox tag format and max length.

    NetBox tag max length: 100 characters
    """
    # If the tag presented is an IP address then no modifications are required
    try:
        ip_network(tag)
    except ValueError:
        # If an IP was not provided then assume fqdn
        tag = tag.split(".")[0]
        tag = truncate(tag, max_len=100)
    return tag

def prefix_template(prefix, description, tags):
    """A template of the NetBox prefix object used by Azure resources."""
    return {
        "prefix": prefix,
        "description": truncate(description, max_len=100),
        # VRF and tenant are initialized to be updated later
        "vrf": None,
        "tenant": None,
        "status": 1,
        "tags": tags,
        }

def truncate(text="", max_len=50):
    """Ensure a string complies to the maximum length specified."""
    return text if len(text) < max_len else text[:max_len]

def verify_ip(ip_addr):
    """
    Verify input is expected format and checks against allowed networks.

    Allowed networks can be defined in the settings IPV4_ALLOWED and
    IPV6_ALLOWED variables.
    """
    result = False
    try:
        log.debug(
            "Validating IP '%s' is properly formatted and within allowed "
            "networks.",
            ip_addr
            )
        # Strict is set to false to allow host address checks
        version = ip_network(ip_addr, strict=False).version
        global_nets = settings.IPV4_ALLOWED if version == 4 \
            else settings.IPV6_ALLOWED
        # Check whether the network is within the global allowed networks
        log.debug(
            "Checking whether IP address '%s' is within %s.", ip_addr,
            global_nets
            )
        net_matches = [
            ip_network(ip_addr, strict=False).overlaps(ip_network(net))
            for net in global_nets
            ]
        result = any(net_matches)
    except ValueError as err:
        log.debug("Validation of %s failed. Received error: %s", ip_addr, err)
    log.debug("IP '%s' validation returned a %s status.", ip_addr, result)
    return result

class AzureHandler:
    """Handles Azure session management and object collection."""
    def __init__(self):
        self.credentials = ServicePrincipalCredentials(
            client_id=settings.AZURE_SP_ID,
            secret=settings.AZURE_SP_KEY,
            tenant=settings.AZURE_TENANT_ID,
            )
        # Initialize clients for use across methods
        self.compute_client = None
        self.network_client = None
        self.subscription_client = SubscriptionClient(self.credentials)
        self.tags = ["Synced", "Azure"]

    def _get_skus(self):
        """
        Provide Virtual Machine SKUs available for the provided subscription.

        returns dict
        """
        # Collect available SKUs for subscription to compare against
        # Unfortunately the resource list is deprecated and this was
        # the documented method for determining memory and vCPU
        # Please feel free to help me find a better way!
        log.debug("Collecting VM SKUs available to the subscription.")
        sub_vm_skus = {}
        for sku in self.compute_client.resource_skus.list():
            if sku.resource_type == "virtualMachines":
                sub_vm_skus[sku.name] = {}
                for cap in sku.capabilities:
                    sub_vm_skus[sku.name][cap.name] = cap.value
        log.debug("Collected details of %s available VM SKUs.", len(sub_vm_skus))
        return sub_vm_skus

    def _get_storage(self, vm):
        """
        Get storage information for the provided virtual machine and return sum.

        vm = Azure virtual machine model
        returns integer of storage space
        """
        # OS Disk
        log.debug("Collecting size of VM '%s' OS disk.", vm.name)
        os_disk = vm.storage_profile.os_disk.managed_disk.id
        os_disk_rg = find_resource_name(
            resource_id=os_disk,
            resource_type="resourceGroups"
            )
        os_disk_id = find_resource_name(
            resource_id=os_disk,
            resource_type="disks"
            )
        storage_size_sum = self.compute_client.disks.get(
            resource_group_name=os_disk_rg,
            disk_name=os_disk_id
            ).disk_size_gb
        # Data Disks
        log.debug("Collecting size of VM '%s' data disks.", vm.name)
        for data_disk in vm.storage_profile.data_disks:
            data_disk_size = data_disk.disk_size_gb
            if data_disk_size is not None:
                storage_size_sum += data_disk_size
        return storage_size_sum

    def _get_network_config(self, vm):
        """
        Get network configuration for the provided virtual machine.

        vm = Azure virtual machine model
        returns dictionary containing nics and their configuration
        """
        results = {"virtual_interfaces": [], "ip_addresses": []}
        vm_nics = vm.network_profile.network_interfaces
        for nic in vm_nics:
            nic_rg = find_resource_name(
                resource_id=nic.id,
                resource_type="resourceGroups"
                )
            nic_name = find_resource_name(
                resource_id=nic.id,
                resource_type="networkInterfaces"
                )
            # Collect IP information for NIC
            nic_conf = self.network_client.network_interfaces.get(
                resource_group_name=nic_rg,
                network_interface_name=nic_name
                )
            log.debug("Collecting VM '%s' VNIC '%s' data.", vm.name, nic_name)
            nic_mac = nic_conf.mac_address.replace("-", ":")
            results["virtual_interfaces"].append(
                {
                    "virtual_machine": {"name": truncate(vm.name, max_len=64)},
                    "name": truncate(nic_name, max_len=64),
                    "type": 0, # 0 = Virtual
                    "enabled": True,
                    "mac_address": nic_mac.upper(),
                    "tags": self.tags
                })
            # Each NIC may have multiple IP configs
            for ip in nic_conf.ip_configurations:
                priv_ip_addr = ip.private_ip_address
                subnet = ip.subnet.id
                subnet_name = find_resource_name(
                    resource_id=subnet,
                    resource_type="subnets"
                    )
                subnet_rg = find_resource_name(
                    resource_id=subnet,
                    resource_type="resourceGroups"
                    )
                subnet_vnet = find_resource_name(
                    resource_id=subnet,
                    resource_type="virtualNetworks"
                    )
                # Collect Subnet info
                subnet_info = self.network_client.subnets.get(
                    resource_group_name=subnet_rg,
                    virtual_network_name=subnet_vnet,
                    subnet_name=subnet_name,
                    )
                subnet_prefix = subnet_info.address_prefix
                subnet_cidr = subnet_prefix.split("/")[-1]
                priv_ip_addr = "{}/{}".format(
                    priv_ip_addr, subnet_cidr
                    )
                # Collect Public IP config
                pub_ip_addr = None
                if hasattr(ip.public_ip_address, "id"):
                    pub_ip_id = ip.public_ip_address.id
                    pub_ip_rg = find_resource_name(
                        resource_id=pub_ip_id,
                        resource_type="resourceGroups"
                        )
                    pub_ip_name = find_resource_name(
                        resource_id=pub_ip_id,
                        resource_type="publicIPAddresses"
                        )
                    pub_ip = self.network_client.public_ip_addresses.get(
                        resource_group_name=pub_ip_rg,
                        public_ip_address_name=pub_ip_name
                        )
                    if pub_ip.public_ip_prefix is not None:
                        pub_ip_addr = "{}/{}".format(
                            pub_ip.ip_address,
                            pub_ip.public_ip_prefix.split("/")[-1]
                            )
                    else:
                        pub_ip_addr = "{}/32".format(pub_ip.ip_address)
                # Create records for all IPs found
                ips = [
                    ip for ip in [priv_ip_addr, pub_ip_addr] if ip is not None
                    ]
                for ip_addr in ips:
                    results["ip_addresses"].append(
                        {
                            "address": ip_addr,
                            "vrf": None,
                            "tenant": None,
                            "interface": {
                                "virtual_machine": {
                                    "name": truncate(vm.name, max_len=64)
                                    },
                                "name": truncate(nic_name, max_len=64),
                                },
                            "tags": self.tags,
                        })
        return results

    def get_subscriptions(self):
        """
        Get Azure subscriptions available under the provided tenant ID.

        returns dict of subscription id key and name value pair
        """
        log.debug("Collecting subscriptions available to Azure tenant.")
        subscriptions = {}
        for sub in self.subscription_client.subscriptions.list():
            subscriptions[sub.subscription_id] = sub.display_name
        return subscriptions

    def _get_regions(self, subscription_id):
        """
        Get a list of regions available for the provided subscription ID.

        returns dict of regions
        """
        log.debug(
            "Collecting regions available to subscription ID '%s'.",
            subscription_id
            )
        results = {}
        regions = self.subscription_client.subscriptions.list_locations(
            subscription_id=subscription_id
            )
        for region in regions:
            results[region.name] = {
                "description": "Microsoft Azure {}".format(region.display_name),
                }
        return results

    def get_vnets(self):
        """Get Azure virtual networks for the provided subscription."""
        results = {"prefixes": []}
        subscriptions = self.get_subscriptions()
        for sub_id in subscriptions:
            log.info("Accessing Azure Subscription ID '%s'.", sub_id)
            self.network_client = NetworkManagementClient(
                self.credentials, sub_id
                )
            log.info("Collecting VNETs for Azure Subscription ID '%s'.", sub_id)
            try:
                for vnet in self.network_client.virtual_networks.list_all():
                    log.debug("Collecting VNET '%s' address spaces.", vnet.name)
                    for prefix in vnet.address_space.address_prefixes:
                        results["prefixes"].append(prefix_template(
                            prefix=prefix,
                            description=truncate(vnet.name, max_len=100),
                            tags=self.tags
                            ))
                    for subnet in vnet.subnets:
                        if subnet.address_prefixes is not None:
                            for prefix in subnet.address_prefixes:
                                results["prefixes"].append(prefix_template(
                                    prefix=prefix.address_prefix,
                                    description=truncate(vnet.name, max_len=100),
                                    tags=self.tags
                                    ))
                        else:
                            results["prefixes"].append(prefix_template(
                                prefix=subnet.address_prefix,
                                description=truncate(subnet.name, max_len=100),
                                tags=self.tags
                                ))
            except azure_exceptions.CloudError as err:
                log.warning(
                    "Unable to collect data from subscription ID '%s'. "
                    "Received error '%s: %s'", sub_id, err.error.error,
                    err.message
                    )
        return results

    def get_vms(self):
        """Get Azure Virtual Machine information."""
        # Initialize expected result keys
        results = {
            "clusters": [],
            "virtual_machines": [],
            "virtual_interfaces": [],
            "ip_addresses": []
            }
        used_regions = []
        subscriptions = self.get_subscriptions()
        for sub_id in subscriptions:
            log.info("Accessing Azure Subscription ID '%s'.", sub_id)
            sub_vm_skus = {} # Store  available subscription VM SKU details
            self.network_client = NetworkManagementClient(
                self.credentials, sub_id
                )
            self.compute_client = ComputeManagementClient(
                self.credentials, sub_id
                )
            regions = self._get_regions(sub_id)
            # Some subscriptions are not readable so catch and move on
            try:
                for vm in self.compute_client.virtual_machines.list_all():
                    # We check whether the subscription SKUs have been collected
                    # only if the subscription has VMs. This saves lots of time.
                    if not sub_vm_skus:
                        sub_vm_skus = self._get_skus()
                    # Virtual Machine info
                    log.info(
                        "Collecting information for Azure VM '%s'.",
                        vm.name
                        )
                    # Collect all regions used by VMs
                    if vm.location not in used_regions:
                        log.debug(
                            "VM region '%s' added to used regions.", vm.location
                            )
                        used_regions.append(vm.location)
                    vm_size = vm.hardware_profile.vm_size
                    vm_mem = int(
                        float(sub_vm_skus[vm_size]["MemoryGB"]) * 1024.0
                        )
                    os_type = vm.storage_profile.os_disk.os_type.value
                    if os_type is not None:
                        os_type = {"name": os_type}
                    storage_size = self._get_storage(vm)
                    results["virtual_machines"].append(
                        {
                            "name": truncate(vm.name, max_len=64),
                            "status": 1,
                            "cluster": {
                                "name": regions[vm.location]["description"]
                                },
                            "role": {"name": "Server"},
                            "platform": os_type,
                            "vcpus": int(sub_vm_skus[vm_size]["vCPUs"]),
                            "memory": vm_mem,
                            "disk": storage_size,
                            "tags": self.tags,
                        })
                    # Network configuration
                    network_objects = self._get_network_config(vm)
                    for key in network_objects:
                        results[key].extend(network_objects[key])
            except azure_exceptions.CloudError as err:
                log.warning(
                    "Unable to collect data from subscription ID '%s'. "
                    "Received error '%s: %s'", sub_id, err.error.error,
                    err.message
                    )
            # Clusters are done after virtual machines to ensure we only build
            # relevant regions
            for region in used_regions:
                # We check to make sure the results don't already contain the
                # site we want to add
                if not any(
                        cluster["name"] == regions[region]["description"]
                        for cluster in results["clusters"]):
                    results["clusters"].append(
                        {
                            "name": regions[region]["description"],
                            "type": {"name": "Public Cloud"},
                            "group": {"name": "Microsoft Azure"},
                            "tags": self.tags,
                        })
        return results

class NetBoxHandler:
    """Handles NetBox connection state and interaction with the API"""
    def __init__(self):
        self.header = {"Authorization": "Token {}".format(settings.NB_API_KEY)}
        self.nb_api_url = "http{}://{}{}/api/".format(
            ("s" if not settings.NB_DISABLE_TLS else ""), settings.NB_FQDN,
            (":{}".format(settings.NB_PORT) if settings.NB_PORT != 443 else "")
            )
        self.nb_session = None
        # NetBox object type relationships when working in the API
        self.obj_map = {
            "cluster_groups": {
                "api_app": "virtualization",
                "api_model": "cluster-groups",
                "key": "name",
                "prune": False,
                },
            "cluster_types": {
                "api_app": "virtualization",
                "api_model": "cluster-types",
                "key": "name",
                "prune": False,
                },
            "clusters": {
                "api_app": "virtualization",
                "api_model": "clusters",
                "key": "name",
                "prune": True,
                "prune_pref": 2
                },
            "device_roles": {
                "api_app": "dcim",
                "api_model": "device-roles",
                "key": "name",
                "prune": False,
                },
            "device_types": {
                "api_app": "dcim",
                "api_model": "device-types",
                "key": "model",
                "prune": True,
                "prune_pref": 3
                },
            "devices": {
                "api_app": "dcim",
                "api_model": "devices",
                "key": "name",
                "prune": True,
                "prune_pref": 4
                },
            "interfaces": {
                "api_app": "dcim",
                "api_model": "interfaces",
                "key": "name",
                "prune": True,
                "prune_pref": 5
                },
            "ip_addresses": {
                "api_app": "ipam",
                "api_model": "ip-addresses",
                "key": "address",
                "prune": True,
                "prune_pref": 9
                },
            "manufacturers": {
                "api_app": "dcim",
                "api_model": "manufacturers",
                "key": "name",
                "prune": False,
                },
            "platforms": {
                "api_app": "dcim",
                "api_model": "platforms",
                "key": "name",
                "prune": False,
                },
            "prefixes": {
                "api_app": "ipam",
                "api_model": "prefixes",
                "key": "prefix",
                "prune": True,
                "prune_pref": 8
                },
            "sites": {
                "api_app": "dcim",
                "api_model": "sites",
                "key": "name",
                "prune": True,
                "prune_pref": 1
                },
            "tags": {
                "api_app": "extras",
                "api_model": "tags",
                "key": "name",
                "prune": False,
                },
            "virtual_machines": {
                "api_app": "virtualization",
                "api_model": "virtual-machines",
                "key": "name",
                "prune": True,
                "prune_pref": 6
                },
            "virtual_interfaces": {
                "api_app": "virtualization",
                "api_model": "interfaces",
                "key": "name",
                "prune": True,
                "prune_pref": 7
                },
            }

    def request(self, req_type, nb_obj_type, data=None, query=None, nb_id=None):
        """
        HTTP requests and exception handler for NetBox

        req_type: HTTP Method
        nb_obj_type: NetBox object type, must match keys in self.obj_map
        data: Dictionary to be passed as request body.
        query: String used to filter results when using GET method
        nb_id: Integer used when working with a single NetBox object
        """
        # If an existing session is not already found then create it
        # The goal here is session re-use without TCP handshake on every request
        if not self.nb_session:
            self.nb_session = requests.Session()
            self.nb_session.headers.update(self.header)
        result = None
        # Generate URL
        url = "{}{}/{}/{}{}".format(
            self.nb_api_url,
            self.obj_map[nb_obj_type]["api_app"], # App that model falls under
            self.obj_map[nb_obj_type]["api_model"], # Data model
            query if query else "",
            "{}/".format(nb_id) if nb_id else ""
            )
        log.debug("Sending %s to '%s'", req_type.upper(), url)
        req = getattr(self.nb_session, req_type)(
            url, json=data, timeout=10, verify=(not settings.NB_INSECURE_TLS)
            )
        # Parse status
        if req.status_code == 200:
            log.debug(
                "NetBox %s request OK; returned %s status.", req_type.upper(),
                req.status_code
                )
            result = req.json()
            if req_type == "get":
                # NetBox returns 50 results by default, this ensures all results
                # are bundled together
                while req.json()["next"] is not None:
                    url = req.json()["next"]
                    log.debug(
                        "NetBox returned more than 50 objects. Sending %s to "
                        "%s for additional objects.", req_type.upper(), url
                        )
                    req = getattr(self.nb_session, req_type)(url, timeout=10)
                    result["results"] += req.json()["results"]
        elif req.status_code in [201, 204]:
            log.info(
                "NetBox successfully %s %s object.",
                "created" if req.status_code == 201 else "deleted",
                nb_obj_type,
                )
        elif req.status_code == 400:
            if req_type == "post":
                log.warning(
                    "NetBox failed to create %s object. A duplicate record may "
                    "exist or the data sent is not acceptable.", nb_obj_type
                    )
                log.debug(
                    "NetBox %s status reason: %s", req.status_code, req.json()
                    )
            elif req_type == "put":
                log.warning(
                    "NetBox failed to modify %s object with status %s. The "
                    "data sent may not be acceptable.", nb_obj_type,
                    req.status_code
                    )
                log.debug(
                    "NetBox %s status reason: %s", req.status_code, req.json()
                    )
            else:
                raise SystemExit(
                    log.critical(
                        "Well this in unexpected. Please report this. "
                        "%s request received %s status with body '%s' and "
                        "response '%s'.",
                        req_type.upper(), req.status_code, data, req.json()
                        )
                    )
            log.debug("Unaccepted request data: %s", data)
        elif req.status_code == 409 and req_type == "delete":
            log.warning(
                "Received %s status when attemping to delete NetBox object "
                "(ID: %s). Please check the object dependencies.",
                req.status_code, nb_id
                )
            log.debug("NetBox %s status body: %s", req.status_code, req.json())
        else:
            raise SystemExit(
                log.critical(
                    "Well this in unexpected. Please report this. "
                    "%s request received %s status with body '%s' and response "
                    "'%s'.",
                    req_type.upper(), req.status_code, data, req.json()
                    )
                )
        return result

    def obj_exists(self, nb_obj_type, az_data):
        """
        Checks whether a NetBox object exists and matches the Azure object.

        If object does not exist or does not match the Azure object it will
        be created or updated.

        nb_obj_type: String NetBox object type to query for and compare against
        az_data: Dictionary of Azure object key value pairs pre-formatted for
        NetBox
        """
        # NetBox object types do not have a standard key to search and filter
        # them by therefore we look up the appropriate key
        query_key = self.obj_map[nb_obj_type]["key"]
        # Create a query specific to the device parent/child relationship when
        # working with interfaces
        if nb_obj_type == "interfaces":
            query = "?device={}&{}={}".format(
                az_data["device"]["name"], query_key, az_data[query_key]
                )
        elif nb_obj_type == "virtual_interfaces":
            query = "?virtual_machine={}&{}={}".format(
                az_data["virtual_machine"]["name"], query_key,
                az_data[query_key]
                )
        else:
            query = "?{}={}".format(query_key, az_data[query_key])
        req = self.request(
            req_type="get", nb_obj_type=nb_obj_type,
            query=query
            )
        # Users have the option to avoid updating prefixes that have already
        # been created by other means.
        if req["count"] == 1 and nb_obj_type == "prefixes" \
                and "Azure" not in req["results"][0]["tags"] \
                and not settings.NB_OVERWRITE_PREFIXES:
            log.info(
                "NetBox %s object '%s' already exists with no 'Azure' tag and "
                "the overwrite prefixes setting is currently False. Skipping "
                "update.", nb_obj_type, az_data[query_key]
                )
        # A single matching object is found so we compare its values to the new
        # object
        elif req["count"] == 1:
            log.debug(
                "NetBox %s object '%s' already exists. Comparing values.",
                nb_obj_type, az_data[query_key]
                )
            nb_data = req["results"][0]
            # Objects that have been previously tagged as orphaned but then
            # reappear in Azure need to be stripped of their orphaned status
            if "tags" in az_data and "Orphaned" in nb_data["tags"]:
                log.info(
                    "NetBox %s object '%s' is currently marked as orphaned "
                    "but has reappeared in Azure. Updating NetBox.",
                    nb_obj_type, az_data[query_key]
                    )
                self.request(
                    req_type="put", nb_obj_type=nb_obj_type, data=az_data,
                    nb_id=nb_data["id"]
                    )
            elif compare_dicts(
                    az_data, nb_data, dict1_name="az_data",
                    dict2_name="nb_data"):
                log.info(
                    "NetBox %s object '%s' match current values. Moving on.",
                    nb_obj_type, az_data[query_key]
                    )
            else:
                log.info(
                    "NetBox %s object '%s' do not match current values.",
                    nb_obj_type, az_data[query_key]
                    )
                if "tags" in az_data:
                    log.debug("Merging tags between Azure and NetBox object.")
                    az_data["tags"] = list(
                        set(az_data["tags"] + nb_data["tags"])
                        )
                self.request(
                    req_type="put", nb_obj_type=nb_obj_type, data=az_data,
                    nb_id=nb_data["id"]
                    )
        elif req["count"] > 1:
            log.warning(
                "Search for NetBox %s object '%s' returned %s results but "
                "should have only returned 1. Please manually review and "
                "report this if the data is accurate. Skipping for safety.",
                nb_obj_type, az_data[query_key], req["count"]
                )
        else:
            log.info(
                "Netbox %s '%s' object not found. Requesting creation.",
                nb_obj_type,
                az_data[query_key],
                )
            self.request(
                req_type="post", nb_obj_type=nb_obj_type, data=az_data
                )

    def sync_objects(self, az_obj_type):
        """
        Collect resources of type from Azure and syncs them to NetBox.

        Some NB object types do not support tags so they will be a one-way sync
        meaning orphaned objects will not be removed from NetBox.
        """
        # Collect data from Azure
        log.info(
            "Initiated sync of Azure %s objects to NetBox.",
            az_obj_type[:-1]
            )
        # Dynamically accept any of the AzureHandler class get_ functions
        az_objects = getattr(AzureHandler(), "get_{}".format(az_obj_type))()
        nb_obj_types = list(az_objects.keys())
        for nb_obj_type in nb_obj_types:
            log.info(
                "Starting sync of %s Azure %s object%s to NetBox %s "
                "object%s.",
                len(az_objects[nb_obj_type]),
                az_obj_type,
                "s" if len(az_objects[nb_obj_type]) != 1 else "",
                nb_obj_type,
                "s" if len(az_objects[nb_obj_type]) != 1 else "",
                )
            for obj in az_objects[nb_obj_type]:
                # Check to ensure IP addresses pass all checks before syncing
                # to NetBox
                if nb_obj_type == "ip_addresses":
                    ip_addr = obj["address"]
                    if verify_ip(ip_addr):
                        log.debug(
                            "IP %s has passed necessary pre-checks.",
                            ip_addr
                            )
                        # Search for parent prefix to assign VRF and tenancy
                        prefix = self.search_prefix(ip_addr)
                        # Update placeholder values with matched values
                        obj["vrf"] = prefix["vrf"]
                        obj["tenant"] = prefix["tenant"]
                    else:
                        log.debug(
                            "IP %s has failed necessary pre-checks. Skipping "
                            "sync to NetBox.", ip_addr,
                            )
                        continue
                self.obj_exists(nb_obj_type=nb_obj_type, az_data=obj)
            log.info(
                "Finished sync of %s Azure %s object%s to NetBox %s "
                "object%s.",
                len(az_objects[nb_obj_type]),
                az_obj_type,
                "s" if len(az_objects[nb_obj_type]) != 1 else "",
                nb_obj_type,
                "s" if len(az_objects[nb_obj_type]) != 1 else "",
                )
        # Send Azure objects to the pruner
        if settings.NB_PRUNE_ENABLED:
            self.prune_objects(az_objects, az_obj_type)

    def prune_objects(self, az_objects, az_obj_type):
        """
        Collects NetBox objects and checks if they still exist in Azure.

        If NetBox objects are not found in the supplied az_objects data then
        they will go through a pruning process.

        az_objects: Dictionary of Azure object types and list of their objects
        az_obj_type: The parent object type called during the sync. This is
        used to determine whether special filtering needs to be applied.
        """
        # Determine which of our NetBox objects types support pruning
        nb_obj_types = [t for t in az_objects if self.obj_map[t]["prune"]]
        # Sort NetBox object types by pruning priority. This ensures
        # we do not have issues with deleting objects with dependencies.
        nb_obj_types = sorted(
            nb_obj_types, key=lambda t: self.obj_map[t]["prune_pref"],
            reverse=True
            )
        for nb_obj_type in nb_obj_types:
            log.info(
                "Comparing existing NetBox %s objects to current Azure "
                "objects for pruning eligibility.", nb_obj_type
                )
            nb_objects = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                # Tags need to always be searched by slug
                query="?tag={}".format(format_slug("Azure"))
                )["results"]
            # Issue 33: As of NetBox v2.6.11 it is not possible to filter
            # virtual interfaces by tag. Therefore we filter post collection.
            if az_obj_type == "vms" and \
                    nb_obj_type == "virtual_interfaces":
                nb_objects = [
                    obj for obj in nb_objects
                    if "Azure" in obj["tags"]
                    ]
                log.debug(
                    "Found %s virtual interfaces with tag 'Azure'.",
                    len(nb_objects)
                    )
            elif az_obj_type == "vms" and \
                    nb_obj_type == "ip_addresses":
                nb_objects = [
                    obj for obj in nb_objects
                    if obj["interface"]["virtual_machine"] is not None
                    ]
            # NetBox object types do not have a standard key to search and
            # filter them by therefore we look up the appropriate key
            query_key = self.obj_map[nb_obj_type]["key"]
            az_obj_values = [obj[query_key] for obj in az_objects[nb_obj_type]]
            orphans = [
                obj for obj in nb_objects if obj[query_key] not in az_obj_values
                ]
            log.info(
                "Comparison completed. %s %s orphaned NetBox object%s did not "
                "match.",
                len(orphans), nb_obj_type, "s" if len(orphans) != 1 else ""
                )
            log.debug("The following objects did not match: %s", orphans)
            # Pruned items are checked against the prune timer
            # All pruned items are first tagged so it is clear why they were
            # deleted, and then those items which are greater than the max age
            # will be deleted permanently
            for orphan in orphans:
                log.info(
                    "Processing orphaned NetBox %s '%s' object.",
                    nb_obj_type, orphan[query_key]
                    )
                if "Orphaned" not in orphan["tags"]:
                    log.info(
                        "No tag found. Adding 'Orphaned' tag to %s '%s' "
                        "object.",
                        nb_obj_type, orphan[query_key]
                        )
                    tags = {
                        "tags": ["Synced", "Azure", "Orphaned"]
                        }
                    self.request(
                        req_type="patch", nb_obj_type=nb_obj_type,
                        nb_id=orphan["id"],
                        data=tags
                        )
                # Check if the orphan has gone past the max prune timer and
                # needs to be deleted
                # Dates are in YY, MM, DD format
                current_date = date.today()
                # Some objects do not have a last_updated field so we must
                # handle that gracefully and send for deletion
                del_obj = False
                try:
                    modified_date = date(
                        int(orphan["last_updated"][:4]), # Year
                        int(orphan["last_updated"][5:7]), # Month
                        int(orphan["last_updated"][8:10]) # Day
                        )
                    # Calculated timedelta then converts it to the days integer
                    days_orphaned = (current_date - modified_date).days
                    if days_orphaned >= settings.NB_PRUNE_DELAY_DAYS:
                        log.info(
                            "The %s '%s' object has exceeded the %s day max "
                            "for orphaned objects. Sending it for deletion.",
                            nb_obj_type, orphan[query_key],
                            settings.NB_PRUNE_DELAY_DAYS
                            )
                        del_obj = True
                    else:
                        log.info(
                            "The %s '%s' object has been orphaned for %s of %s "
                            "max days. Proceeding to next object.",
                            nb_obj_type, orphan[query_key], days_orphaned,
                            settings.NB_PRUNE_DELAY_DAYS
                            )
                except KeyError as err:
                    log.debug(
                        "The %s '%s' object does not have a %s "
                        "field. Sending it for deletion.",
                        nb_obj_type, orphan[query_key], err
                        )
                    del_obj = True
                if del_obj:
                    self.request(
                        req_type="delete", nb_obj_type=nb_obj_type,
                        nb_id=orphan["id"],
                        )

    def search_prefix(self, ip_addr):
        """
        Queries Netbox for the parent prefix of any supplied IP address.

        Returns dictionary of VRF and tenant values.
        """
        result = {"tenant": None, "vrf": None}
        query = "?contains={}".format(ip_addr)
        try:
            prefix_obj = self.request(
                req_type="get", nb_obj_type="prefixes", query=query
                )["results"][-1] # -1 used to choose the most specific result
            prefix = prefix_obj["prefix"]
            for key in result:
                # Ensure the data returned was not null.
                try:
                    result[key] = {"name": prefix_obj[key]["name"]}
                except TypeError:
                    log.debug(
                        "No %s key was found in the parent prefix. Nulling.",
                        key
                        )
                    result[key] = None
            log.debug(
                "IP address %s is a child of prefix %s with the following "
                "attributes: %s", ip_addr, prefix, result
                )
        except IndexError:
            log.debug("No parent prefix was found for IP %s.", ip_addr)
        return result

    def verify_dependencies(self):
        """
        Validates that all prerequisite NetBox objects exist and creates them.
        """
        dependencies = {
            "platforms": [
                {"name": "Windows", "slug": "windows"},
                {"name": "Linux", "slug": "linux"},
                ],
            "cluster_types": [
                {"name": "Public Cloud", "slug": "public-cloud"}
                ],
            "cluster_groups": [
                {"name": "Microsoft Azure", "slug": "microsoft-azure"}
                ],
            "device_roles": [
                {
                    "name": "Server",
                    "slug": "server",
                    "color": "9e9e9e",
                    "vm_role": True
                }],
            "tags": [
                {
                    "name": "Orphaned",
                    "slug": "orphaned",
                    "color": "607d8b",
                    "comments": "This applies to objects that have become "
                                "orphaned. The source system which has "
                                "previously provided the object no longer "
                                "states it exists.{}".format(
                                    " An object with the 'Orphaned' tag will "
                                    "remain in this state until it ages out "
                                    "and is automatically removed."
                                    ) if settings.NB_PRUNE_ENABLED else ""
                },
                {
                    "name": "Azure",
                    "slug": "azure",
                    "comments": "Objects synced from Azure. Be careful not to "
                                "modify the name or slug."
                }]
            }
        # For each dependency of each type verify object exists
        log.info("Verifying all prerequisite objects exist in NetBox.")
        for dep_type in dependencies:
            log.debug(
                "Checking NetBox has necessary %s objects.", dep_type[:-1]
                )
            for dep in dependencies[dep_type]:
                self.obj_exists(nb_obj_type=dep_type, az_data=dep)
        log.info("Finished verifying prerequisites.")

    def remove_all(self):
        """
        Searches NetBox for all Azure synced objects and then removes them.

        This is intended to be used in the case you wish to start fresh or stop
        using the script.
        """
        log.info(
            "Preparing for the removal of all Azure objects synced to NetBox."
            )
        nb_obj_types = [
            t for t in self.obj_map if self.obj_map[t]["prune"]
            ]
        # Honor pruning preference, highest to lowest
        nb_obj_types = sorted(
            nb_obj_types, key=lambda t: self.obj_map[t]["prune_pref"],
            reverse=True
            )
        for nb_obj_type in nb_obj_types:
            log.info(
                "Collecting all current NetBox %s objects to prepare for "
                "deletion.", nb_obj_type
                )
            nb_objects = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                query="?tag=azure"
                )["results"]
            # NetBox virtual interfaces do not currently support filtering
            # by tags. Therefore we collect all virtual interfaces and
            # filter them post collection.
            if nb_obj_type == "virtual_interfaces":
                log.debug("Collected %s virtual interfaces pre-filtering.")
                nb_objects = [
                    obj for obj in nb_objects if "Azure" in obj["tags"]
                    ]
                log.debug(
                    "Filtered to %s virtual interfaces with 'Azure' tag.",
                    len(nb_objects)
                    )
            query_key = self.obj_map[nb_obj_type]["key"]
            log.info(
                "Deleting %s NetBox %s objects.", len(nb_objects), nb_obj_type
                )
            for obj in nb_objects:
                log.info(
                    "Deleting NetBox %s '%s' object.", nb_obj_type,
                    obj[query_key]
                    )
                self.request(
                    req_type="delete", nb_obj_type=nb_obj_type,
                    nb_id=obj["id"],
                    )


if __name__ == "__main__":
    main()
