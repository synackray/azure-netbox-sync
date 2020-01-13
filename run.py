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
    if args.verbose:
        log.setLevel("DEBUG")
        log.debug("Log level has been overriden by the --verbose argument.")
        start_time = datetime.now()
        if args.cleanup:
            log.info(
                "Completed removal of Azure tenant ID '%s' objects. Total "
                "execution time %s.",
                settings.AZURE_TENANT_ID, (datetime.now() - start_time)
                )
        else:
            azure = AzureHandler()
            log.debug(azure.get_vnets())
            log.debug(azure.get_vms())
            # nb.verify_dependencies()
            # nb.sync_objects(vc_obj_type="virtual_machines")
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
    result = False
    for key in dict1.keys():
        dict1_path = "{}{}[{}]".format(dict1_name, path, key)
        dict2_path = "{}{}[{}]".format(dict2_name, path, key)
        if key not in dict2.keys():
            log.debug("%s not a valid key in %s.", dict1_path, dict2_path)
        elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            log.debug(
                "%s and %s contain dictionary. Evaluating.", dict1_path,
                dict2_path
                )
            compare_dicts(
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
        # Hack for NetBox v2.6.7 requiring integers for some values
        elif key in ["status", "type"]:
            if dict1[key] != dict2[key]["value"]:
                log.debug(
                    "Mismatch: %s value is '%s' while %s value is '%s'.",
                    dict1_path, dict1[key], dict2_path, dict2[key]["value"]
                    )
        elif dict1[key] != dict2[key]:
            log.debug(
                "Mismatch: %s value is '%s' while %s value is '%s'.",
                dict1_path, dict1[key], dict2_path, dict2[key]
                )
        if not result:
            log.debug(
                "%s and %s values do not match.", dict1_path, dict2_path
                )
        else:
            log.debug("%s and %s values match.", dict1_path, dict2_path)
            result = True
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
        log.debug("Collecting size of VM '%s' data disk(s).", vm.name)
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
            nic_mac = nic_conf.mac_address.replace("-", ":")
            results["virtual_interfaces"].append(
                {
                    "virtual_machine": {"name": vm.name},
                    "name": nic_name,
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
                    pub_ip_addr = pub_ip.ip_address
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
                                    "name": vm.name
                                    },
                                "name": nic_name,
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
                "latitude": region.latitude,
                "longitude": region.longitude,
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
                    prefix_template = {
                        "prefix": "",
                        "site": {"slug": vnet.location},
                        "description": "",
                        # VRF and tenant are initialized and will be updated later
                        "vrf": None,
                        "tenant": None,
                        "status": 1,
                        "tags": self.tags,
                        }
                    log.debug("Collecting VNET '%s' address spaces.", vnet.name)
                    for prefix in vnet.address_space.address_prefixes:
                        prefix_template["prefix"] = prefix
                        prefix_template["description"] = vnet.name
                        results["prefixes"].append(prefix_template)
                    for subnet in vnet.subnets:
                        if subnet.address_prefixes is not None:
                            for prefix in subnet.address_prefixes:
                                prefix_template["prefix"] = \
                                    prefix.address_prefix
                                results["prefixes"].append(prefix_template)
                        else:
                            prefix_template["prefix"] = subnet.address_prefix
                            prefix_template["description"] = subnet.name
                            results["prefixes"].append(prefix_template)
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
            "sites": [],
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
                    vm_cpus = sub_vm_skus[vm_size]["vCPUs"]
                    vm_mem = int(
                        float(sub_vm_skus[vm_size]["MemoryGB"]) * 1024.0
                        )
                    os_type = vm.storage_profile.os_disk.os_type.value
                    if os_type is not None:
                        os_type = {"name": os_type}
                    storage_size = self._get_storage(vm)
                    results["virtual_machines"].append(
                        {
                            "name": vm.name,
                            "status": 1,
                            "cluster": {"name": "Microsoft Azure"},
                            "site": {"slug": az_slug(vm.location)},
                            "role": {"name": "Server"},
                            "platform": os_type,
                            "vcpus": vm_cpus,
                            "memory": vm_mem,
                            "disk": storage_size,
                            "tags": self.tags,
                        })
                    # Network configuration
                    network_objects = self._get_network_config(vm)
                    for key in network_objects:
                        results[key].append(network_objects[key])
            except azure_exceptions.CloudError as err:
                log.warning(
                    "Unable to collect data from subscription ID '%s'. "
                    "Received error '%s: %s'", sub_id, err.error.error,
                    err.message
                    )
            # Sites are done after virtual machines to ensure we only build
            # relevant regions
            avail_regions = self._get_regions(sub_id)
            for region in used_regions:
                results["sites"].append(
                    {
                        "name": avail_regions[region]["description"],
                        "slug": az_slug(region),
                        "latitude": avail_regions[region]["latitude"],
                        "longitude": avail_regions[region]["longitude"],
                        "tags": self.tags,
                    })
        return results


if __name__ == "__main__":
    main()
