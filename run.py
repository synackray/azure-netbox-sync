#!/usr/bin/env python3
"""Exports Azure objects and imports them into Netbox via Python3"""

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from msrestazure import azure_exceptions
import settings


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


class AzureHandler:
    """Handles Azure session management and object collection."""
    def __init__(self):
        self.credentials = ServicePrincipalCredentials(
            client_id=settings.AZURE_SP_ID,
            secret=settings.AZURE_SP_KEY,
            tenant=settings.AZURE_TENANT_ID,
            )
        # Initialize clients for use across methods
        self.network_client = None
        self.compute_client = None

    def _get_skus(self):
        """
        Provide Virtual Machine SKUs available for the provided subscription.

        returns dict
        """
        # Collect available SKUs for subscription to compare against
        # Unfortunately the resource list is deprecated and this was
        # the documented method for determining memory and vCPU
        # Please feel free to help me find a better way!
        sub_skus = {}
        for sku in self.compute_client.resource_skus.list():
            if sku.resource_type == "virtualMachines":
                sub_skus[sku.name] = {}
                for cap in sku.capabilities:
                    sub_skus[sku.name][cap.name] = cap.value
        return sub_skus

    def _get_storage(self, vm):
        """
        Get storage information for the provided virtual machine and return sum.

        vm = Azure virtual machine model
        returns integer of storage space
        """
        # OS Disk
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
        result = {}
        vm_nics = vm.network_profile.network_interfaces
        for nic in vm_nics:
            nic_id = nic.id
            nic_rg = find_resource_name(
                resource_id=nic_id,
                resource_type="resourceGroups"
                )
            nic_name = find_resource_name(
                resource_id=nic_id,
                resource_type="networkInterfaces"
                )
            # Collect IP information for NIC
            nic_conf = self.network_client.network_interfaces.get(
                resource_group_name=nic_rg,
                network_interface_name=nic_name
                )
            nic_mac = nic_conf.mac_address.replace("-", ":")
            # Each NIC may have multiple IP configs
            for ip in nic_conf.ip_configurations:
                primary_ip = ip.primary
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

    def get_vms(self):
        """Get Azure Virtual Machine information."""
        # Subscriptions
        subscription_client = SubscriptionClient(self.credentials)
        for sub in subscription_client.subscriptions.list():
            sub_id = sub.subscription_id
            sub_skus = {}
            self.network_client = NetworkManagementClient(
                self.credentials, sub_id
                )
            self.compute_client = ComputeManagementClient(
                self.credentials, sub_id
                )
            print("#"*16, "Subscription ID", sub_id, "#"*16)
            # Some subscriptions are not readable so catch and move on
            try:
                for vm in self.compute_client.virtual_machines.list_all():
                    # We check whether the subscription SKUs have been collected
                    # only if the subscription has VMs. This saves lots of time.
                    if not sub_skus:
                        sub_skus = self._get_skus()
                    # Virtual Machine info
                    vm_location = vm.location
                    vm_name = vm.name
                    vm_size = vm.hardware_profile.vm_size
                    vm_cpus = sub_skus[vm_size]["vCPUs"]
                    vm_mem = int(float(sub_skus[vm_size]["MemoryGB"]) * 1024.0)
                    os_type = vm.storage_profile.os_disk.os_type.value
                    # Storage
                    storage_sum = self._get_storage(vm)
                    # VM Summary
                    print(
                        "VM Name: {} | Location: {} | OS Type: {} | "
                        "Disk Sum: {} GB | vCPUS: {} | RAM: {} MB"
                        .format(
                            vm_name, vm_location, os_type, storage_sum,
                            vm_cpus, vm_mem
                            ))
                    # Network
                    network_conf = self._get_network_config(vm)
                    print(network_conf)
            except azure_exceptions.CloudError as err:
                print(
                    "Unable to collect data from subscription ID {}. Received "
                    "error '{}: {}'".format(
                        sub_id, err.error.error, err.message
                        ))


if __name__ == "__main__":
    azure = AzureHandler()
    azure.get_vms()
