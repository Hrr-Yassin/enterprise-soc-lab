# Dedicated Windows endpoint

Requires an authorized, separately licensed Windows guest. The existing Windows VM is outside this deployment. The two Windows fixtures exercise the manager and indexer using EventChannel-shaped data on the Linux agent. Live Windows collection and Sysmon require validation on the dedicated guest.

1. Place the guest on the lab-only data path and allow its Wazuh agent to reach TCP 1514 on that path. A second QEMU user network can use the same directed loopback data relay as the Linux VM. Keep Windows management on a separate console or loopback connection.
2. Install the matching Wazuh agent from the official packages list. Check the vendor's checksum and Authenticode signature. Create a uniquely named agent record with the internal manager API and transfer its key using a private channel. Configure the Wazuh server address for the dedicated guest's path. Leave automatic enrollment off. [Wazuh agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html) · [Wazuh key import](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/importing-the-key.html)
3. Download Sysmon from Microsoft, verify the publisher signature, and install it with sysmon.xml after accepting the vendor terms. Check the schema supported by the installed binary and use agent-localfiles.xml to add or replace the matching channel subscriptions. Enable the approved account-management audit policy in the dedicated guest. [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
4. Restart the Wazuh agent and verify the endpoint is active. Run a harmless process from the regular application directory and confirm that a real Sysmon Event ID 1 arrives with the expected Image field. Use a separate approved test event for the Public-directory policy. Confirm that the native rule 100126 sees the expected path and that the approved path does not trigger it.
5. Verify the Security log channel and the SID on an authorized test membership record. Evaluate native rule 100122 separately from fixture rule 100102. Preserve event record IDs and Windows agent identity before updating the coverage matrix.

The supplied Sysmon policy collects process creation in this scope. Tune event volume and review command-line data access before using it beyond a dedicated guest.

## Fedora inventory

A separate SOC guest and a license for it remain unverified. During the SOC acceptance run, the local filesystem had about 25 GiB free. A dedicated Windows 11 guest needs its own suitable storage allocation and administrative access. [Microsoft virtual-machine requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements#virtual-machine-support)
