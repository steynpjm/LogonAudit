using LogonAudit.Common.Interfaces;
using NetFwTypeLib;

namespace LogonAudit.CommandProcessors
{
	public class IPBlockCommand(string ipAddress, string firewallRuleName) : CommandProcessorBase
	{
		private readonly string _ipAddress = ipAddress;
		private readonly string _firewallRuleName = firewallRuleName;


		public override Task Process()
		{
			NotifyProgress($"Adding IP {_ipAddress} to firewall rule '{_firewallRuleName}'...");
			try
			{
				// Get the firewall policy
				INetFwPolicy2? firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

				if (firewallPolicy is null)
				{
					NotifyProgress($"Firewall policy not found.");
					return Task.CompletedTask;
				}

				// Retrieve the existing rule
				INetFwRule existingRule = firewallPolicy.Rules.Item(_firewallRuleName);

				if (existingRule is null)
				{
					NotifyProgress($"Firewall rule '{_firewallRuleName}' not found.");
					return Task.CompletedTask;
				}

				// Add the new IP address to the existing remote addresses
				string ipAddress = $"{_ipAddress}/255.255.255.255".Trim();
				string currentAddresses = existingRule.RemoteAddresses;

				if (!string.IsNullOrEmpty(currentAddresses))
				{
					if (!currentAddresses.Contains(_ipAddress))
					{
						currentAddresses += "," + ipAddress;
						existingRule.RemoteAddresses = currentAddresses;
						NotifyProgress($"IP {_ipAddress} added to firewall rule.");
					}
					else
					{
						NotifyProgress($"IP {_ipAddress} already added.");
					}
				}
				else
				{
					existingRule.RemoteAddresses = ipAddress;
					NotifyProgress($"IP {_ipAddress} added to firewall rule.");
				}

				return Task.CompletedTask;
			}
			catch (Exception ex)
			{
				NotifyProgress($"Failed to block IP address {_ipAddress}: {ex.Message}.");
				throw;
			}
		}
	}
}