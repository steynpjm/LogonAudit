using NetFwTypeLib;

namespace LogonAudit.CommandProcessors
{
	public class RuleIPListCommand(string firewallRuleName) : CommandProcessorBase
	{
		public override Task Process()
		{
			NotifyProgress($"IP List for firewall rule '{firewallRuleName}':");
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
				INetFwRule existingRule = firewallPolicy.Rules.Item(firewallRuleName);

				if (existingRule is null)
				{
					NotifyProgress($"Firewall rule '{firewallRuleName}' not found.");
					return Task.CompletedTask;
				}

				string currentAddresses = existingRule.RemoteAddresses;

				// split comma seperated into ip's.
				if (!string.IsNullOrEmpty(currentAddresses))
				{
					string[] addresses = currentAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
					foreach (var address in addresses)
					{
						NotifyProgress($"{address}");
					}
				}
				else
				{
					NotifyProgress($"No IP addresses found for rule '{firewallRuleName}'.");
				}


				return Task.CompletedTask;
			}
			catch (Exception ex)
			{
				NotifyProgress($"Failed to list IP's for rule '{firewallRuleName}': {ex.Message}.");
				throw;
			}

		}
	}
}
