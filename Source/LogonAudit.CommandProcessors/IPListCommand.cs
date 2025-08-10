using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogonAudit.CommandProcessors
{
	public class IPListCommand(string ipAddress, int numberOfDays) : CommandProcessorBase
	{
		private readonly string _ipAddress = ipAddress;
		private readonly int _numberOfDays = numberOfDays;

		public override Task Process()
		{
			NotifyProgress($"Processing IPList command for the IP {_ipAddress}...");
			NotifyProgress($"Display records for last {_numberOfDays} days.");
			// Simulate some processing work
			return Task.Run(async () =>
			{
				// Here you would implement the logic to list logon audits
				// For now, we just simulate a delay
				await Task.Delay(2000);
				NotifyProgress("IPList command processing completed.");
			});

		}
	}
}
