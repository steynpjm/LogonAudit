using LogonAudit.Common.EventArguments;
using LogonAudit.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogonAudit.CommandProcessors
{
	public class ListCommand(int numberOfDays) : ICommandProcessor, IIndicateProgress
	{
		private readonly int _numberOfDays = numberOfDays;

		public event EventHandler<ProgressReportEventArgs> Progress;

		public Task Process()
		{
			NotifyProgress($"Processing list command for the last {_numberOfDays} days...");
			// Simulate some processing work
			return Task.Run(() =>
			{
				// Here you would implement the logic to list logon audits
				// For now, we just simulate a delay
				System.Threading.Thread.Sleep(2000);
				NotifyProgress("List command processing completed.");
			});
		}



		private void NotifyProgress(string message)
		{
			Progress?.Invoke(this, new (message));
		}	
	}
}
