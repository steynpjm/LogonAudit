using LogonAudit.Common.EventArguments;
using LogonAudit.Common.Interfaces;

namespace LogonAudit.CommandProcessors
{
	public abstract class CommandProcessorBase : ICommandProcessor, IIndicateProgress
	{
		public event EventHandler<ProgressReportEventArgs> Progress;

		public abstract Task Process();


		protected void NotifyProgress(string message)
		{
			Progress?.Invoke(this, new(message));
		}

	}
}
