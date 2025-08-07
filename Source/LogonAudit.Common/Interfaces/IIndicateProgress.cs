using LogonAudit.Common.EventArguments;

namespace LogonAudit.Common.Interfaces
{
	public interface IIndicateProgress
	{
		event EventHandler<ProgressReportEventArgs> Progress;
	}
}
