namespace LogonAudit.Common.EventArguments
{
	public class ProgressReportEventArgs(string progressMessage) : EventArgs
	{
		public string ProgressMessage { get; } = progressMessage;
	}
}
