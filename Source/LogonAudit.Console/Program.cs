using LogonAudit.CommandProcessors;
using LogonAudit.Common.Interfaces;
using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LogonAudit.Console
{
	internal class Program
	{
		[STAThread]
		static int Main(string[] args)
		{
			// Initialize the COM library
			int hr = CoInitializeEx(IntPtr.Zero, COINIT_APARTMENTTHREADED);
			if (hr < 0)
			{
				Marshal.ThrowExceptionForHR(hr);
			}

			//if (IsAdministrator() == false)
			//{
			//	System.Console.WriteLine("Must be run as an administrator.");
			//	return 0;
			//}


			Option<int> optionNumberOfDays = new("--days")
			{
				Description = "The last x number of days to include in analysis",
				DefaultValueFactory = x => 30
			};
			Option<int> optionTopCopunt = new("--top")
			{
				Description = "The top x number of records to show",
				DefaultValueFactory = x => 10
			};
			Option<string> optionIPAddress = new("--ip")
			{
				Description = "The IP address to use.",
				Required = true,
			};
			Option<string> optionFireWallRuleName = new("--rule")
			{
				Description = "The Firewall Rule to apply the action to.",
				DefaultValueFactory = x => "Permanent Block"
			};

			RootCommand rootCommand = new("Analyses the Windows Security Audit event log entries.");

			Command listCommand = new("list", "List all the IP's and there respective counts.") { optionNumberOfDays, optionTopCopunt };
			listCommand.SetAction(x => CreateListSubCommand(x.GetValue(optionNumberOfDays), x.GetValue(optionTopCopunt)));

			Command ipListCommand = new("ipList", "List all events for the defined IP address.") { optionIPAddress, optionNumberOfDays };
			ipListCommand.SetAction(x => CreateIPListSubCommand(x.GetRequiredValue(optionIPAddress), x.GetValue(optionNumberOfDays)));




			rootCommand.Add(listCommand);
			rootCommand.Add(ipListCommand);


			ParseResult parseResult = rootCommand.Parse(args);
			return parseResult.Invoke();
		}

		private static async Task CreateIPListSubCommand(string ipAddress, int numberOfDays)
		{
			ICommandProcessor ipListCommand = new CommandProcessors.IPListCommand(ipAddress, numberOfDays);
			IIndicateProgress progress = ipListCommand as IIndicateProgress;

			if (progress != null)
			{
				progress.Progress += (sender, e) =>
				{
					System.Console.WriteLine($"Progress: {e.ProgressMessage}");
				};
			}

			await ipListCommand.Process();
		}

		private static async Task CreateListSubCommand(int numberOfDays, int topCount)
		{

			ICommandProcessor listCommand = new CommandProcessors.ListCommand(numberOfDays, topCount);
			IIndicateProgress progress = listCommand as IIndicateProgress;

			if (progress != null)
			{
				progress.Progress += (sender, e) =>
				{
					System.Console.WriteLine($"Progress: {e.ProgressMessage}");
				};
			}

			await listCommand.Process();
		}

		static bool IsAdministrator()
		{
			using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
			{
				WindowsPrincipal principal = new WindowsPrincipal(identity);
				return principal.IsInRole(WindowsBuiltInRole.Administrator);
			}
		}

		[DllImport("ole32.dll")]
		private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

		[DllImport("ole32.dll")]
		private static extern void CoUninitialize();

		private const uint COINIT_APARTMENTTHREADED = 0x2; // STA model


	}
}
