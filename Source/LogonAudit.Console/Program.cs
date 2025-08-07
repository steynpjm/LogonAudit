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
			Option<string> ipAddress = new("--ip")
			{
				Description = "The IP address to use.",
			};

			RootCommand rootCommand = new("Analyses the Windows Security Audit event log entries.");

			Command listCommand = new("list", "List all the IP's and there respective counts.") { optionNumberOfDays };
			listCommand.SetAction(x => CreateListSubCommand(x.GetValue(optionNumberOfDays)));



			rootCommand.Add(listCommand);


			ParseResult parseResult = rootCommand.Parse(args);
			return parseResult.Invoke();
		}

		private static async Task CreateListSubCommand(int numberOfDays)
		{
			System.Console.WriteLine($"Listing for {numberOfDays}...");

			ICommandProcessor listCommand = new CommandProcessors.ListCommand(numberOfDays);
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
