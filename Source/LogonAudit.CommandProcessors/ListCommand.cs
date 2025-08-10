using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace LogonAudit.CommandProcessors
{
	public class ListCommand(int numberOfDays, int topCount) : CommandProcessorBase
	{
		private readonly int _numberOfDays = numberOfDays;
		private readonly int _topCount = topCount;

		public override async Task Process()
		{
			string logName = "Security";
			DateTime cutoffDate = DateTime.Now.AddDays(-_numberOfDays);

			ConcurrentBag<EventRecord> logEntriesWithIp = [];
			List<EventRecord> logEntries = [];

			NotifyProgress($"Reading Audit Failure entries from the past {_numberOfDays} days...");

			EventLogQuery query = new EventLogQuery(logName, PathType.LogName)
			{
				ReverseDirection = true
			};

			using EventLogReader reader = new EventLogReader(query);
			EventRecord record;

			while ((record = reader.ReadEvent()) != null)
			{
				logEntries.Add(record);
			}

			Parallel.ForEach(logEntries, record =>
			{
				AddIfHasIp(record, cutoffDate, logEntriesWithIp);
			});

			NotifyProgress($"Audit Failure entries with IPs found = {logEntriesWithIp.Count}");



		}

		private void AddIfHasIp(EventRecord record, DateTime cutoffDate, ConcurrentBag<EventRecord> logEntries)
		{
			try
			{
				if (record.ProviderName == "Microsoft-Windows-Security-Auditing" &&
						record.TimeCreated.HasValue &&
						record.TimeCreated.Value > cutoffDate &&
						record.KeywordsDisplayNames != null &&
						record.KeywordsDisplayNames.Contains("Audit Failure"))
				{
					string xml = record.ToXml();
					XDocument doc = XDocument.Parse(xml);
					XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

					string ipAddress = doc.Descendants(ns + "Data")
																.Where(d => (string)d.Attribute("Name") == "IpAddress")
																.Select(d => d.Value)
																.FirstOrDefault();

					if (!string.IsNullOrWhiteSpace(ipAddress) && ipAddress != "-")
					{
						logEntries.Add(record);
					}
				}
			}
			catch (Exception ex)
			{
				// Optionally log or handle the error
				NotifyProgress(ex.Message);
				throw;
			}
		}

	}
}
