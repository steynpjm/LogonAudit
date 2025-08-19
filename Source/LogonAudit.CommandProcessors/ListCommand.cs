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

			Parallel.ForEach(logEntries, record => AddIfHasIp(record, cutoffDate, logEntriesWithIp));

			NotifyProgress($"Audit Failure entries with IPs found = {logEntriesWithIp.Count}");

			// Work through the log entries with IP and create a summary of counts against each IP address.
			var ipCounts = logEntriesWithIp
				.Select(record => record.ToXml())
				.Select(xml => XDocument.Parse(xml))
				.Select(doc => ExtractIpAddress(doc))
				.Where(ip => !string.IsNullOrWhiteSpace(ip) && ip != "-")
				.GroupBy(ip => ip)
				.Select(g => new { IpAddress = g.Key, Count = g.Count() })
				.OrderByDescending(x => x.Count)
				.Take(_topCount);

			// List each IP address and its count.
			NotifyProgress($"Top {_topCount} IP addresses with counts:");
			foreach (var ipCount in ipCounts)
			{
				NotifyProgress($"{ipCount.IpAddress}: {ipCount.Count}");
			}

			await Task.Delay(5000);
		}

		private static readonly string[] TestIpAddresses = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.3",
    "203.0.113.42",
    "198.51.100.7",
		"192.168.1.11",
		"10.0.0.6",
		"172.16.0.4",
		"203.0.113.43",
		"198.51.100.8",
		"203.0.113.44",
		"198.51.100.9"
];

		//private string? ExtractIpAddress(XDocument doc)
		//{
		//    // For testing: randomly return one of the test IPs
		//    var random = new Random(Guid.NewGuid().GetHashCode());
		//    return TestIpAddresses[random.Next(TestIpAddresses.Length)];
		//}

		private string? ExtractIpAddress(XDocument doc)
		{
			XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
			return doc.Descendants(ns + "Data")
				.FirstOrDefault(d => (string?)d.Attribute("Name") == "IpAddress")
				?.Value;
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

					string? ipAddress = ExtractIpAddress(doc);

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
