using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace LogonAudit.CommandProcessors
{
	public class IPListCommand(string ipAddress, int numberOfDays) : CommandProcessorBase
	{
		private readonly string _ipAddress = ipAddress;
		private readonly int _numberOfDays = numberOfDays;

		public override Task Process()
		{
			string logName = "Security";
			DateTime cutoffDate = DateTime.Now.AddDays(-_numberOfDays);

			ConcurrentBag<EventRecord> logEntriesWithIp = [];
			List<EventRecord> logEntries = [];

			NotifyProgress($"Processing IPList command for the IP {_ipAddress}...");
			NotifyProgress($"Display records for last {_numberOfDays} days.");

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

			Parallel.ForEach(logEntries, record => AddIfHasIp(record, _ipAddress, cutoffDate, logEntriesWithIp));

			string workstationName = string.Empty;	
			string targetUsername = string.Empty;	

			foreach (var logEntry in logEntriesWithIp.OrderBy(x => x.TimeCreated))
			{
				string xml = logEntry.ToXml();
				XDocument doc = XDocument.Parse(xml);
				XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
				workstationName = ExtractWorkstationName(doc) ?? "Unknown";
				targetUsername = ExtractTargetUserName(doc) ?? "Unknown";
				NotifyProgress($"IP Address: {_ipAddress} - Time: {logEntry.TimeCreated} - Workstation: {workstationName} - TargetUserName: {targetUsername}");
			}

			return Task.CompletedTask;
		}

		private void AddIfHasIp(EventRecord record, string ipAddress, DateTime cutoffDate, ConcurrentBag<EventRecord> logEntries)
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

					string? extractedIpAddress = ExtractIpAddress(doc);

					if (!string.IsNullOrWhiteSpace(extractedIpAddress) && extractedIpAddress == ipAddress)
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

		private string? ExtractIpAddress(XDocument doc)
		{
			XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
			return doc.Descendants(ns + "Data")
				.FirstOrDefault(d => (string?)d.Attribute("Name") == "IpAddress")
				?.Value;
		}

		private string? ExtractWorkstationName(XDocument doc)
		{
			XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
			return doc.Descendants(ns + "Data")
				.FirstOrDefault(d => (string?)d.Attribute("Name") == "WorkstationName")
				?.Value;
		}

		private string? ExtractTargetUserName(XDocument doc)
		{
			XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
			return doc.Descendants(ns + "Data")
				.FirstOrDefault(d => (string?)d.Attribute("Name") == "TargetUserName")
				?.Value;
		}

	}
}
