This is an Apache Server Log Analyzer using python.
Program is designed to collect numerous log files and run customized search queries and filters.

Allows to filter by IPs, HTTP actions, and dates.

Useful for detecting activity on a server.



#CODE:



from datetime import datetime
import re
import os

from pathlib import Path

import pytz

#log file

class LogAnalyzer:
    analyzes logs within a given folder
    def __init__(self, folder):
        self.folder = folder
        self.logs = []
        self.read_logs()

    def read_logs(self):
        files = []
        for filename in os.listdir(self.folder):
            if filename.startswith("access_") and filename.endswith(".log"):
                files.append(filename)

        for file in files:
            filepath = os.path.join(self.folder, file)
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    self.logs.append(line)
        
    def filter_by_date(self, start, end):
        filtered = []
        for line in self.logs:
            datematch = re.search(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]", line)
            if datematch:
                timestmp_str = datematch.group(1)
                log_date = datetime.strptime(timestmp_str, "%d/%b/%Y:%H:%M:%S %z")
                if start <= log_date <= end:
                    filtered.append(line)

        return filtered
    
    def count_field(self, lines, field_index, filter_status=None, filter_action=None):
        counts = {}

        for line in lines:
            parts = line.split()

            if len(parts) < 9:
                continue

            # extracting fields
            ip_address = parts[0]
            
            status_code = parts[8]

            action = parts[5].replace('"','') # extracting the HTTP method

            # apply the filters



            field_value = parts[field_index].replace('"', '') if field_index == 5 else parts[field_index]

            if self.apply_filters(status_code, action, filter_status, filter_action):   
                counts[field_value] = counts.get(field_value, 0) + 1

        return counts
    
    def apply_filters(self, status_code, action, filter_status, filter_action):
        if filter_status and status_code != filter_status:
            return False
        if filter_action and action != filter_action:
            return False
        return True

    
    def get_top_n(self, counts, n):
        # turn dictionary into a list and then sort

        sorted_list = sorted(counts.items(), key=lambda item: item[1], reverse=True)

        # return only top N items
        return sorted_list[:n]
    
    def top_n_ips(self, n, start_date=None, end_date=None):
        
        if start_date and end_date:
            filtered_logs = self.filter_by_date(start_date,end_date)
        else:
            filtered_logs = self.logs

        counts = self.count_field(filtered_logs, 0) #HTTP action is the sixth field
        return self.get_top_n(counts, n)
    
    def top_n_actions(self, n, start_date=None, end_date=None):
        if start_date and end_date:
            filtered_logs = self.filter_by_date(start_date, end_date)
        else:
            filtered_logs = self.logs

        counts = self.count_field(filtered_logs, 5)  # HTTP action is the sixth field
        return self.get_top_n(counts, n)
    
    def top_n_ips_with_status(self, status_code, n, start_date=None, end_date=None):
        if start_date and end_date:
            filtered_logs = self.filter_by_date(start_date, end_date)
        else:
            filtered_logs = self.logs

        counts = self.count_field(filtered_logs, 0, filter_status=status_code)
        return self.get_top_n(counts,n)
    
    def top_n_ips_with_action_and_status(self, action, status_code, n, start_date=None, end_date=None):
        if start_date and end_date:
            filtered_logs = self.filter_by_date(start_date, end_date)
        else:
            filtered_logs = self.logs
            
        counts = self.count_field(filtered_logs, 0, filter_status=status_code, filter_action=action)
        return self.get_top_n(counts, n)


def LogAnalyzerApp():
    log_folder = '.' # project folder

    analyzer = LogAnalyzer(log_folder)

    # sample queries

    
    # between 2/18/2016 and 3/01/2016

    start_date = datetime(2016, 2, 18, tzinfo=pytz.UTC)  # Set timezones to UTC for compatability
    end_date = datetime(2016, 3, 1, tzinfo=pytz.UTC)  

    
    # to search without date filters, leave out arguments

    print("Top 10 client IPs between 2/18/2016 and 3/01/2016:")
    top_ips = analyzer.top_n_ips(10, start_date, end_date)
    for ip, count in top_ips:
        print(f"{ip}: Count {count}")

    print("Top 3 HTTP actions between 2/18/2016 and 3/01/2016:")
    top_actions = analyzer.top_n_actions(3, start_date, end_date)
    for action, count in top_actions:
        print(f"{action}: {count}")

    print("Top 5 client IPs with status code 404 between 2/18/2016 and 3/01/2016:")
    top_status_code = analyzer.top_n_ips_with_status("404", 5, start_date, end_date)
    
    for ip, count in top_status_code:
        print(f"{ip}: {count}")

    print("Top 5 client IPs with POST action and status code 200 between 2/18/2016 and 3/01/2016:")
    top_action_and_status = analyzer.top_n_ips_with_action_and_status("POST", "200", 5, start_date, end_date)
    
    for ip, count in  top_action_and_status:
        print(f"{ip}: {count}")

if __name__ == "__main__":
    LogAnalyzerApp()


"""

      
    
        



