# SPSWakeUp Features

**Logging**:

- Log script results in log file,
- Cleaning log files after 30 days (can be set with xml input file).

**Warm-Up SharePoint Sites**:

- Wakes up all site collections, web applications, and host-named site collections in a SharePoint environment.
- Uses multi-threading with `Invoke-WebRequest` to optimize warm-up performance.

**Central Administration Support**:

- Includes functionality to warm up Central Administration sites and related administration pages.

**Task Scheduler Integration**:

- Automates the warm-up process by creating scheduled tasks using `Add-SPSSheduledTask`.
- Supports daily, startup, and IIS reset triggers for task execution.

**HOSTS File Management**:

- Adds SharePoint web application URLs to the system `HOSTS` file for local resolution.
- Creates backups of the `HOSTS` file and cleans up old backup files.

**Loopback Check Management**:

- Disables the Windows loopback check to prevent authentication issues during warm-up.

**SharePoint User Policy Management**:

- Adds read access for a specified user account to all web applications.

**Resource Monitoring**:

- Reports memory usage for each SharePoint worker process (`w3wp.exe`) after the warm-up.

**Error Logging and Event Logging**:

- Logs errors and events to the Windows Event Log under a custom log source (`SPSWakeUp`).
- Provides detailed error handling and reporting for troubleshooting.

**SharePoint Version Detection**:

- Detects the installed SharePoint version and adjusts behavior accordingly (e.g., loading the appropriate PowerShell module or Snapin).

**Transcript Logging**:

- Supports PowerShell transcript logging for detailed execution logs.

**Compatibility**:

- Designed for all supported SharePoint versions (2016 to Subscription Edition).

**Customizable Throttling**:

- Dynamically determines the throttle limit for multi-threaded requests based on the system's CPU configuration.

**Cleanup Utilities**:

- Includes functions to clean up old log files and backup files to maintain a clean environment.

**Error Handling**:

- Provides robust error handling for operations like scheduled task creation, web requests, and SharePoint object retrieval.

**Administrator Privileges Check**:

- Ensures the script is executed with administrator rights for proper functionality.
