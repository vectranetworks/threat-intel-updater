# Vectra Threat Intel Updater
## Overview
This script is designed to automate the process of collecting threat intel IOCs from one or 
more sources and updating Cognito Detect's threat intel feeds.  
The script is controlled by the configuration file *config.json* which will need to be updated
accordingly for the environment and the threat intel sources.

### Threat Intel Sources
The script supports the following sources:
- CrowdStrike
- FireEye
- Anomali
  
## Setup
### Installing requirements
Python3.6+ is required.  

Multiple python packages are required.  To install the requirements with pip, please run
> sudo pip3 install -r requirements.txt

### Configuration
Once the required python modules are installed, please edit the file **config.json**.  

Update the fields:  
**"cognito"** section:
> `brain` – contains the IP or hostname of your Vectra Cognito Detect instance  
> `token` – contains the API token generated under a Cognito user's profile
 
**"crowdstrike"** section:
> `api_id` – the Falcon API id that has been generated for a user  
> `secret` – the Falcon API secret that was provided when the API configuration was generated for the user
 
**crowdstrike "feeds"** section:  
> `name` – the name of the threat feed that the script will configure in Detect  
> `stix_file` – the name of the STIX file the STIX information is written to.  Please keep these unique per feed.  
> `age` – the maximum age in days of an indicator  
> `max` – the maximum number of indicators returned for this specific feed (CS support maximum of 50000)  
> `filter` – (optional) API filter notation to return indicators based on region, actor, malware family, industry, 
> etc.  Please refer to CrowdStrike's document.

**"fireeye"** section:
> `api_id` – the Falcon API id that has been generated for a user  
> `secret` – the Falcon API secret that was provided when the API configuration was generated for the user  
> `X-App-Name` - please don't change the default value

**fireeye "feeds"** section:  
> `name` – the name of the threat feed that the script will configure in Detect  
> `stix_file` – the name of the STIX file the STIX information is written to.  Please keep these unique per feed.  
> `age` – the maximum age in days of an indicator  
> `max` – the maximum number of indicators returned for this specific feed (CS support maximum of 50000)  
> `filter` – (optional) API filter parameters.  See FireEye's documentation.

**"anomali"** section:
> `user` – the Anomali user  
> `secret` – the Anomali password for the supplied user

**anomali "feeds"** section:  
> `collection_list` – The list of Anomali Collections to retrieve  
> `confidence` - default confidence level

See supplied config for examples.  

Note: Feeds that do not have a complete configuration will be skipped over.  All supplied keys must have a non-null value.  
Example: `"skip": ""`

## Executing the script
### Option 1 - as a Linux service
Edit the **indicators.service** file:  
> `WorkingDirectory` - configure the correct working directory for the script  
> `User` – configure the user the service will run as (recommend not running as root)  
> `ExecStart` – update to reflect the correct path to the indicators.py script file  
 
Once configuration is complete, copy this config file to `/etc/systemd/system/`
 
To enable the service:  
  `sudo systemctl enable indicators`
 
To start the service:  
  `sudo systemctl start indicators`
 
To check the status of the service and see the most recent logs:  
  `sudo systemctl status indicators`

### Option 2 - manually or run via cron
To run the script manually or via a cron job, supply the *--cron* flag.  
Example: `python3 indicators.py --cron`

## Logging
Logging output is sent to the local host's syslog facilities 