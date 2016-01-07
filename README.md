# Timeseries Ingestion Service

Python service that ingests CSV files of timeseries data into Predix Timeseries service.

## Deploying

Clone this repo.

Change the file manifest.yml to add:

- Client Id
- Client Secret
- Predix UAA instance name
- Predix Timeseries instance name
- Push the service using the cf tool


## Using

Send a post request to the endpoint /upload.

The request must have the Authorization header with the bearer token for a user with access to Predix Timeseries ingestion service.

The request body must be a form-data with the following fields:

- file(s) - the CSV file(s) to be ingested. You can send more than one file in the same request.
- metername - the metername where the data will be saved.
- delimiter - the delimiter char used in the csv file.
- timestamp - the timestamp format used in the csv file. https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
- packetsize - the size of the packets to be sent. Maxium is 5000.
- equipment_index - the equipment name row index in the csv file.
- tagname_index- the source tag name row index in the csv file.
- timestamp_index - the timestamp row index in the csv file.
- value_index - the value row index in the csv file.
- metername_index - the meter name row index in the csv file.
- concat - the char to used for concatenating the equipment name and tag name.