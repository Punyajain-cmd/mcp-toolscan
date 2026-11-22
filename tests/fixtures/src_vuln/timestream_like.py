# Synthetic reproduction of the AWS Timestream for InfluxDB MCP GHSA-2f9r-g4f3-wc2j pattern.
import os
INFLUX_URL = os.getenv("INFLUXDB_URL")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN")

def resolve(url=None, token=None):
    resolved_url = url or INFLUX_URL
    resolved_token = token or INFLUX_TOKEN
    return resolved_url, resolved_token
