# Check IPs


This script takes a list of IPs and runs these through Virustotal. It reports any IPs that are not completely clean.
The IPs should each be placed on a separate line in the input-file.


## Installation

1. Download the repository.
2. Find your virustotal API-key from virustotal.com
3. Create a folder in the repository folder called `credentials`
4. Create a file in this folder called `virustotal_api_key.txt` and paste your api key in this file.


## Use

Syntax:
```bash
py check_ips.py -i|--input <input filename> [--throttle] [-o|--output <output filename>]
```


Use the `throttle` option if you have a standard public API-key which has a quota of 4 requests pr. minute.


If no `--output <filename>` is specified, the script will place any suspicious IPs in a file with a filename based on the input filename
but with `_filtered.txt` stuck at the end instead of the previous filename extension.