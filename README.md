HackMyCF Report Extractor
=========================

Uses REGEX to analyse a HackMyCF report email and extract information
to a key = value pair for further processing.

This script is to be run as an AWS Lambda function which receives it's
email via an SES Inbound route.

To test the function offline, simply run the python script with the
origins email contents in file.txt