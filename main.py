from __future__ import print_function

import re
import string
import boto3
import urllib


s3 = boto3.client('s3')
s3r = boto3.resource('s3')

parser_type = "hackmycf_v1.0"
bucket = key = ""
contents = ""
debug = False


def main():
    # Main function used for debugging
    global debug
    event = context = {}
    debug = True
    lambda_handler(event, context)


def lambda_handler(event, context):

    global contents
    get_s3_params(event)
    fetch_ses_s3_email()

    # Check this is a CF report
    if "ColdFusion Server Security Report" not in contents:
        print("Not a valid email. Exiting.")
        return

    # Remove linebreaks for simple REGEX
    nonlinebreak = contents # Used for special REGEX
    contents = string.replace(nonlinebreak, '\n', ' ')

    val = {}
    val['cf_version'] = extract_value("ColdFusion Version:\*\ ([0-9,]+)")
    val['os_version'] = extract_value("Operating System:\*\ ([\w0-9\. ]+) *")
    val['web_server'] = extract_value("Web Server:\*\ ([\w0-9\-//0-9/. ]+) *")
    if val['web_server'] == "NULL":
        val['web_server'] = extract_value("Web Server Software:\*\ ([\w0-9\-//0-9/. ]+) *")
    val['hostname'] = extract_value("Report \[([\w\.]+)\]")

    if extract_value("Probe API Version:\*[ ]*([0-9\.]+)") != "NULL":
        val['probe_enabled'] = 'true'

        val['local_ip'] = extract_value("Server Local IP:\*[ ]*([0-9\.]+)")
        val['probe_api_version'] = extract_value("Probe API Version:\*[ ]*([0-9\.]+)")
        val['jvm_version'] = extract_value("Java JVM:\*[ ]*([\w 0-9._]+)*")
        val['jee_server'] = extract_value("JEE Server:\*[ ]*([\w 0-9._//]+)*")
        val['hotfix_jars'] = extract_value("Hotfix Jars:\*[ ]*([\w.]+)*")

        # Hotfixes
        cfissues = re.findall("ColdFusion ([0-9\.]+) [\w //:<]+> (Installed|Not Installed)", contents)
        cfapsb = re.findall("(APSB[0-9\-]+)[ ]*<[\w://]+>[\w0-9 ]+ \- (Installed|Not Installed)", contents)

        for x in cfissues + cfapsb:
            val['hotfix_' + x[0]] = x[1].lower()

        # Connector Summary (No clear way to extract information)
        val['connectors'] = extract_value("Newer Connector Available").lower()
        if val['connectors'] == 'null':
            val['connectors'] = 'up to date'

    else:
        val['probe_enabled'] = 'false'

    if extract_value("(=3D=3D Error =3D=3D)") != "NULL":
        val["connection_issue"] = 'true'

    # TLS / SSL Report
    if extract_value("(=3D=3D TLS // SSL Report =3D=3D)") != "NULL":
        val['https_enabled'] = 'true'
        val['common_name'] = extract_value("Common Name:\*[ ]*([\w\.]+)")
        val['certificate_expiry'] = extract_value("Certificate Expiration Date:\*[ ]*([\w, ]+)")
        val['public_key_size'] = extract_value("Public Key Size:\*[ ]*([0-9]+)")
        val['signature_algorithm'] = extract_value("Signature Algorithm:\*[ ]*([\w]+)")

        val['truststore_mozilla_nss_04_2015'] = get_truststore_state("Mozilla NSS 04/2015")
        val['truststore_microsoft_04_2015'] = get_truststore_state("Microsoft 04/2015")
        val['truststore_java_6'] = get_truststore_state("Java 6 Update 65")
        val['apple_osx_10_10_3'] = get_truststore_state("Apple OS X 10.10.3")

        val['ssl_v2'] = get_cipher_state("SSLv2")
        val['ssl_v3'] = get_cipher_state("SSLv3")
        val['tls_v1'] = get_cipher_state("TLSv1")
        val['tls_v1.1'] = get_cipher_state("TLSv1.1")
        val['tls_v1.2'] = get_cipher_state("TLSv1.2")

        val['compression_support'] = extract_value("Compression Supported:\*[ ]*([\w]+)")
        val['heartbleed'] = extract_value("Heartbleed:\*[ ]*([\w ]+)*").lower()

        val['client_renegotiation'] = extract_value("Client Initiated Session Renegotiation ([\w]+)").lower()
        val['secure_renegotiation'] = extract_value("Secure Session Renegotiation ([\w]+)").lower()

    else:
        val['https_enabled'] = 'false'

    # Security Issues Summary
    val['critical_count'] = extract_value("Found ([0-9]+) Critical Issues")
    val['important_count'] = extract_value("Found ([0-9]+) Important Issues")
    val['warning_count'] = extract_value("Found ([0-9]+) Warnings")
    val['total_count'] = extract_value("We found \*([0-9]+) security issues\* on your")

    # List of issues
    val['critical_issues'] = get_issue_summary('critical', nonlinebreak)
    val['important_issues'] = get_issue_summary('important', nonlinebreak)
    val['warning_issues'] = get_issue_summary('warning', nonlinebreak)

    # Debug if needed
    if debug:
        debug_output(val)

    # Key Value output for Splunk
    remove_ses_s3_email()
    print(keyval_output(val))

    return


def keyval_output(values):
    global parser_type
    buf = 'parser_type="' + parser_type + '" '
    for y in values:
        buf += y + '="' + values[y] + '" '
    return buf


def get_s3_params(event):
    global bucket, key, debug
    if not debug:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')


def fetch_ses_s3_email():
    global contents, debug, bucket, key
    if debug:
        contents = open("file.txt", 'rU').read()
    else:
        try:
            waiter = s3.get_waiter('object_exists')
            waiter.wait(Bucket=bucket, Key=key)

            response = s3r.Bucket(bucket).Object(key)
            contents = response.get()["Body"].read()
        except Exception as e:
            print(e)
            print('Error getting object {} from bucket {}. Make sure they exist '
                  'and your bucket is in the same region as this '
                  'function.'.format(key, bucket))


def remove_ses_s3_email():
    global debug, bucket, key
    if not debug:
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except Exception as e:
            print(e)


def get_truststore_state(store):
    return extract_value(store + ":[ ]*([\w]+)")


def get_cipher_state(cipher):
    return extract_value("\*" + cipher + "\*[ ]*(Disabled|Enabled)").lower()


def get_issue_summary(mode, buffer):
    regex = "[ ]{0,5}"+ mode + "\n[ ]*([\w //]+)"
    value = ", ".join(re.findall(regex, buffer))
    if value:
        return value
    else:
        return 'NULL'


def debug_output(values):
    for y in values:
        print(y, ':', values[y])


def extract_value(regex):
    value = re.search(regex, contents)

    if value:
        return value.group(1).strip()
    else:
        return 'NULL'


if __name__ == '__main__':
    main()

