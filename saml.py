"""
Based on the script from
https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS#postCommentsTx1LDN0UBGJJ26Q
Changes were made to
- use python3 to get rid of unicode annoyances
- use separate config and credentials files as aws cli does by default
- report cleanly a failed authentication

Requires boto, beautifulsoup4 and requests_ntlm (all on requirements.txt file)
"""

import sys
import boto.sts
import boto.s3
import requests
import getpass
import configparser
import base64
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from os.path import expanduser
from requests_ntlm import HttpNtlmAuth

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-east-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile and awscredentialsfile: The files where this script will store the temp
# credentials under the saml profile
awscredentialsfile = '/.aws/credentials'
awsconfigfile = '/.aws/config'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# fully qualified domain name of your adfs
fqdn = 'your.domain.here'

# idpentryurl: The initial URL that starts the authentication process.
idpentryurl = 'https://'+fqdn+'/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

##########################################################################

# Get the federated credentials from the user
username = input("Username (domain\\username): ")
password = getpass.getpass(prompt="Password: ")

# Initiate session handler
session = requests.Session()

# Programatically get the SAML assertion
# Set up the NTLM authentication handler by using the provided credential
session.auth = HttpNtlmAuth(username, password, session)

# Opens the initial AD FS URL and follows all of the HTTP302 redirects
# The adfs server I am using this script against returns me a form, not ntlm auth, so we cheat here giving it a
# browser header so it gives us the NTLM auth we wanted.
headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
response = session.get(idpentryurl, verify=sslverification, headers=headers)

# Debug the response if needed
# print(response)

# Exits if the authentication failed
if response.status_code != 200:
    print('Authentication failed!')
    sys.exit(1)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

# Decode the response and extract the SAML assertion
soup = BeautifulSoup(response.text, "html.parser")
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if inputtag.get('name') == 'SAMLResponse':
        # print(inputtag.get('value'))
        assertion = inputtag.get('value')

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))

for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)


# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# # Remove non-admin roles
# for index, role in enumerate(awsroles):
#     if "Admin" not in role:
#         awsroles.pop(index)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print("")
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print ('[', i, ']: ', awsrole.split(',')[0])
        i += 1

    print("Selection: "),
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]

else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region, anon=True)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the region and output format into the AWS config file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
# config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the credentials into a specific profile instead of clobbering
# the default credentials
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Write the AWS STS token into the AWS credentials file
filename = home + awscredentialsfile

# Read in the existing config file
config = configparser.RawConfigParser()
# config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the credentials into a specific profile instead of clobbering
# the default credentials
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'aws_access_key_id', token.credentials.access_key)
config.set('saml', 'aws_secret_access_key', token.credentials.secret_key)
config.set('saml', 'aws_session_token', token.credentials.session_token)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print('\n\n--------------------------------------------------------------------------------------------')
print('Your new access key pair has been stored in your AWS configuration files under the saml profile.')
print('Note that it will expire at {0}.'.format(token.credentials.expiration))
print('After this time you may safely rerun this script to refresh your access key pair.')
print('To use this credential call the AWS CLI with the --profile option ')
print('(e.g. aws --profile saml ec2 describe-instances).')
print('------------------------------------------------------------------------------------------------\n\n')

