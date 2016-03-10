# AWS CLI keys with ADFS credentials

## WhuT!?

This script will authenticate with your adfs and get a temporary pair of keys to use with aws cli under the saml profile.

If you have more than one role available the script will present a list of roles to choose from.

After selecting a role the script will save the keys under the saml profile and you can use them as simple as

```aws --profile saml s3 ls```

Run it with a simple

```python saml.py```

Enjoy!

## How-to "install" :D

Install the requirements
```pip install -r requirements.txt```

Edit the saml.py file variables:

- fqdn = domain of your adfs
- awscredentialsfile and awsconfigfile = paths to these files, usually on the .aws folder under your home folder

## Notes

Totally based on the script from https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS#postCommentsTx1LDN0UBGJJ26Q

Changes were made to
- use python3 to get rid of unicode annoyances
- use separate config and credentials files as aws cli does by default
- report cleanly a failed authentication