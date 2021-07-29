from os.path import expanduser
import configparser
import boto.sts
import boto.s3
import base64
import xml.etree.ElementTree as ET
import getpass
import time
import os
import sys
import asyncio
import re
from pyppeteer import launch
from pyppeteer.errors import TimeoutError, NetworkError
from html.parser import HTMLParser

# Global mapping from account number to account name.  Built by parsing div tags in source to find account names and numbers.
# SAML return only gives us the numbers, not the actual associated name.  Having name helps people understand which is which.
accountname = {}


class MyHTMLParser(HTMLParser):
    #
    # Parse through the HTML looking for div tag entries that have the account name and number.
    # We will build a (global) dictionary for this to map the names so we can display useful info.
    # Example:
    #      <div class="saml-account-name">Account: ist-cloud-central-app-nprd (770203350335)</div>
    # gives:
    #      accountname{'770203350335' : 'ist-cloud-central-app-nprd'}
    #

    # Flag that indicates we are looking in an interesting div entry that has account details
    processing_account_div = False

    # Callback whenever we see a tag in the HTML
    def handle_starttag(self,tag,attrs):
        # We only care about looking at div tags
        if (tag == "div"):
            for attr in attrs:
                # attrs is a list of attribute tuples (name,value)
                # Look only for the one with class of saml-account-name
                # Set flag so that during handle_data callback we save the value in the data part
                if (attr[0] == "class" and attr[1] == "saml-account-name"):
                    MyHTMLParser.processing_account_div = True
    # Callback for all data between tags.  We only care about data if we previously set the flag
    def handle_data(self,data):
        global accountname
        if (MyHTMLParser.processing_account_div == True):
            # print("Found interesting div content {}".format(data))
            # Pull out content from string
            # Account: ist-cloud-central-app-nprd (770203350335)
            #                       1                   2
            match = re.search(r'Account:\s+(\S+)\s+\((\d+)\)',data)
            if (match):
                accountname[match.group(2)] = match.group(1)
            # Set flag so that we no longer care about content (until we get another div match)
            MyHTMLParser.processing_account_div = False


async def basic_auth(page):
    error = await page.querySelector('.error-box')
    if error:
        error_text = await page.evaluate('(error) => error.textContent', error)
        print(error_text)

    print("Username: ", end='')
    username = input()
    password = getpass.getpass()
    print('')

    await page.focus('[name*=email], [name*=name]')
    await page.keyboard.type(username)
    await page.focus('[name*=pass]')
    await page.keyboard.type(password)
    await page.evaluate("document.querySelector('button[type=submit]').click()")

async def get_duo_message(duo):
    message = await duo.querySelector('#messages-view')
    if message:
        message_text = await duo.evaluate('(message) => message.textContent', message)
        non_whitespace = re.search('[^\s]', message_text)
        if non_whitespace:
            return message_text
    return ''

async def get_duo(page):
    res = await page._client.send("Page.getFrameTree")
    childFrames = res["frameTree"]["childFrames"]
    duo_id = next(
        frame["frame"]["id"]
        for frame in childFrames
        if "duosecurity.com" in frame["frame"]["url"]
    )

    duo = page._frameManager.frame(duo_id)

    return duo

async def duo_auth(page):
    duo = await get_duo(page)

    message = await get_duo_message(duo)
    if message:
        print(message)

    # Click the first available button - should be "Send Me a Push"
    await duo.evaluate("document.querySelector('button.auth-button').click()")
    time.sleep(2)
    await duo_wait(page)

async def duo_wait(page, last_message=''):
    if not await page.querySelector('#duo_iframe'):
        return

    duo = await get_duo(page)

    message = await get_duo_message(duo)
    if message and message != last_message:
        print(message)
    last_message = message

    try:
        await page.waitForNavigation({ 'waitUntil': 'networkidle0', 'timeout': 3000 })
    except TimeoutError:
        await duo_wait(page, last_message)

async def is_duo_available(page):
    return True if await page.querySelector('#duo_iframe') else False

async def is_saml_available(page):
    return True if await page.querySelector('input[name=SAMLResponse]') else False

async def main():
    # region: The default AWS region that this script will connect
    # to for all API calls
    region = os.environ.get('AWS_REGION')

    # output format: The AWS CLI output format that will be configured in the
    # saml profile (affects subsequent CLI calls)
    outputformat = os.environ.get('AWS_OUTPUT_FORMAT')

    # awsconfigfile: The file where this script will store the temp
    # credentials under the saml profile
    awsconfigfile = '/.aws/credentials'

    # Load or create AWS config file
    home = expanduser("~")
    filename = home + awsconfigfile

    # Read in the existing config file
    config = configparser.ConfigParser()
    config.read(filename)

    # The only command line argument is the profile to use
    aws_profile = 'default'
    if len(sys.argv) > 1:
      aws_profile = sys.argv[1]

    # If aws config doesn't exist, create one because boto requires it
    if not config.has_section(aws_profile):
        config.add_section(aws_profile)
        config.set(aws_profile, 'output', outputformat)
        config.set(aws_profile, 'region', region)
        config.set(aws_profile, 'aws_access_key_id', '')
        config.set(aws_profile, 'aws_secret_access_key', '')
        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)

    browser = await launch(
        headless=True,
        executablePath="/usr/bin/chromium-browser",
        args=['--no-sandbox', '--disable-gpu']
    )
    page = await browser.newPage()
    await page.goto(os.environ.get('AWS_LOGIN_URL'))

    try:
        while not await is_saml_available(page) and await page.querySelector('[name*=email], [name*=name]'):
            await basic_auth(page)
            try:
                await page.waitForNavigation({ 'waitUntil': 'networkidle0', 'timeout': 15000 })
            except TimeoutError as ex:
                # When Duo is configured to automatically send push,
                # saml may be already available at this step or will
                # soon become available
                if not await is_saml_available(page) and not await is_duo_available(page):
                    raise ex

        if await is_duo_available(page):
            await duo_auth(page)

    except Exception as ex:
        print('Unidentified error, check screenshot. Error message: ' + str(ex))
        await page.screenshot({'path': 'error.png'})
        await browser.close()
        exit()

    samlElement = await page.waitForSelector('input[name=SAMLResponse]')
    samlValueProperty = await samlElement.getProperty('value')
    samlValue = await samlValueProperty.jsonValue()

    # Save the full HTML content of the page.  We will parse this in a little while to get a mapping of
    # the account number to account name based on the <div> entries we see on the page.
    pagesource = await page.content()

    await browser.close()

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Call HTML parser to look for the <div> tags for the account name and number.  These are stored into the
    # global dictionary accountname for lookup later.
    parser = MyHTMLParser()
    parser.feed(pagesource)

    awsroles = []
    root = ET.fromstring(base64.b64decode(samlValue))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
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

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")
    if len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            role_str = awsrole.split(',', 2)[0]
            role_expanded = role_str.split(':', 5)
            role_account = role_expanded[4]
            role_name = role_expanded[5]
            if '/' in role_name:
              label = role_name.split('/', 2)[1]
            else:
              label = role_str
            print('[%d]: %s    %s' % (i, accountname.get(role_account, role_account), label) )
            i += 1
        print("Selection: ", end="")
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
    conn = boto.sts.connect_to_region(region, profile_name=aws_profile)
    # BU standard is a 8 hour lifespan as passed from Shibboleth to AWS Federated login.  However,
    # the boto assume_role call will do the lowest of that value and the role's max duration.  
    # We may not have permission to look at the IAM role for that max duration so we start at 10 hours and keep decrementing
    # an hour until we get a sucessful call.  
    token = None
    duration_seconds = 36000
    while (token is None and duration_seconds > 0):
        try:
            # print("token={0} duration={1}".format(token, duration_seconds))
            token = conn.assume_role_with_saml(role_arn, principal_arn, samlValue, duration_seconds=duration_seconds)
        except:
            # print("duration={0} did not work".format(duration_seconds))
            duration_seconds = duration_seconds - 3600

    config.set(aws_profile, 'aws_access_key_id', token.credentials.access_key)
    config.set(aws_profile, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(aws_profile, 'aws_session_token', token.credentials.session_token)

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    print('\n\n----------------------------------------------------------------')
    print('Your new access key pair has been stored in the AWS configuration \nfile ({0}) under the {1} profile.'.format(filename, aws_profile))
    print('\nNote that it will expire at {0}.'.format(token.credentials.expiration))
    print('After that, you may the following command to refresh your access key pair:')
    print('')
    print('shib-auth')
    print('----------------------------------------------------------------\n\n')


asyncio.get_event_loop().run_until_complete(main())
