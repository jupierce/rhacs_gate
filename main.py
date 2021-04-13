import os
import typing
import hashlib
import time
import base64
import requests

from flask import Flask, render_template, redirect, url_for, request
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
import phonenumbers
import boto3

SDB_DOMAIN = 'rhacs'
QUAY_ORG_NAME = 'rhacs'

sdb = boto3.client('sdb')
ses = boto3.client('sesv2')

app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY=os.environ['SECRET_KEY'],
    SERVER_NAME=os.environ['SERVER_NAME'],
    WTF_CSRF_SECRET_KEY=os.environ['CRSF_SECRET_KEY'],
    RECAPTCHA_PUBLIC_KEY=os.environ['RECAPTCHA_PUBLIC_KEY'],
    RECAPTCHA_PRIVATE_KEY=os.environ['RECAPTCHA_PRIVATE_KEY'],
))

EMAIL_IDENTITY_ARN = os.environ['EMAIL_IDENTITY_ARN']
EMAIL_IDENTITY = os.environ['EMAIL_IDENTITY']

# Fast fail for undefined env vars
os.environ['QUAY_TOKEN']
os.environ['AWS_ACCESS_KEY_ID']
os.environ['AWS_SECRET_ACCESS_KEY']
os.environ['AWS_DEFAULT_REGION']


class SubmissionForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=3)])
    phone = StringField('Phone Number', validators=[DataRequired()])
    company_name = StringField('Company Name')
    email_address = StringField('Email', validators=[DataRequired(), Email(), Length(min=6, max=40)])
    accept = BooleanField('I have read and agree to all terms and conditions.', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Request Pull Secret')

    def validate_phone(self, phone):
        try:
            p = phonenumbers.parse(phone.data)
            if not phonenumbers.is_valid_number(p):
                raise ValueError()
        except (phonenumbers.phonenumberutil.NumberParseException, ValueError):
            try:
                p = phonenumbers.parse("+1" + phone.data)
                if not phonenumbers.is_valid_number(p):
                    raise ValueError()
            except (phonenumbers.phonenumberutil.NumberParseException, ValueError):
                raise ValidationError('Invalid phone number')


def get_record(record_key: str):
    """
    :param record_key: The sdb record to create or update
    :return: Returns a dict of attribute_name->value. If the item does not exist, an empty dict is returned.
    """
    result = sdb.get_attributes(
        DomainName=SDB_DOMAIN,
        ItemName=record_key,
        ConsistentRead=True,
    )
    values = {}
    attr_list = result.get('Attributes', [])
    for entry in attr_list:
        values[entry['Name']] = entry['Value']
    return values


def set_attributes(record_key: str, d: typing.Dict):
    """
    :param record_key: The sdb record to create or update
    :param d: A dict with key=value where each key is an sdb attribute for the record
    """

    attributes = []
    for k, v in d.items():
        attributes.append({
            'Name': k,
            'Value': str(v),
            'Replace': True,
        })

    sdb.put_attributes(
        DomainName=SDB_DOMAIN,
        ItemName=record_key,
        Attributes=attributes,
    )


def send_email(to, subject, text_body, html_body=None):
    if not html_body:
        html_body = f'''
<html>
    <body>
        {text_body}
    </body>
</html>
'''
    return ses.send_email(
        FromEmailAddress=EMAIL_IDENTITY,
        FromEmailAddressIdentityArn=EMAIL_IDENTITY_ARN,
        Destination={
            'ToAddresses': [to]
        },
        ReplyToAddresses=['do-not-reply@redhat.com'],
        Content={
            'Simple': {
                'Subject': {
                    'Data': subject,
                },
                'Body': {
                    'Text': {
                        'Data': text_body,
                    },
                    'Html': {
                        'Data': html_body,
                    }
                }
            },
        }
    )


def quay_put(api_uri, payload_dict, session=None):
    return requests.put(f'https://quay.io/{api_uri}',
                        json=payload_dict,
                        headers={'Authorization': f'Bearer {os.environ["QUAY_TOKEN"]}'})


def quay_get(api_uri, params=None, session=None):
    return requests.get(f'https://quay.io/{api_uri}',
                        params=params,
                        headers={'Authorization': f'Bearer {os.environ["QUAY_TOKEN"]}'})


@app.route('/terms')
def terms():
    return render_template('/terms.html')


@app.route('/verify')
def verify():
    session = requests.Session()
    email_address = request.args.get('email_address')
    vcode = request.args.get('v')
    record = get_record(email_address)
    quay_robot_name = record['quay_robot_name']
    full_name = record['full_name']
    if record['verification_code'] != vcode:
        index_url = url_for(".index", _external=True)
        return render_template('/verify_fail.html', message=f'Oops - this activation link has expired. Please check your inbox for a more recent verification email or re-submit your information here <a href="{index_url}">{index_url}</a>.')

    # Otherwise, this looks legit. Create a new quay.io robot
    # for this request.
    resp = quay_get(f'api/v1/organization/{QUAY_ORG_NAME}/robots/{quay_robot_name}', session=session)

    if resp.status_code != 200:
        # If not 404, the robot already exists; Do not try to recreate.
        resp = quay_put(f'api/v1/organization/{QUAY_ORG_NAME}/robots/{quay_robot_name}', payload_dict={
            'description': f'Robot for {full_name} ({email_address}).'
        }, session=session)
        if resp.status_code not in [200, 201]:
            send_email(EMAIL_IDENTITY, 'ERROR:ROBOT: Red Hat Advanced Cluster Security',
                       text_body=f'''
Email: {email_address}
Status: {resp.status_code}
{resp.content}'''
                       )
            print(f'Error establishing robot for {email_address}: {resp.content}')
            return render_template('/verify_fail.html', message='An error was encountered. Please try again later.')

    for repo in ['collector', 'main', 'scanner', 'scanner-db']:
        resp = quay_put(f'api/v1/repository/{QUAY_ORG_NAME}/{repo}/permissions/user/{QUAY_ORG_NAME}+{quay_robot_name}', payload_dict={
            'role': 'read'
        }, session=session)
        if resp.status_code != 200:
            send_email(EMAIL_IDENTITY, f'ERROR:ROBOT:PERM:{repo}: Red Hat Advanced Cluster Security',
                       text_body=f'''
Status: {resp.status_code}
Email: {email_address}
{resp.content}'''
                       )
            print(f'Error establishing permissions for {email_address}: {resp.content}')
            return render_template('/verify_fail.html', message='An error was encountered. Please try again later.')

    resp = quay_get(f'api/v1/organization/{QUAY_ORG_NAME}/robots/{quay_robot_name}', session=session)
    if resp.status_code != 200:
        print(f'Error retreiving user token {email_address}: {resp.content}')
        return render_template('/verify_fail.html', message='An error was encountered. Please try again later.')

    quay_robot_token = resp.json()['token']
    conf_auth = base64.b64encode(f'{quay_robot_name}:{quay_robot_token}'.encode('utf-8')).decode('utf-8')
    return render_template('/verify_success.html',
                           robot_name=f'{QUAY_ORG_NAME}+{quay_robot_name}',
                           token=quay_robot_token,
                           conf_auth=str(conf_auth))

@app.route('/submitted')
def submitted():
    return render_template('/submitted.html')


@app.route('/', methods=['POST', 'GET'])
def index():
    form = SubmissionForm()
    if form.validate_on_submit():
        email_address = form.email_address.data
        existing = get_record(email_address)
        attributes: typing.Dict = {}
        if not existing:
            # Do not allow subsequent form submissions to replace original values.
            attributes.update({
                'full_name': form.full_name.data,
                'company_name': form.company_name.data,
                'phone': form.phone.data,
            })

        quay_robot_name = hashlib.sha256(email_address.encode('utf-8')).hexdigest()
        verification_code = hashlib.sha256(f'{email_address}{int(time.time())}'.encode('utf-8')).hexdigest()
        attributes.update({
            'awaiting_verification': True,  # we are expecting a email link to be clicked
            'verification_code': verification_code,
            'quay_robot_name': quay_robot_name,
        })

        set_attributes(email_address, attributes)

        verify_url = url_for('verify', email_address=email_address, v=verification_code, _external=True)
        email_result = send_email(email_address, 'Red Hat Advanced Cluster Security - Email Verification',
                                  text_body=f'''Thank you for your interest in Red Hat Advanced Cluster Management (RHACS).
Please navigate your web browser to {url_for('verify', vcode={verification_code})} to verify your email and receive credentials to access RHACS content.
''',
                                  html_body=f'''
<html>
    <body>
        Thank you for your interest in Red Hat Advanced Cluster Management (RHACS).
        Please use <a href='{verify_url}'>this link</a> to verify your email and receive credentials to access RHACS content.
    </body>
</html>
'''
                                  )
        print(f'Sent email: {email_result}')

        return redirect(url_for('submitted'))

    return render_template('/index.html', form=form)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
