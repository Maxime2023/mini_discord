import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import json
USER_POOL_ID = 'eu-central-1_Lj6tzlFad'
CLIENT_ID = '24shf0nduvsojrki0fivv6r5sc'
client = boto3.client('cognito-idp')

def login(username, password):
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            },
            ClientMetadata={
                'username': username,
                'password': password,
            }
        )
        print(resp)
        return  {
            'code': 200,
            'message': {
                'access_token': resp['AuthenticationResult']['IdToken'],
                'refresh_token': resp['AuthenticationResult']['RefreshToken'],
                'expires_in': resp['AuthenticationResult']['ExpiresIn'],
                'token_type': resp['AuthenticationResult']['TokenType']
            }
        }
    except Exception as e:
        print(str(e))
        return  {
            'message': str(e), 
            'error': True, 
            'success': False,
            'code': 400
        }

def register(username, password):
    try:
        resp = client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password)
        client.admin_update_user_attributes(
            UserPoolId=USER_POOL_ID,
            Username=username,
            UserAttributes=[
            {
                'Name': 'email_verified',
                'Value': 'true'
            },
            ]
        )
        client.admin_add_user_to_group(
            UserPoolId=USER_POOL_ID,
            Username=username,
            GroupName='users'
        )
        client.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID,
            Username=username,
        )
        print("registred")
        return {
            'error': False, 
            'success': True, 
            'message': "Registred", 
            'data': None,
            'code': 200
        }
    except Exception as e:
        print(str(e))
        return {
            'error': True, 
            'success': False, 
            'message': str(e), 
            'data': None,
            'code': 400
        }

def change_to_admin(username):
    client.admin_add_user_to_group(
        UserPoolId=USER_POOL_ID,
        Username=username,
        GroupName='SuperAdmin'
    )
    return {
        'error': False, 
        'success': True, 
        'message': "Changed", 
        'data': None,
        'code': 200
    }

def lambda_handler(event, context):
    body_parsed = json.loads(event['body'])
    username=body_parsed['username']

    if event['pathParameters']['ressource'] == 'login':
        password=body_parsed['password']
        response = login(username, password)
    if event['pathParameters']['ressource'] == 'register':
        password=body_parsed['password']
        response = register(username, password)
    if event['pathParameters']['ressource'] == 'admin':
        response = change_to_admin(username)

    return {
        'headers': {
            'Access-Control-Allow-Origin' : '*',
            'Access-Control-Allow-Credentials' : True
        },
        'statusCode': response['code'],
        'body': json.dumps(response['message']),
    }

if __name__ == '__main__':
    lambda_handler('test', 'test')