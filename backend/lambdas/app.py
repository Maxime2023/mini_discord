import json
import boto3
client = boto3.client('dynamodb')
import uuid
from boto3.dynamodb.conditions import Key

def scanRecursive(tableName, **kwargs):
    dynamo = boto3.resource('dynamodb')
    dbTable = dynamo.Table(tableName)
    response = dbTable.scan(**kwargs)
    if kwargs.get('Select')=="COUNT":
        return response.get('Count')
    data = response.get('Items')
    while 'LastEvaluatedKey' in response:
        response = kwargs.get('table').scan(ExclusiveStartKey=response['LastEvaluatedKey'], **kwargs)
        data.extend(response['Items'])
    return data

def get_servers(event):
    servers = scanRecursive("mini_discord")
    list_servers = []
    for server in servers:
        list_servers.append({"server": server['server'], "id": server['id']})
    return list_servers

def get_channels(event):
    server_id = event['pathParameters']['serverid']
    servers = scanRecursive("mini_discord")
    list_channels = []
    for server in servers:
        if server['id'] == server_id:
            return server['channels']
    return 'no channels'

def get_channel(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    server_data = ""
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == server_id:
            for channel in server['channels']:
                if channel['id'] == channel_id:
                    return channel
    return "channel id"

def delete_channel(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    servers = scanRecursive("mini_discord")
    server_data = ""
    remove_channel = []
    for server in servers:
        if server['id'] == server_id:
            server_data = server['channels']
            break
    for channel in server_data:
        if channel['id'] != channel_id:
            remove_channel.append(channel)
    
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    table.update_item(
        Key={
            'id': server_id,
        },
        UpdateExpression="set channels = :g",
        ExpressionAttributeValues={
        ':g': remove_channel
        },
        ReturnValues="UPDATED_NEW"
        )
        
    return remove_channel
    

def get_server_by_id(event):
    event_splited = event['path'].split('/')
    id = event_splited[len(event_splited) - 1]
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == id:
            return server
    return "No id found"

def delete_server_by_id(event):
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    event_splited = event['path'].split('/')
    id = event_splited[len(event_splited) - 1]
    table = client.Table("mini_discord")
    table.delete_item(
        Key = {
            'id': id
        }
    )
    return ("deleted")

def create_server(event):
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    body = json.loads(event['body'])
    table.put_item(
        Item = {
        'id': str(uuid.uuid1()),
        'server': body['server_name'],
        'admins':  [{'email': body['email']}],
        'channels': []
        }
    )
    return "Ressource Created"

def create_channel(event):
    server_id = event['pathParameters']['serverid']
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    body = json.loads(event['body'])
    server = table.get_item(
        Key = {'id': server_id}
    )
    server_channels = server['Item']['channels']
    server_channels.append({"id": str(uuid.uuid1()), "name": body['name'], "messages": []})
    table.update_item(
        Key={
            'id': server_id,
        },
        UpdateExpression="set channels = :g",
        ExpressionAttributeValues={
        ':g': server_channels
        },
        ReturnValues="UPDATED_NEW"
        )
    return server_channels

def get_messages(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    server_data = ""
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == server_id:
            for channel in server['channels']:
                if channel['id'] == channel_id:
                    return channel['messages']
    return 'no msg'

def find_channel(server_id, channel_id):
    dynamodb = boto3.resource('dynamodb')

    table = dynamodb.Table('mini_discord')
    response = table.query(
        KeyConditionExpression=Key('id').eq(server_id)
    )
    for channel in response['Items'][0]['channels']:
        if channel['id'] == channel_id:
            return channel
    return "no channels"
            
def create_message(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    body = json.loads(event['body'])
    new_msg = {"id": str(uuid.uuid1()), "writter": body['email'], "text": body['text']}
    channel = find_channel(server_id, channel_id)
    channel['messages'].append(new_msg)
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    table.update_item(
        Key={
            'id': server_id,
        },
        UpdateExpression="set channels = :g",
        ExpressionAttributeValues={
        ':g': [channel]
        },
        ReturnValues="UPDATED_NEW"
    )
    return 'message created'

def get_message(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    message_id = event['pathParameters']['messageid']
    channel = find_channel(server_id, channel_id)
    for message in channel['messages']:
        if message['id'] == message_id:
            return message
    return 'not found'

def delete_message(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    message_id = event['pathParameters']['messageid']
    channel = find_channel(server_id, channel_id)
    deleted_msg = []
    for message in channel['messages']:
        if message['id'] != message_id:
            deleted_msg.append(message)
    channel['messages'] = deleted_msg
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    table.update_item(
        Key={
            'id': server_id,
        },
        UpdateExpression="set channels = :g",
        ExpressionAttributeValues={
        ':g': [channel]
        },
        ReturnValues="UPDATED_NEW"
    )
    return 'deleted'


def lambda_handler(event, context):
    data_to_return = "ok"
    statusCode = 200
    if event['resource'] == '/servers':
        if event['httpMethod'] == 'GET':
            data_to_return = get_servers(event)
        if event['httpMethod'] == 'POST':
            data_to_return = create_server(event)
            statusCode = 201
    if event['resource'] == '/servers/{serverid}':
        if event['httpMethod'] == 'GET':
            data_to_return = get_server_by_id(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return = delete_server_by_id(event)
    if event['resource'] == '/servers/{serverid}/channels':
        if event['httpMethod'] == 'GET':
            data_to_return = get_channels(event)
        if event['httpMethod'] == 'POST':
            data_to_return = create_channel(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}':
        if event['httpMethod'] == 'GET':
            data_to_return = get_channel(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return = delete_channel(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}/messages':
        if event['httpMethod'] == 'GET':
            data_to_return = get_messages(event)
        if event['httpMethod'] == 'POST':
            data_to_return = create_message(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}/messages/{messageid}':
        if event['httpMethod'] == 'GET':
            data_to_return = get_message(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return = delete_message(event)
        
    return {
        "statusCode": statusCode,
        "body": json.dumps(data_to_return)
    }
