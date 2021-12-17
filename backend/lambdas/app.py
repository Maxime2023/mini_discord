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

def check_authorisations(event, to_delete, data):
    email = event['requestContext']['authorizer']['claims']['email']
    if event['requestContext']['authorizer']['claims']['cognito:groups'] == 'users':
        if to_delete == "server":
            servers = scanRecursive("mini_discord")
            for server in servers:
                if server['id'] == data:
                    if email in server['admins']:
                        return True
                    else:
                        return False
        if to_delete == "channel":
            server_id = data[0]
            channel_id = data[1]
            server_data = ""
            servers = scanRecursive("mini_discord")
            for server in servers:
                if server['id'] == server_id:
                    for channel in server['channels']:
                        if channel['id'] == channel_id:
                            if email in channel['admins']:
                                return True
                            else:
                                return False
        if to_delete == "message":
            server_id = data[0]
            channel_id = data[1]
            message_id = data[2]
            data = [server_id, channel_id, message_id]
            channel = find_channel(server_id, channel_id)
            for message in channel['messages']:
                if message['id'] == message_id:
                    if message['writter'] == email:
                        return True
                    else:
                        return False
        return False
    return True

def get_servers(event):
    email = event['requestContext']['authorizer']['claims']['email']
    servers = scanRecursive("mini_discord")
    list_servers = []
    if event['requestContext']['authorizer']['claims']['cognito:groups'] == 'SuperAdmin':
        for server in servers:
            list_servers.append({"server": server['server'], "id": server['id']})
    else:
        for server in servers:
            if email in server['members']:
                list_servers.append({"server": server['server'], "id": server['id']})
    return list_servers, 200

def get_channels(event):
    server_id = event['pathParameters']['serverid']
    servers = scanRecursive("mini_discord")
    list_channels = []
    for server in servers:
        if server['id'] == server_id:
            return server['channels'], 200
    return [], 200

def get_channel(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    server_data = ""
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == server_id:
            for channel in server['channels']:
                if channel['id'] == channel_id:
                    return channel, 200
    return "Ressource not found", 404

def delete_channel(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    if check_authorisations(event, "channel", [server_id, channel_id]) == False:
        return "Not authorized", 401
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
        
    return "Ressource Deleted", 201
    

def get_server_by_id(event):
    event_splited = event['path'].split('/')
    id = event_splited[len(event_splited) - 1]
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == id:
            return server, 200
    return 'Ressource not found', 404

def delete_server_by_id(event):
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    event_splited = event['path'].split('/')
    id = event_splited[len(event_splited) - 1]
    if check_authorisations(event, "server", id) == False:
        return "Not Authorized", 401
    table = client.Table("mini_discord")
    table.delete_item(
        Key = {
            'id': id
        }
    )
    return "Ressource deleted", 204

def create_server(event):
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    body = json.loads(event['body'])
    email = event['requestContext']['authorizer']['claims']['email']
    table.put_item(
        Item = {
        'id': str(uuid.uuid1()),
        'server': body['server_name'],
        'admins':  [email],
        'channels': [],
        'members': [email]
        }
    )
    return "Ressource Created", 201

def create_channel(event):
    email = event['requestContext']['authorizer']['claims']['email']
    server_id = event['pathParameters']['serverid']
    client = boto3.resource('dynamodb')
    table = client.Table("mini_discord")
    body = json.loads(event['body'])
    server = table.get_item(
        Key = {'id': server_id}
    )
    print(server)
    server_channels = server['Item']['channels']
    server_channels.append({"id": str(uuid.uuid1()), "name": body['name'], "messages": [], 'admins':  [email]})
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
    return "Ressource Created", 201

def get_messages(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    server_data = ""
    servers = scanRecursive("mini_discord")
    for server in servers:
        if server['id'] == server_id:
            for channel in server['channels']:
                if channel['id'] == channel_id:
                    return channel['messages'], 200
    return "No ressource found", 404

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
    email = event['requestContext']['authorizer']['claims']['email']
    body = json.loads(event['body'])
    new_msg = {"id": str(uuid.uuid1()), "writter": email, "text": body['text']}
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
    return 'Ressource created', 200

def get_message(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    message_id = event['pathParameters']['messageid']
    channel = find_channel(server_id, channel_id)
    for message in channel['messages']:
        if message['id'] == message_id:
            return message, 200
    return 'Ressource not found', 400

def delete_message(event):
    server_id = event['pathParameters']['serverid']
    channel_id = event['pathParameters']['channelid']
    message_id = event['pathParameters']['messageid']
    data = [server_id, channel_id, message_id]
    if check_authorisations(event, "message", data) == False:
        return "Not authorized", 401
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
    return "Ressource deleted", 204

def modify_members(event):
    email = event['requestContext']['authorizer']['claims']['email']
    server_id = event['pathParameters']['serverid']
    body = json.loads(event['body'])
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('mini_discord')
    tmp = []
    response = table.query(
        KeyConditionExpression=Key('id').eq(server_id)
    )
    print('response', response['Items'][0])
    tmp = response['Items'][0]['members']
    if body['action'] == "add":
        if email in tmp:
            return
        else:
            tmp.append(email)
    else:
        if not email in tmp:
            return
        else:
            tmp.remove(email)
    table.update_item(
        Key={
            'id': server_id,
        },
        UpdateExpression="set members = :g",
        ExpressionAttributeValues={
        ':g': tmp
        },
        ReturnValues="UPDATED_NEW"
    )
    return "Ressource modified", 200

def lambda_handler(event, context):
    data_to_return = "ok"
    statusCode = 200
    if event['resource'] == '/servers':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_servers(event)
        if event['httpMethod'] == 'POST':
            data_to_return, statusCode = create_server(event)
    if event['resource'] == '/servers/{serverid}':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_server_by_id(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return, statusCode = delete_server_by_id(event)
        if event['httpMethod'] == 'PATCH':
            data_to_return, statusCode = modify_members(event)
    if event['resource'] == '/servers/{serverid}/channels':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_channels(event)
        if event['httpMethod'] == 'POST':
            data_to_return, statusCode = create_channel(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_channel(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return, statusCode = delete_channel(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}/messages':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_messages(event)
        if event['httpMethod'] == 'POST':
            data_to_return, statusCode = create_message(event)
    if event['resource'] == '/servers/{serverid}/channels/{channelid}/messages/{messageid}':
        if event['httpMethod'] == 'GET':
            data_to_return, statusCode = get_message(event)
        if event['httpMethod'] == 'DELETE':
            data_to_return, statusCode = delete_message(event)
        
    return {
        "statusCode": statusCode,
        'headers': {
            "Access-Control-Allow-Origin" : '*',
            "Access-Control-Allow-Credentials" : True
        },
        "body": json.dumps(data_to_return)
    }
