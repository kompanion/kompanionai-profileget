"""AWS Lambda function handler for ChadBot ProfilePost function"""
from __future__ import print_function
import gzip
import json
import time
import urllib.request
from io import BytesIO
import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode

def lambda_handler(event, context):
    """Lambda function handler"""
    print("Event:")
    print(event)

    Body = json.loads(event['body'])

    token = Body['jwttoken']

    region = 'us-east-2'
    userpool_id = 'us-east-2_i2gGWvrBo'
    keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
    # instead of re-downloading the public keys every time
    # we download them only on cold start
    # https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
    with urllib.request.urlopen(keys_url) as f:
        response = f.read()
    keys = json.loads(response.decode('utf-8'))['keys']

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # now we can use the claims
    print(claims)

    # fix username key mismatch between Cognito and AWS Lambda testing
    if 'cognito:username' in claims.keys():
        username = claims['cognito:username']
    elif 'username' in claims.keys():
        username = claims['username']
    else:
        return False

    # read compressed JSON from S3
    s3 = boto3.resource("s3")
    obj = s3.Object('chadbotprofiles', username + '/profile.json.gz')
    with gzip.GzipFile(fileobj=obj.get()['Body']) as gzipfile:
        currentprofile = json.loads(gzipfile.read())

    print('Current profile:')
    print(repr(currentprofile))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "profile": currentprofile,
            "message": "ChadBot User Profile Successfully Fetched"
        }),
    }

    # the following is useful to make this script executable in both
    # AWS Lambda and any other local environments
if __name__ == '__main__':
    event = {
        'token': 'eyJraWQiOiJxNm56YVhrbWxFYytmUDdwQ3hESDIxTUhQSU9KUGVyMUFKaW5aWTVJK3BNPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJlZGNjOTJiMy0xNzE3LTQyYTctYTFhZC1iYjFjZjRjNjI0MWIiLCJldmVudF9pZCI6IjZjMTIyMmQ5LTUwOTAtNGE4MC1iMjQxLTc3M2YwODVlMDk5NSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MTc3ODI0MDQsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTIuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0yX3V0aWwzaFg3SSIsImV4cCI6MTYxNzc4NjAwNCwiaWF0IjoxNjE3NzgyNDA0LCJqdGkiOiJmZWE5MDk0ZC1jYWRlLTQ4ODItODE5NS0xMzUyMjNiZDVhNGIiLCJjbGllbnRfaWQiOiIzZzFkdnVvZWVxYXB1ODNvcmdlbmI1ZjNjcCIsInVzZXJuYW1lIjoiZWRjYzkyYjMtMTcxNy00MmE3LWExYWQtYmIxY2Y0YzYyNDFiIn0.scUqEhoFaXYVVyI8tPbwyMneo0hyRBpmD72MyGrVDILOCIhMr10uB32RDb8fpD7128w-5GcTyxUeyCgdXPJkBMZXBdmh08qADTw5GFfUv_xCOVhTTIuPr97LreeDIG4RHvrp2eY4l-VF3ogQcMDn1EHy_oL_-wJPHRkqYKIOl6We2DavL6pVgrurSqHHrf2YT8DwAiIefD0ukYYDJvwivRzYwOYMBfahB3YZvxlIuHzMJItDjaOcSZYwEzWqyLgX8h-aK_HzGI9eI50LS8fBDqQTsEYeP-X088AWGLR7u93pGN8ofau8F-UFXJD630K1hzrFAFkjaBIfCDJ_-HBbjA',
        'email': 'somewhere@somewhere.com'}
    lambda_handler(event, None)
