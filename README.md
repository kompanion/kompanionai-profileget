# profileget

This repo contains the AWS Lambda function handler to fetch user profiles via the Kompanion app.

Endpoint address:

```
```

JSON payload:

```
{
    "jwttoken": ""
}
```

Debug:

```
export TOKEN=$(aws cognito-idp initiate-auth \
    --client-id 3g1dvuoeeqapu83orgenb5f3cp \
    --auth-flow USER_PASSWORD_AUTH \
    --auth-parameters USERNAME=gp@cogniant.ai,PASSWORD=asdfasdf \
    --query 'AuthenticationResult.AccessToken' \
    --output text)
curl -i --header "Content-Type: application/json" --request POST --data '{"jwttoken": "'"$TOKEN"'" }' https://
```
