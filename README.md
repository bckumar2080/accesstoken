# Mash Token

Use the TIBCO Cloud Mashery V3 API to get a login token to perform other calls

## Installation

```bash
flogo install github.com/bckumar2080/accesstoken
```
Link for flogo web:
```
https://github.com/bckumar2080/accesstoken
```

## Schema
Inputs and Outputs:

```json
{
    "inputs": [
        {
            "name": "username",
            "type": "string",
            "required": true
        },
        {
            "name": "password",
            "type": "string",
            "required": true
        },
        {
            "name": "basicauth",
            "type": "string",
            "required": true
        }
    ],
    "outputs": [
        {
            "name": "accesstoken",
            "type": "string"
        },
        {
            "name": "tokentype",
            "type": "string"
        },
        {
            "name": "expiresin",
            "type": "string"
        },
        {
            "name": "refreshtoken",
            "type": "string"
        }
    ]
}
```
## Inputs
| Input     | Description    |
|:----------|:---------------|
| username  | The username for which you want to generate a token |
| password  | The password associated with the username |
| basicauth | The username / password combination used to connect to Mashery (must be in format `user:pass` and is likely not the same as the username and password above) |

## Ouputs
| Output       | Description                                             |
|:-------------|:--------------------------------------------------------|
| accesstoken  | The access token generated by the Mashery API           |
| tokentype    | The type of token generated by the Mashery API          |
| expiresin    | The amount of time (seconds) in which the token expires |
| refreshtoken | The token to use to refresh the access token            |
