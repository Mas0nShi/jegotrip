# jegotrip

> [!WARNING]
> TEACH PURPOSES ONLY, DO NOT ATTACK WEBSITE, ANYTHING ABOUT VIOLATION OF THE NATIONAL LAWs.

API is not public, I found through reverse IOS client.

PS: The SSL cert is self-signed certificate, so must set extra param: [`verify=False`](jego.py#L73).

## Usage 

```python
if __name__ == '__main__':
    token = '***'  # input your token

    req = JegoRequest()
    resp = req.post(apiPath='/api/service/v1/mission/sign/userSign',
                    params={'token': token},
                    data='{"signConfigId":xxx}',
                    headers={'Content-Type': 'application/json'})
    print(resp)
    # ...
```
