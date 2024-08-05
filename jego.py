import os
import time
import json
import hashlib
import struct

import warnings
from functools import total_ordering
from dataclasses import dataclass
from typing import NamedTuple, Literal, List, Union
try:
    from typing import Self
except ModuleNotFoundError:
    from typing_extensions import Self

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests import session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode


def md5(s):
    return hashlib.md5(s).hexdigest().encode()

def aes_ecb_pkcs7_decrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    decryptedText = cipher.decrypt(data)
    return unpad(decryptedText, 16).decode('utf-8')


def aes_ecb_pkcs7_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode('utf-8'), 16))

class JegoResponse(NamedTuple):
    code: int
    msg: Literal['成功', '失败']
    body: str
    sec: str

    @staticmethod
    def from_json(obj: dict) -> 'JegoResponse':
        return JegoResponse(
            code=int(obj['code']),
            msg=obj['msg'],
            body=obj['body'],
            sec=obj['sec']
        )

    def decode_body(self) -> dict:
        if self.msg == '失败':
            return {}

        dec_salt = JegoRequest.getDecryptSaltWithSec(self.sec)
        dec_sec = JegoRequest.getDecryptSecretWithSec(dec_salt)
        body_ = b64decode(self.body)
        decrypted = aes_ecb_pkcs7_decrypt(dec_sec, body_)
        return json.loads(decrypted)


class JegoRequest:
    HEADER = {
        'User-Agent': 'Roam/2024071001 CFNetwork/1496.0.7 Darwin/23.5.0'
    }
    # in app3
    HOST_ONLINE_JEGO_APP: str = 'https://app3.jegotrip.com.cn'
    SEC_APP: str = 'online_jego_app'
    CRYPT_SALT: str = '03F0B33929245A16'

    # fields
    host: str

    def __init__(self, host=HOST_ONLINE_JEGO_APP):
        self.session = session()
        self.session.headers = self.HEADER
        self.session.verify = False  # disable SSL verification
        self.host = host

    def get(self, apiPath: str, params: {}, headers=None):
        if 1|1: raise NotImplementedError
        # unreachable
        assert apiPath.startswith('/'), f'excepted prefix "/": {apiPath}'
        return self.session.get(f'{self.host}{apiPath}', params=params, headers=headers)

    def post(self, apiPath: str, params=None, data=None, headers=None) -> JegoResponse:
        assert apiPath.startswith('/'), f'excepted prefix "/": {apiPath}'
        ts = self.getTimeStamp()

        if params and params.get('token', None):
            params['lang'] = 'zh_CN'
            params['timestamp'] = ts // 1000
            params['sign'] = self.getJegoTripSign(ts)

        encryptedSec = self.getEncryptSecretWithSalt(ts)

        content = {'sec': self.getRequestEncryptSecBase64WithSalt(ts), 'body': self.getRequestEncryptBodyBase64(encryptedSec, data)}
        data = json.dumps(content, separators=(",", ':'))
        obj = self.session.post(f'{self.host}{apiPath}', params=params, data=data, headers=headers).json()
        return JegoResponse.from_json(obj)

    def close(self):
        self.session.close()

    @staticmethod
    def getTimeStamp() -> int:
        return int(time.time() * 1000 * 1000)

    @staticmethod
    def getJegoTripSign(timestamp: int) -> str:
        salt = bytearray(i + v for i, v in enumerate(b"jt97&^%!"))
        ts = struct.pack(">Q", timestamp)
        return hashlib.sha1(salt + ts).hexdigest()

    @staticmethod
    def getRequestEncryptSecBase64WithSalt(timestamp: int) -> str:
        secret = f'{__class__.SEC_APP};{timestamp};01'.encode('utf-8')
        return b64encode(secret).decode()

    @staticmethod
    def getEncryptSecretWithSalt(timestamp) -> bytes:
        secret = f'{__class__.CRYPT_SALT}{timestamp}'
        return md5(secret.encode())[8:24]

    @staticmethod
    def getRequestEncryptBodyBase64(encryptSecret, _body) -> str:
        encryptBody = aes_ecb_pkcs7_encrypt(encryptSecret, _body)
        return b64encode(encryptBody).decode('utf-8')

    @staticmethod
    def getDecryptSaltWithSec(encryptedSec) -> int:
        salt = b64decode(encryptedSec).decode('utf-8')
        return int(salt.split(";")[1], 10)

    @staticmethod
    def getDecryptSecretWithSec(timestamp: int):
        secret = f'{__class__.CRYPT_SALT}{timestamp}'
        return md5(secret.encode())[8:24]



@dataclass(frozen=True)
class AwardVo:
    id: int
    signConfigId: int
    rewardName: str
    rewardId: str
    rewardProbability: int
    rewardType: str
    rewardQuantity: int

@total_ordering
@dataclass(frozen=True, order=False)
class Task:
    id: int
    signGroupId: int
    signDescribe: str
    eventCode: str
    completeNumber: int
    grantType: int
    reward: str
    isSign: int
    rewardExp: str
    rewardCoin: str
    iconUrl: str
    isRemindMark: int
    signMysteryAwardVos: Union[List[AwardVo], str]

    def __eq__(self, other: Self):
        return self.completeNumber == other.completeNumber

    def __le__(self, other: Self):
        return self.completeNumber <= other.completeNumber

class JegoSignin:
    token: str
    req: 'JegoRequest'


    def __init__(self, _token: str):
        self.req = JegoRequest()
        self.token = _token

    def querySignConfigId(self) -> Task | None:
        resp = self.req.post(apiPath='/api/service/v1/mission/sign/querySign',
                        params={'token': self.token},
                        data='{}',
                        headers={'Content-Type': 'application/json'})
        assert resp.code == 0 and resp.msg == '成功', resp
        tasks = resp.decode_body()
        tasks = [Task(**r) for r in tasks]
        tasks.sort() #
        for t in tasks:
            if t.isSign == 2:
                return t
        return None

    def signIn(self, task: 'Task') -> (bool, JegoResponse):
        resp = self.req.post(apiPath='/api/service/v1/mission/sign/userSign',
                        params={'token': self.token},
                        data=f'{{"signConfigId":{task.id}}}',
                        headers={'Content-Type': 'application/json','Accept': 'application/json'})
        if not (resp.code == 0 and resp.msg == '成功' ):
            # !add warning message
            if resp.code == 24005:
                warnings.warn('Maybe you need to bind WeChat account firstly... it\'s stupid... but what can you do? nothing 🤮')
            return False, resp

        body_ = resp.decode_body()
        return body_.get('rpcMsg', '') == 'SUCCESS', resp


if __name__ == '__main__':
    token = os.environ.get('JEGO_TOKEN', None)
    assert token, f'cannot to get token: {token}'

    si = JegoSignin(token)
    ti = si.querySignConfigId()
    if ti is None:
        print('⚠️ No task to signin :(')
        exit(1)
    print(ti)
    status, rsp = si.signIn(ti)
    if not status:
        print(f'❌ Failed signin :(')
        print(f'❌ {rsp.decode_body()}')
    else:
        print('🎉 Success for signin ~')

    # query
    rsp = si.req.post(apiPath='/api/service/member/v1/expireRewardQuery',
                params={'token': token},
                data='{}',
                headers={'Content-Type': 'application/json'})
    body = rsp.decode_body()
    coins = body.get('tripcoins') or -1
    if status:
        addon_coins = int(ti.rewardCoin) + sum([vo.get('rewardQuantity') if vo.get('rewardProbability') == 100 else 0 for vo in ti.signMysteryAwardVos if ti.signMysteryAwardVos])
    else:
        addon_coins = 0
    print(f'🎉 Here your 💰: {coins}, Today + 🪙 {addon_coins}')
