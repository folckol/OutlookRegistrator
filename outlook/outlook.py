import ua_generator
from tls_client import Session
from re import findall
from json import loads, dumps, load
from datetime import datetime

from Abuse.OutlookRegistrator.outlook.outlook_pw import OutlookPWModel
from utils.crypto import Crypto
import random
from random import randint, choice
from names import get_first_name, get_last_name
from os import urandom
from time import time
import time as timess
import faker
import hashlib
import string
import requests



def create_task(API_crt):
    url_create_task = f"https://api.1stcaptcha.com/funcaptchatokentask?apikey={API_crt}&sitekey=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA&siteurl=https://signup.live.com/API/CreateAccount?lcid=1033&wa=wsignin1.0&rpsnv=13&ct=1667394016&rver=7.0.6737.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1%26signup%3d1%26RpsCsrfState%3d7f6d4048-5351-f65f-8b93-409ba7e7e4e4&id=292841&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=90015&lic=1&uaid=93bc3e1fb03c42568561df0711c6d450"

    responce_create_task = requests.get(url_create_task)
    if responce_create_task.json()["Code"] == 0 and responce_create_task.json()["Message"] == "OK":
        return responce_create_task.json()["TaskId"]
    else:
        raise Exception("Произошла ошибка с отправкой задания на решение капчи")

def get_task(API_crt, request_id):
    url_get_task = f"https://api.1stcaptcha.com/getresult?apikey={API_crt}&taskid={request_id}"

    for q in range(30):
        timess.sleep(0.3)
        responce_get_task = requests.get(url_get_task)
        if responce_get_task.json()["Code"] == 0 and responce_get_task.json()["Status"] == "SUCCESS":
            return responce_get_task.json()["Data"]["Token"]
        elif responce_get_task.json()["Code"] == 0 and responce_get_task.json()["Status"] == "PROCESSING":
            continue
        else:
            raise Exception("Проблема с капчей при получение токена")


class Outlook:
    def __init__(self, API_, proxy):

        self.client = Session(client_identifier='chrome_112')

        self.userAgent = ua_generator.generate().text
        self.client.proxies = {'http': f'http://{proxy.split(":")[2]}:{proxy.split(":")[3]}@{proxy.split(":")[0]}:{proxy.split(":")[1]}', 'https': f'http://{proxy}'} if proxy else None
        self.API = API_
        self.Key = None
        self.randomNum = None
        self.SKI = None
        self.uaid = None
        self.tcxt = None
        self.apiCanary = None
        self.encAttemptToken = ""
        self.dfpRequestId = ""

        self.first_name = get_first_name()
        self.last_name = get_last_name()
        self.email = f"{self.first_name}.{self.last_name}{randint(0, 100)}@outlook.com".lower()
        password = hashlib.sha256(self.email.encode('utf-8').hex().encode('utf-8')).hexdigest()
        password = password[0:(random.randint(8, 16))]
        random_index = random.randint(0, len(password) - 1)
        password = password[:random_index] + password[random_index].upper() + password[random_index + 1:]
        random_index = random.randint(0, len(password))
        self.password = password[:random_index] + '!' + password[random_index:] + random.choice(string.ascii_uppercase) + str(random.randint(0, 9))
        self.siteKey = 'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA'

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def main(self):
        headers_1 = {
            "host": "signup.live.com",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "connection": "keep-alive",
            "user-agent": self.userAgent
        }
        content = self.client.get('https://signup.live.com/signup?lic=1', headers=headers_1)
        self.Key, self.randomNum, self.SKI = findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"', content.text)[0]
        json_data = loads(findall(r't0=([\s\S]*)w\["\$Config"]=', content.text)[0].replace(';', ''))

        self.uaid = json_data['clientTelemetry']['uaid']
        self.tcxt = json_data['clientTelemetry']['tcxt']
        self.apiCanary = json_data['apiCanary']
        self.cipher = Crypto.encrypt(self.password, self.randomNum, self.Key)

        headers_2 = {
            "accept"            : "application/json",
            "accept-encoding"   : "gzip, deflate, br",
            "accept-language"   : "en-US,en;q=0.9",
            "cache-control"     : "no-cache",
            "canary"            : self.apiCanary,
            "content-type"      : "application/json",
            "dnt"               : "1",
            "hpgid"             : f"2006{randint(10, 99)}",
            "origin"            : "https://signup.live.com",
            "pragma"            : "no-cache",
            "scid"              : "100118",
            "sec-ch-ua"         : '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile"  : "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest"    : "empty",
            "sec-fetch-mode"    : "cors",
            "sec-fetch-site"    : "same-origin",
            "tcxt"              : self.tcxt,
            "uaid"              : self.uaid,
            "uiflvr"            : "1001",
            "user-agent"        : self.userAgent,
            "x-ms-apitransport" : "xhr",
            "x-ms-apiversion"   : "2",
            "referrer"          : "https://signup.live.com/?lic=1"
        }

        id_task = create_task(self.API)
        token_funcupc = get_task(self.API, id_task)

        payload_2 = {
            "password": self.password,
            "CheckAvailStateMap": [f"{self.email}:undefined"],
            "MemberName": self.email,
            "FirstName": self.first_name,
            "LastName": self.last_name,
            "BirthDate": f"{randint(2, 25)}:0{randint(1, 9)}:{randint(1969, 2000)}",
            "RequestTimeStamp": str(datetime.now()).replace(" ", "T")[:-3] + "Z",
            "EvictionWarningShown": [],
            "UpgradeFlowToken": {},
            "MemberNameChangeCount": 1,
            "MemberNameAvailableCount": 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue": self.cipher,
            "SKI": self.SKI,
            "Country": "CA",
            "AltEmail": None,
            "IsOptOutEmailDefault": True,
            "IsOptOutEmailShown": True,
            "IsOptOutEmail": True,
            "LW": True,
            "SiteId": 68692,
            "IsRDM": 0,
            "WReply": None,
            "ReturnUrl": None,
            "SignupReturnUrl": None,
            "uiflvr": 1001,
            "uaid": self.uaid,
            "SuggestedAccountType": "OUTLOOK",
            "SuggestionType": "Locked",
            "encAttemptToken": self.encAttemptToken,
            "dfpRequestId": self.dfpRequestId,
            "scid": 100118,
            "hpgid": 201040,
            "HType": "enforcement",
            "HPId": self.siteKey,
            "HSol": token_funcupc,

        }

        print(token_funcupc)

        response = self.client.post('https://signup.live.com/API/CreateAccount?lic=1',
                                    json=payload_2, headers=headers_2)

        print(response)
        print()
        print(self.client.cookies)
        print(response.json())
        print()
        print(self.email)
        print(self.password)

        return self.email, self.password



if __name__ == '__main__':

    api_1fst = ""
    proxy = ""

    requests.get("")
    timess.sleep(10)

    outlook = Outlook(api_1fst, proxy)
    mail, password = outlook.main()

    model = OutlookPWModel(api_1fst, mail, password, proxy)
    model.Main()

'''
<[<Cookie amsc=phUwYTCxdLgkLDkmhjVII3XESBdmnKRHTNxLfcdLOAhWeHS0C/fzamuRjEOx9oyC2qA6wJ3TM9TAburU99nlaOYMusFqpOMkF3FukOFJWlkED84EDPtqRsQOuLLUgxhnYCEIUAxw3PHEFv3nwTDLzGCYzZRgvqUB3GdR7niRiwt6Ik7atCoqcpr+FDor13XY+TL1q+dnqQrAw2gZc+46DkyJ+Csd4mVH85C5LcBSq8RgvLJcaM2JnVsRTiZwiE4wJ2nU1FbgxKNIv5DK4KgQs3nCW9ybsqB1nRrSYzZX6m4=:2:3c for .live.com/>]>
'''



