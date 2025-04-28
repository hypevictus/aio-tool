# System
import string
import random
import json
import time
import ctypes
import zipfile

from colorama import Fore
from uuid import uuid4
import re
import os
import yaml
import io
import traceback
import secrets

# Webrequests
import requests
from requests_toolbelt import MultipartEncoder
import urllib.parse
import tls_client

# Hash/Encryption Functions
import hmac
import hashlib
import base64

# Cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Threading
import concurrent.futures
import threading

# LOCAL IMPORTS
from log import *

# CONFIG

config = yaml.safe_load(open('./assets/config.yml', "r"))

MAX_VCC_USES = config['max_vcc_uses']
THREADS = config['threads']

EXPIRE_MONTH = 10
EXPIRE_YEAR = 2028

# GLOBAL VARIABLES

client_identifier = 'chrome_120'

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

LANGUAGE_CODE = config['language_code']
TIMEOUT = 60

city = config['city']
state = config['state']
postal = config['postal']

REVOLUT_QUEUE = []
REVOLUT_WAIT_BETWEEN_OTP = config['revolut_between_otp_time']

try:
    import licence
    lic = True
except:
    lic = False

try:
    from creator import *
    cre = True
except:
    cre = False

if lic:
    import subprocess

    def getHWID():
        hwid = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
        return hwid


    # CHANGE THIS EVERY UPDATE
    VERSION = 1.4

    if cre is False:
        TOOL_ID = 8
    else:
        TOOL_ID = 10

    KEY = config["KEY"]
    HWID = getHWID()

    if KEY == "" or KEY == " " or KEY == "000-000-000-000":
        error('[AUTH]', f"Please insert your license-key in assets/config.yml to authenticate yourself.")
        input()
        quit()

    code, message = licence.login(KEY, TOOL_ID, HWID)
    if code is True:
        info('[AUTH]', f"{message}")
    else:
        error('[AUTH]', f"{message}")
        input()
        quit()

    code, message = licence.update(TOOL_ID, VERSION)
    if code == 200:
        info('[VERSION]', f"{message}")
    elif code == 201:
        debug('[VERSION]', f"{message}")
        input()
        quit()
    else:
        time.sleep(10)
        quit()

    code, SELLER = licence.getUser(KEY)

    if code != 200:
        time.sleep(10)
        quit()
else:
    info("[INFO]", "Congratulations! You are using the source code.")


def advancedLog(id, request):
    print(f"FAILED REQUEST [{str(id)}]: {request.status_code} : {request.text[:1000]}")
    return False


def save(text="", filename=None):
    file = open(filename, "a")
    add = ""
    add += text
    add += "\n"
    file.write(add)
    file.close()


def check_proxy(proxy):
    try:
        r = requests.get(f'https://ipinfo.io/ip', proxies={'https': proxy, 'http': proxy}, timeout=config['speed'],
                         headers={'user-agent': USER_AGENT})
        if r.status_code != 200:
            return False
        return True
    except Exception as e:
        return False


def getProxy():
    with open("./assets/proxies.txt") as f:
        proxies = f.read().split('\n')
    while True:
        proxy = "http://" + random.choice(proxies)
        if check_proxy(proxy):
            return proxy
        else:
            continue


def getFileLines(filename):
    with open(filename) as f:
        lines = f.read().split('\n')
    for line in lines:
        if line.replace(" ", "") == "":
            lines.remove(line)
    return lines


def doFileOperation(operation, data=""):
    global VCC_LIST, ACCOUNT_LIST

    def updateTxtFile(TYPE, filename):
        with open(filename, "w") as g:
            g.writelines(io.StringIO('\n'.join(TYPE)))

    operation = operation.lower().strip()

    TYPE = None

    if "vcc" in operation:
        TYPE = "VCC"

        if "add" in operation:
            VCC_LIST.append(data)
        elif "remove" in operation:
            if data in VCC_LIST:
                VCC_LIST.remove(data)

    elif "account" in operation:
        TYPE = "ACCOUNT"

        if "add" in operation:
            ACCOUNT_LIST.append(data)
        elif "remove" in operation:
            if data in ACCOUNT_LIST:
                ACCOUNT_LIST.remove(data)

    if TYPE is not None:
        updateTxtFile(VCC_LIST if TYPE == "VCC" else ACCOUNT_LIST,
                      './assets/vccs.txt' if TYPE == "VCC" else './assets/accounts.txt')


def getRandom(amount: int = 10):
    s = ""
    for a in range(amount):
        s += random.choice(string.ascii_letters)
    return s


def getRandomInt(amount: int = 10):
    return str(random.randint(1, amount))


def parseVCC(vcc):
    vcc = vcc.replace(" ", "")

    if len(vcc.split("|")) == 2:
        return vcc.split("|")[0], vcc.split("|")[1], EXPIRE_MONTH, EXPIRE_YEAR
    elif len(vcc.split("|")) == 1 and len(vcc.split(":")) == 3:
        NUMBER = vcc.split(":")[0]
        CVC = vcc.split(":")[-1]
        EXPIRING = vcc.split(":")[1]
        EXPIRING_MONTH = EXPIRING[:2]
        EXPIRING_YEAR = "20" + EXPIRING[-2:]
        return NUMBER, CVC, EXPIRING_MONTH, EXPIRING_YEAR
    elif len(vcc.split(":") == 4):
        return vcc.split(":")[0], vcc.split(":")[3], vcc.split(":")[1], vcc.split(":")[2]
    else:
        return vcc.split("|")[0], vcc.split("|")[3], vcc.split("|")[1], vcc.split("|")[2]


class DeviceToken:

    @staticmethod
    def sign(http_method: str, uri_path: str, payload: str, priv_key: ec.EllipticCurvePrivateKey) -> str:
        win_time = (int(time.time()) + 11644473600) * 10000000
        data = b''
        data += b"\0\0\0\1\0"
        data += win_time.to_bytes(8, "big") + b'\0'
        data += http_method.encode() + b'\0'
        data += uri_path.encode() + b'\0'
        data += b'\0'
        data += payload.encode() + b'\0'

        sig = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
        (r, s) = decode_dss_signature(sig)
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")

        raw_sig = b'\0\0\0\1' + win_time.to_bytes(8, "big") + r_bytes + s_bytes
        sig = base64.b64encode(raw_sig).decode("ascii")
        return sig

    @staticmethod
    def get_proofkey(priv_key: ec.EllipticCurvePrivateKey):
        def int_to_base64(x: int, length=32, byteorder='big') -> str:
            return base64.urlsafe_b64encode(x.to_bytes(length, byteorder)).decode("ascii").replace('=', '')

        return dict(alg="ES256",
                    crv="P-256",
                    kty="EC",
                    use="sig",
                    x=int_to_base64(priv_key.private_numbers().public_numbers.x),
                    y=int_to_base64(priv_key.private_numbers().public_numbers.y))

    @staticmethod
    def get_device_key() -> ec.EllipticCurvePrivateKey:
        priv_key = ec.generate_private_key(ec.SECP256R1)
        priv_key_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return priv_key

    @staticmethod
    def get_device_token() -> str:
        global TIMEOUT

        priv_key: ec.EllipticCurvePrivateKey = DeviceToken.get_device_key()
        payload_obj = dict(
            Properties=dict(
                AuthMethod="ProofOfPossession",
                DeviceType="Win32",
                Id="{" + str(uuid4()).upper() + "}",
                ProofKey=DeviceToken.get_proofkey(priv_key),
            ),
            RelyingParty="http://auth.xboxlive.com",
            TokenType="JWT"
        )

        payload = json.dumps(payload_obj, indent=2)
        target = 'https://device.auth.xboxlive.com/device/authenticate'
        sig = DeviceToken.sign("POST", '/device/authenticate', payload, priv_key)

        session = tls_client.Session(
            client_identifier=client_identifier,
            random_tls_extension_order=True
        )
        session.timeout_seconds = TIMEOUT
        while True:
            try:
                response = session.post(target, json=payload, headers={
                    "Content-Type": "application/json",
                    "x-xbl-contract-version": "1",
                    "Signature": sig
                })
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                else:
                    print(e)
                    return
        return response.json()['Token']


class Session:
    def __init__(self, combo, language, city, state, postal_code):

        self.address_line1 = getRandom(20) + " " + getRandom(5) + " " + getRandomInt(499)
        self.name = [getRandom(), getRandom()]
        self.city = city
        self.state = state
        self.postal_code = postal_code
        self.language = language
        self.country = self.language.split("-")[-1].lower()

        self.USER_AGENT = USER_AGENT

        self.address_id = None
        self.card_id = None
        self.account_id = None

        self.card_type = None

        self.combo = combo
        if ":" in combo:
            combo = combo.split(':')
        elif "|" in combo:
            combo = combo.split('|')

        self.email = combo[0]
        self.password = combo[1]

        self.session = requests.Session()

        self.session.headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            "accept-language": f"{LANGUAGE_CODE},en;q=0.9",
            "user-agent": self.USER_AGENT,
            "referer": "https://account.microsoft.com/",
            "origin": "https://account.microsoft.com"
        }

        self.proxy = getProxy() if config['proxyless'] is False else None
        proxy = self.proxy
        self.session.proxies = {'http': proxy, 'https': proxy}
        self.xbl_auth2 = None
        self.xbl_auth = None
        self.msadelegate = None

        log(Fore.LIGHTBLUE_EX, '[TASK]', "Started task.", {'email': self.email})

    def acceptPrivacyNotice(self, privNotifUrl, corelationId, mCode):

        r1_data = {
            'correlation_id': corelationId,
            'code': mCode
        }

        r1 = self.session.post(privNotifUrl,
                               data=r1_data,
                               headers={
                                   'path': privNotifUrl.replace('https://privacynotice.account.microsoft.com', ''),
                                   'content-type': 'application/x-www-form-urlencoded',
                                   'origin': 'https://login.live.com',
                                   'referer': 'https://login.live.com/',
                               },
                               timeout=TIMEOUT
                               )

        r2_data = MultipartEncoder(
            fields={
                'ClientId': r1.text.split("ucis.ClientId = '")[1].split("'")[0],
                'ConsentSurface': 'SISU',
                'ConsentType': 'ucsisunotice',
                'correlation_id': corelationId,
                'CountryRegion': r1.text.split("ucis.CountryRegion = '")[1].split("'")[0],
                'DeviceId': '',
                'SerializedEncryptionData': r1.text.split("ucis.SerializedEncryptionData = '")[1].split("'")[0],
                'FormFactor': 'Desktop',
                'Market': r1.text.split("ucis.Market = '")[1].split("'")[0],
                'ModelType': 'ucsisunotice',
                'ModelVersion': '1.11',
                'NoticeId': r1.text.split("ucis.NoticeId = '")[1].split("'")[0],
                'Platform': 'Web',
                'UserId': r1.text.split("ucis.UserId = '")[1].split("'")[0],
                'UserVersion': '1'},
            boundary='----WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16)))

        r2 = self.session.post("https://privacynotice.account.microsoft.com/recordnotice",
                               data=r2_data,
                               headers={
                                   'accept': 'application/json, text/plain, */*',
                                   'content-type': r2_data.content_type,
                                   'origin': 'https://privacynotice.account.microsoft.com',
                                   'referer': privNotifUrl,

                               },
                               timeout=TIMEOUT
                               )

        if r2.status_code == 200:
            log(Fore.LIGHTYELLOW_EX, "[PRIVACY]", "Accepted Privacy terms.", {'email': self.email})

        r3_url = urllib.parse.unquote(privNotifUrl.split('notice?ru=')[1])
        r3 = self.session.get(r3_url,
                              headers={
                                  'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                                  'referer': 'https://privacynotice.account.microsoft.com/',
                                  'Upgrade-Insecure-Requests': '1',
                              },
                              timeout=TIMEOUT
                              )
        return r3

    def login(self):

        r1 = self.session.get(
            'https://login.live.com/ppsecure/post.srf',
            timeout=TIMEOUT
        )
        if r1.status_code != 200:
            return self.login()
        r2_ppft = r1.text.split(''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        r2_url = r1.text.split(",urlPost:'")[1].split("'")[0]

        r2_data = f'i13=0&login={self.email}&loginfmt={self.email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={self.password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={r2_ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'

        r2 = self.session.post(
            r2_url,
            data=r2_data,
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://login.live.com',
                'referer': 'https://login.live.com/',
            },
            timeout=TIMEOUT
        )

        if r2.status_code != 200:
            return self.login()

        if 'https://privacynotice.account.microsoft.com/notice' in r2.text:
            # print("Accepting privacy notices...")
            privNotifUrl = r2.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]
            corelationId = r2.text.split('name="correlation_id" id="correlation_id" value="')[1].split('"')[0]
            mCode = r2.text.split('type="hidden" name="code" id="code" value="')[1].split('"')[0]

            r2 = self.acceptPrivacyNotice(privNotifUrl, corelationId, mCode)
        elif 'name="uaid" id="uaid" value="' in r2.text:

            privNotifUrl = r2.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]
            ipt = r2.text.split('name="ipt" id="ipt" value="')[1].split('"')[0]
            pprid = r2.text.split('name="pprid" id="pprid" value="')[1].split('"')[0]
            uaid = r2.text.split('name="uaid" id="uaid" value="')[1].split('"')[0]

            r2_1_data = {
                "ipt": ipt,
                "pprid": pprid,
                "uaid": uaid
            }

            r2_1 = self.session.post(
                privNotifUrl,
                data=r2_1_data,
                headers={'referer': 'https://login.live.com/', 'origin': 'https://login.live.com'},
                timeout=TIMEOUT
            )

            if '<input type="hidden" id="canary" name="canary" value="' not in r2_1.text or 'iAccrualForm' not in r2_1.text:
                data.fail += 1
                if config['remove_resources']:
                    doFileOperation('remove:account', self.combo)
                error("[LOCKED]", "Microsoft account locked. [1]", {'email': self.email})
                return False

            canary = r2_1.text.split('<input type="hidden" id="canary" name="canary" value="')[1].split('"')[0]
            r2_2_url = "https://account.live.com" + r2_1.text.split('<form id="iAccrualForm" action="')[1].split('"')[0]
            r2_2_data = {
                "canary": canary
            }

            r2_2 = self.session.post(
                r2_2_url,
                data=r2_2_data,
                headers={'origin': 'https://account.live.com', 'referer': privNotifUrl},
                timeout=TIMEOUT
            )

            # print(2.2)
            return self.login()

        try:
            r3_ppft = re.findall("sFT:'(.+?(?=\'))", r2.text)[0]
        except:
            if '"authenticatedState":"signedIn"' not in r2.text:
                data.fail += 1
                if config['remove_resources']:
                    doFileOperation('remove:account', self.combo)
                error("[LOCKED]", "Microsoft account locked.", {'email': self.email})
                return False

        if '"authenticatedState":"signedIn"' not in r2.text:

            r3_url = re.findall("urlPost:'(.+?(?=\'))", r2.text)[0]

            r3_data = {
                "LoginOptions": "3",
                "type": "28",
                "ctx": "",
                "hpgrequestid": "",
                "PPFT": r3_ppft,
                "i19": "19130"
            }

            r3 = self.session.post(
                r3_url,
                data=r3_data,
                headers={
                    'content-type': 'application/x-www-form-urlencoded',
                    'origin': 'https://login.live.com',
                    'referer': r2_url,
                },
                timeout=TIMEOUT,
                allow_redirects=True
            )

            if r3.status_code != 200:
                return self.login()

            r4_url = r3.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]
            r4_data = {
                "pprid": r3.text.split('type="hidden" name="pprid" id="pprid" value="')[1].split('"')[0],
                "NAP": r3.text.split('type="hidden" name="NAP" id="NAP" value="')[1].split('"')[0],
                "ANON": r3.text.split('type="hidden" name="ANON" id="ANON" value="')[1].split('"')[0],
                "t": r3.text.split('<input type="hidden" name="t" id="t" value="')[1].split('"')[0]
            }

            r4 = self.session.post(
                r4_url,
                data=r4_data,
                timeout=TIMEOUT,
                allow_redirects=True
            )

            if r4.status_code != 200:
                return self.login()

        self.session.headers['origin'] = 'https://login.live.com'
        self.session.headers['referer'] = 'https://login.live.com/'

        r5 = self.session.get(
            'https://xbox.com/en-US',
            timeout=TIMEOUT,
            allow_redirects=True
        )

        del self.session.headers['origin']
        self.session.headers['referer'] = 'https://www.xbox.com/'

        def generate_code_challenge():
            code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip(
                '=')

            return code_verifier, code_challenge

        code_verifier, code_challenge = generate_code_challenge()
        login_id = str(uuid4())

        def getState(dic):
            json_str = json.dumps(dic)
            bytes_data = json_str.encode('utf-8').strip()
            base64_encoded = base64.b64encode(bytes_data).decode('utf-8')
            return base64_encoded

        state = getState({"id": login_id, "meta": {"interactionType": "silent"}})

        r6 = self.session.get(
            'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize',
            params={
                'client_id': '1f907974-e22b-4810-a9de-d9647380c97e',  # always same
                'scope': 'openid profile offline_access',
                'redirect_uri': 'https://www.xbox.com/auth/msa/blank.html',
                'client-request-id': str(uuid4()),  # dynamic
                'response_mode': 'fragment',
                'response_type': 'code',
                'x-client-SKU': 'msal.js.browser',
                'x-client-VER': '3.7.0',
                'client_info': '1',
                'code_challenge': code_challenge,  # dynamic
                'code_challenge_method': 'S256',
                'prompt': 'none',
                'nonce': str(uuid4()),  # dynamic
                'state': state  # dynamic
            },
            headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Priority': 'u=0, i',
                'Sec-Fetch-Dest': 'iframe',
            },
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        code = r6.url.split('code=')[1].split('&')[0]

        self.session.headers['origin'] = 'https://www.xbox.com'
        self.session.headers['referer'] = 'https://www.xbox.com/'

        r7 = self.session.post(
            'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
            data={
                'client_id': '1f907974-e22b-4810-a9de-d9647380c97e',
                'redirect_uri': 'https://www.xbox.com/auth/msa/blank.html',
                'scope': 'openid profile offline_access',
                'code': code,
                'x-client-SKU': 'msal.js.browser',
                'x-client-VER': '3.7.0',
                'x-ms-lib-capability': 'retry-after, h429',
                'x-client-current-telemetry': str(getRandomInt(100)),
                'x-client-last-telemetry': str(getRandomInt(100)),
                'code_verifier': code_verifier,
                'grant_type': 'authorization_code',
                'client_info': '1',
                'client-request-id': str(uuid4()),
                'X-AnchorMailbox': f'Oid:00000000-0000-0000-e396-884f96f992ff@9188040d-6c67-4c5b-b112-36a304b66dad',
            },
            timeout=TIMEOUT
        )

        if 'client_info' not in r7.json():
            return self.login()

        info = str(r7.json()['client_info'])
        refresh_token = str(r7.json()["refresh_token"])

        mis_padding = len(info) % 4
        if mis_padding != 0:
            info += '=' * (4 - mis_padding)

        value = json.loads(base64.b64decode(info).decode('utf-8'))

        state = getState({"ru": "https://www.xbox.com/" + self.country, "msaId": value['oid'] + "." + value['utid'],
                          "sid": "RETAIL"})

        r8 = self.session.get(
            'https://sisu.xboxlive.com/connect/XboxLive',
            params={
                'ru': 'https://www.xbox.com/auth/msa?action=loggedIn',
                'login_hint': self.email,
                'userPrompts': 'XboxOptionalDataCollection',
                'consent': 'required',
                'cv': '8WCaJN8YphEboYKGWlERXl.24',
                'state': state,
            },
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        signup = True

        if '"fmHF" id="fmHF" action="' in r8.text:

            # IT LOOKS LIKE THE MAIL VERIFY NEEDS TO BE BYPASSED....

            url = r8.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]
            pprid = r8.text.split('name="pprid" id="pprid" value="')[1].split('"')[0]
            ipt = r8.text.split('name="ipt" id="ipt" value="')[1].split('"')[0]
            uaid = r8.text.split('name="uaid" id="uaid" value="')[1].split('"')[0]

            self.session.headers["origin"] = 'https://login.live.com'
            self.session.headers["referer"] = "https://login.live.com"

            f1 = self.session.post(
                url,
                data={
                    'pprid': pprid,
                    'ipt': ipt,
                    'uaid': uaid,
                },
                allow_redirects=True,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=TIMEOUT,
            )

            if '{"cancel":{"url":"' not in f1.text or '"fShowSkip": false,' in f1.text:
                debug("[VERIFY REQUIRED]", "Additional Verification is needed (MAIL/PHONE)", {'email': self.email})
                return False

            self.session.headers['origin'] = 'https://account.live.com/'
            self.session.headers['referer'] = url

            canary = f1.text.split('id="canary" name="canary" value="')[1].split('"')[0]
            url = f1.text.split('<form id="frmAddProof" method="post" action="')[1].split('"')[0]

            time.sleep(2)

            f2 = self.session.post(
                url,
                data={
                    'iProofOptions': 'Email',
                    'DisplayPhoneCountryISO': 'TR',
                    'DisplayPhoneNumber': '',
                    'EmailAddress': '',
                    'canary': canary,
                    'action': 'Skip',
                    'PhoneNumber': '',
                    'PhoneCountryISO': '',
                },
                allow_redirects=True,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=TIMEOUT,
            )
            # debug("[VERIFY SKIP]", "Verification was skipped.", {'email': self.email})

            if 'uaid' not in f2.text:
                # debug("[VERIFY SKIP]", "Verification was skipped.", {'email': self.email})
                pass
            else:
                debug("[FAILED SKIP]", "Retrying to skip verification...", {'email': self.email})
                return self.login()

            r8 = f2

        if "signup" not in r8.url:
            signup = False

        if "spt=" in r8.url:

            token = r8.url.split('spt=')[1].split('&')[0]
            sesid = r8.url.split('sid=')[1].split('&')[0]

            self.session.headers['origin'] = 'https://sisu.xboxlive.com'
            self.session.headers['referer'] = 'https://sisu.xboxlive.com/client/v33/default/view/index.html'
            self.session.headers['authorization'] = token
            self.session.headers['x-xbl-contract-version'] = '3'

            resId = random.randrange(0, 2 ** 32)

            gamertag = f"Oculus" + str(int(random.random() * 1000000))

            datas = [
                {
                    "GamertagReserve": {
                        "Gamertag": gamertag,
                        "ReservationId": resId,
                        "Duration": "1:00:00"
                    }
                },
                {
                    "CreateAccountWithGamertag": {
                        "Gamertag": gamertag,
                        "ReservationId": resId,
                        "MsftOptin": True
                    }
                },
                {
                    "SetGamerpic": {
                        "GamerPic": "https://dlassets-ssl.xboxlive.com/public/content/ppl/gamerpics/00002-00004-md.png?w=320&h=320"
                    }
                },
                {
                    "CheckConsents": {}
                },
                {
                    "SetConsents": {
                        "Consents": [
                            {
                                "id": "9d2ba560-0bfc-43b4-ae7e-5cd6f1072f6a_xboxoptionaldatacollection_1",
                                "values": [
                                    {
                                        "categoryName": "XboxDiagnosticsOptionalData",
                                        "value": "false",
                                        "valueDataType": "Boolean"
                                    }
                                ]
                            }
                        ]
                    }
                },
                {
                    "ReadChainReroute": {}
                },
            ]

            for payload in datas:
                r9 = self.session.post(
                    'https://sisu.xboxlive.com/proxy',
                    params={
                        'sessionid': sesid
                    },
                    json=payload,
                    timeout=TIMEOUT,
                )

            url = r9.json()['Redirect']

            self.session.headers['x-xbl-contract-version'] = '1'

            self.session.headers['referer'] = 'https://xbox.com'
            self.session.headers['origin'] = 'https://xbox.com'

            r11 = self.session.get(
                url,
                timeout=TIMEOUT,
            )



        else:
            try:
                accessToken = r8.url.split("accessToken=")[1].split('&')[0]
            except:
                pass

        r10 = self.session.post(
            'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
            data={
                'client_id': '1f907974-e22b-4810-a9de-d9647380c97e',
                'redirect_uri': 'https://www.xbox.com/auth/msa/blank.html',
                'scope': 'xboxlive.signin openid profile offline_access',
                'grant_type': 'refresh_token',
                'client_info': '1',
                'x-client-SKU': 'msal.js.browser',
                'x-client-VER': '3.7.0',
                'x-ms-lib-capability': 'retry-after, h429',
                'x-client-current-telemetry': str(getRandomInt(100)),
                'x-client-last-telemetry': str(getRandomInt(100)),
                'client-request-id': str(uuid4()),
                'refresh_token': refresh_token,
                'X-AnchorMailbox': 'Oid:00000000-0000-0000-6628-0cf95262818d@9188040d-6c67-4c5b-b112-36a304b66dad',
            },
            timeout=TIMEOUT,
        )

        accessToken = str(r10.json()['access_token'])

        del self.session.headers['origin']
        del self.session.headers['referer']

        if self.xbl_auth is None or self.xbl_auth2 is None or self.xbl_auth3 is None:
            self.getXBL(accessToken)
        if self.msadelegate is None:
            self.getDelegate()

        log(Fore.LIGHTGREEN_EX, "[LOGIN]", "Successfully logged in and created Xbox profile.",
            {'email': self.email})

        return True

    def getXBL(self, accessToken):

        self.session.headers['origin'] = 'https://www.xbox.com'
        self.session.headers['referer'] = 'https://www.xbox.com'
        self.session.headers['x-xbl-contract-version'] = '1'

        r1 = self.session.post(
            'https://user.auth.xboxlive.com/user/authenticate',
            json={
                "Properties": {
                    "AuthMethod": "RPS",
                    "RpsTicket": "d=" + accessToken,
                    "SiteName": "user.auth.xboxlive.com"
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT"
            },
            timeout=TIMEOUT,
        )
        try:
            token = r1.json()['Token']
            uhs = r1.json()['DisplayClaims']['xui'][0]['uhs']
        except:
            return self.login()

        r2 = self.session.post(
            'https://xsts.auth.xboxlive.com/xsts/authorize',
            json={
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [
                        token
                    ]
                },
                "RelyingParty": "http://xboxlive.com",
                "TokenType": "JWT"
            },
            timeout=TIMEOUT,
        )
        try:
            self.xbl_auth3 = "XBL3.0 x=" + uhs + ";" + r2.json()['Token']
        except:
            return self.login()

        r3 = self.session.post(
            'https://xsts.auth.xboxlive.com/xsts/authorize',
            json={
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [
                        token
                    ]
                },
                "RelyingParty": "http://mp.microsoft.com/",
                "TokenType": "JWT"
            },
            timeout=TIMEOUT,
        )

        try:
            xbl_auth = "XBL3.0 x=" + uhs + ";" + r3.json()['Token']
        except:
            return self.login()

        self.xbl_auth = xbl_auth
        self.xbl_auth2 = str({"XToken": xbl_auth})

        del self.session.headers['x-xbl-contract-version']

        return

    def getDelegate(self):
        r1_params = {
            'fref': 'home.drawers.payment-options.manage-payment',
            'refd': 'account.microsoft.com',
        }

        r1 = self.session.get(
            'https://account.microsoft.com/billing/payments',
            params=r1_params,
            headers={
                'referer': 'https://login.live.com/',
            },
            timeout=TIMEOUT
        )

        r2_verificationtoken = \
            r1.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
        r2_params = {
            'scopes': 'pidl',
        }

        r2 = self.session.get(
            'https://account.microsoft.com/auth/acquire-onbehalf-of-token',
            params=r2_params,
            headers={
                'accept': 'application/json, text/plain, */*',
                'correlation-context': f'v=1,ms.b.tel.market={self.country},ms.b.tel.scenario=ust.amc.billing.payment-north-star,ms.c.ust.scenarioStep=PaymentNorthStarOboAuthStart',
                'MS-CV': 'zATvNJImJkOjVJ27.22.16',
                'referer': 'https://account.microsoft.com/billing/payments',
                'x-requested-with': 'XMLHttpRequest',
                '__RequestVerificationToken': r2_verificationtoken,
            },
            timeout=TIMEOUT
        )

        self.msadelegate = "MSADELEGATE1.0=" + r2.json()[0]["token"]

    def addCardv3(self, full, card, cvv, exp_month, exp_year, cvSeed=getRandom(20)):

        global MAX_VCC_USES, TIMEOUT

        s = tls_client.Session(
            random_tls_extension_order=True,
            client_identifier=client_identifier,
        )

        s.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }

        language = self.language
        country = self.language.split("-")[-1].lower()

        card_type = "visa"
        if card.startswith("5"):
            card_type = "mc"
        elif card.startswith("6"):
            card_type = "amex"

        partnerSessionId = str(uuid4())

        r1 = s.get(
            'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
            params={
                'type': 'visa,amex,mc',
                'partner': 'northstarweb',
                'operation': 'Add',
                'language': language,
                'family': 'credit_card',
                'country': country,
            },
            headers={
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Authorization': self.msadelegate,
                'Cache-Control': 'no-cache',
                'Content-Type': 'application/json',
                'Correlation-Context': 'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentaddPaymentInstrument.1,ms.b.tel.partner=northstarweb,ms.c.cfs.payments.partnerSessionId=' + partnerSessionId,
                'Dnt': '1',
                'Ms-Cv': cvSeed + '.11',
                'Origin': 'https://account.microsoft.com',
                'Pragma': 'no-cache',
                'Priority': 'u=1, i',
                'Referer': 'https://account.microsoft.com/',
                'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'User-Agent': self.USER_AGENT,
                'X-Ms-Flight': 'PXUsePartnerSettingsService,partnerSettingsVersion_06.05.2024-22.20.34-233',
                'X-Ms-Pidlsdk-Version': '2.4.1_reactview',
            },
            timeout_seconds=TIMEOUT,
        )

        TokenHeaders = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json; charset=UTF-8',
            'Host': 'tokenization.cp.microsoft.com',
            'Origin': 'https://securepxservice.cp.microsoft.com',
            'Referer': 'https://securepxservice.cp.microsoft.com/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.USER_AGENT,
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        r2 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/cvv/getToken",
            json={
                "data": cvv
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT,
        )
        try:
            cvv_id = r2.json()["data"]
        except:
            return self.addCardv3(full, card, cvv, exp_month, exp_year)

        r3 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/pan/getToken",
            json={
                "data": card
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT,
        )
        try:
            card_id = r3.json()["data"]
        except:
            return self.addCardv3(full, card, cvv, exp_month, exp_year)

        def hmac_(card, msadelegate) -> tuple[str, str]:
            key_token = random.randbytes(64)
            key_token_b64 = base64.b64encode(key_token).decode()
            msg = f"Pan:{card}|HMACKey:{key_token_b64}|UserCredential:{msadelegate}"
            return base64.b64encode(hmac.new(key_token, msg.encode(), hashlib.sha256).digest()).decode(), key_token_b64

        signedData, KeyData = hmac_(card, self.msadelegate)

        r6 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/piAuthKey/getToken",
            json={
                "data": KeyData
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT,
        )

        try:
            r5_keyToken = r6.json()["data"]
        except:
            return self.addCardv3(full, card, cvv, exp_month, exp_year)

        greenId = str(uuid4())

        r99 = self.session.get(
            'https://fpt.microsoft.com/tags',
            params={
                'session_id': greenId
            },
        )

        r7_headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': self.msadelegate,
            'Content-Type': 'application/json',
            'Correlation-Context': 'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentaddPaymentInstrument.1,ms.b.tel.partner=northstarweb,ms.c.cfs.payments.partnerSessionId=' + partnerSessionId,
            'Ms-Cv': cvSeed + '.4',
            'Origin': 'https://account.microsoft.com',
            'Priority': 'u=1, i',
            'Referer': 'https://account.microsoft.com/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.USER_AGENT,
            'X-Ms-Flight': 'PXUsePartnerSettingsService,partnerSettingsVersion_06.05.2024-22.20.34-233',
            'X-Ms-Pidlsdk-Version': '2.4.1_reactview',
        }

        payload = {
            'paymentMethodFamily': r1.json()[0]["data_description"]["paymentMethodFamily"]["default_value"],
            'paymentMethodType': card_type,
            'paymentMethodOperation': r1.json()[0]["data_description"]["paymentMethodOperation"]["default_value"],
            'paymentMethodCountry': r1.json()[0]["data_description"]["paymentMethodCountry"]["default_value"],
            'paymentMethodResource_id': 'credit_card.' + card_type,
            'sessionId': str(uuid4()),
            'context': r1.json()[0]["data_description"]["context"]["default_value"],
            'riskData': {
                'dataType': 'payment_method_riskData',
                'dataOperation': 'add',
                'dataCountry': self.country,
                'greenId': greenId,
            },
            'details': {
                'dataType': f'credit_card_{card_type}_details',
                'dataOperation': 'add',
                'dataCountry': self.country,
                'accountHolderName': self.name[0] + ' ' + self.name[1],
                'accountToken': card_id,
                'expiryMonth': str(int(exp_month)),
                'expiryYear': exp_year,
                'cvvToken': cvv_id,
                'address': {
                    'addressType': 'billing',
                    'addressOperation': 'add',
                    'addressCountry': self.country,
                    'address_line1': self.address_line1,
                    'city': self.city,
                    'region': self.state.lower(),
                    'postal_code': self.postal_code,
                    'country': country,
                },
                'permission': {
                    'dataType': 'permission_details',
                    'dataOperation': 'add',
                    'dataCountry': self.country,
                    'hmac': {
                        'algorithm': 'hmacsha256',
                        'keyToken': r5_keyToken,
                        'data': signedData,
                    },
                    'userCredential': self.msadelegate,
                },
                'currentContext':
                    r1.json()[0]["data_description"]["details"][0]["data_description"]["currentContext"][
                        "default_value"]
            },
            'pxmac': r1.json()[0]["data_description"]["pxmac"]["default_value"],
        }

        # print(payload)

        r7 = s.post(
            url='https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx',
            params={
                'country': self.country,
                'language': self.language,
                'partner': 'northstarweb',
            },
            headers=r7_headers,
            json=payload,
            timeout_seconds=TIMEOUT,
        )

        if "id" in r7.json():
            self.card_id = r7.json()["id"]

        if "accountId" in r7.json():
            self.account_id = r7.json()["accountId"]

        data.vccs[full] += 1
        if data.vccs[full] >= MAX_VCC_USES:
            if config['remove_resources']:
                doFileOperation("remove:vcc", full)

        if r7.status_code == 200 and self.card_id is not None:

            log(Fore.LIGHTGREEN_EX, '[VCC]', "Added card.",
                {'email': self.email, 'card': card, 'provider': '2'})
            return True

        else:

            # print(r7.status_code, r7.text)

            time_amount = config['cooldown']

            if "pxChallengeSessionId" in r7.text:

                challenge_id = r7.json()['clientAction']['context']['resourceActionContext']['pidlDocInfo']['parameters']['pxChallengeSessionId']

                debug("[CAPTCHA]", "Faced captcha add VCC", {'email': self.email, 'id': challenge_id})
                return False

            if not r7.json()["innererror"]["code"] == "ValidationFailed":
                if r7.json()["innererror"]["code"] == "InvalidRequestData":
                    log(Fore.RED, '[VCC]', "VCC endpoint rate limited.",
                        {'email': self.email, 'retrying': str(time_amount) + "s"})
                    time.sleep(time_amount)
                    return self.addCardv3(full, card, cvv, exp_month, exp_year)
                elif r7.json()["innererror"]["code"] == "ExceededMaxCardsPerAccountLimit":
                    log(Fore.RED, '[VCC]', "Maximium limit of credit cards per account has been reached.",
                        {'email': self.email})
                else:
                    log(Fore.RED, '[VCC]', 'Unknown error', {'status_code': r7.status_code, 'text': r7.json()})
            else:
                if config['remove_resources']:
                    doFileOperation("remove:vcc", full)
                log(Fore.RED, '[VCC]', "VCC cannot be validated.",
                    {'email': self.email, 'card': card, 'sleeping': str(time_amount) + "s"})

                if config['retry']:
                    time.sleep(time_amount)
                    return self.addCardv3(full, card, cvv, exp_month, exp_year)

            return False

    def addCardv2(self, full, card: str, cvv: str, exp_month: str, exp_year: str, cvSeed=getRandom(20),
                  audioCaptchaId=None, audioCaptchaReg=None, captchaId=None, captchaReg=None, captchaSolution=None,
                  captchaType=None):

        if "pro_changer" in config:
            if config['pro_changer'] is True:
                return self.addCardv3(full, card, cvv, exp_month, exp_year, cvSeed)

        global MAX_VCC_USES

        card_type = "visa"
        if card.startswith("5"):
            card_type = "mc"
        elif card.startswith("6"):
            card_type = "amex"

        language = self.language
        country = self.language.split("-")[-1].lower()

        s = tls_client.Session(
            random_tls_extension_order=True,
            client_identifier=client_identifier,
        )

        s.headers = {}

        ses = cvSeed

        h = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': f'en-US,en;q=0.9',
            'Authorization': self.xbl_auth,
            # 'content-type': 'application/json',
            'Cache-Control': 'no-cache',
            'Correlation-Context': 'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId=' + ses,
            'Dnt': '1',
            'Ms-Cv': ses,
            'Origin': 'https://www.microsoft.com',
            'Pragma': 'no-cache',
            'Priority': 'u=1, i',
            'Referer': 'https://www.microsoft.com/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.USER_AGENT,
            'X-Ms-Flight': 'enablePaymentMethodGrouping,enableGlobalPiInAddResource,EnableThreeDSOne',
            'X-Ms-Pidlsdk-Version': '2.4.3_reactview',
        }

        self.session.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }

        s.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }

        orderId = str(uuid4())

        r1 = s.get(
            params={
                'type': 'visa,amex,mc',
                'partner': 'webblends',
                'orderId': orderId,  # FIX THIS
                'operation': 'Add',
                'country': self.country.upper(),
                'language': self.language,
                'family': 'credit_card',
                'completePrerequisites': 'true',
            },
            headers=h,
            url='https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions'
        )

        # print(r1.json())

        ses = r1.headers['Ms-Cv'].split('.')[0]
        h['Correlation-Context'] = 'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId=' + ses

        h['ms-cv'] = ses
        '''
        payload = r1.json()[0]["linkedPidls"][0]['displayDescription'][0]['members'][0]['pidlAction']['context2']['payload']

        r8 = s.post(
            url='https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addresses',
            headers=h,
            json={
                "addressType": "billing",
                "addressCountry": self.country,
                "address_line1": self.address_line1,
                "city": self.city,
                "region": self.state,
                "postal_code": self.postal_code,
                "country": country
            }
        )

        payload['default_address_id'] = r8.json()["id"]

        r9 = s.post(
            url='https://paymentinstruments.mp.microsoft.com/v6.0/users/me/profiles/' + payload['id'] + '/update',
            headers=h,
            json=payload,
        )

        print(r9.status_code)
        '''

        TokenHeaders = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Origin': 'https://www.microsoft.com',
            'Pragma': 'no-cache',
            'Referer': 'https://www.microsoft.com/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        r2 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/cvv/getToken",
            json={
                "data": cvv
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT
        )
        cvv_id = r2.json()["data"]

        r3 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/pan/getToken",
            json={
                "data": card
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT
        )
        card_id = r3.json()["data"]

        def hmac_(card, msadelegate) -> tuple[str, str]:
            key_token = random.randbytes(64)
            key_token_b64 = base64.b64encode(key_token).decode()
            msg = f"Pan:{card}|HMACKey:{key_token_b64}|UserCredential:{msadelegate}"
            return base64.b64encode(hmac.new(key_token, msg.encode(), hashlib.sha256).digest()).decode(), key_token_b64

        signedData, KeyData = hmac_(card, self.msadelegate)

        r6 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/piAuthKey/getToken",
            json={
                "data": KeyData
            },
            headers=TokenHeaders,
            timeout_seconds=TIMEOUT
        )

        r5_keyToken = r6.json()["data"]

        payload = {
            'paymentMethodFamily': r1.json()[0]["data_description"]["paymentMethodFamily"]["default_value"],
            'paymentMethodType': card_type,
            'paymentMethodOperation': r1.json()[0]["data_description"]["paymentMethodOperation"]["default_value"],
            'paymentMethodCountry': r1.json()[0]["data_description"]["paymentMethodCountry"]["default_value"],
            'paymentMethodResource_id': 'credit_card.' + card_type,
            'sessionId': str(uuid4()),
            'context': r1.json()[0]["data_description"]["context"]["default_value"],
            'riskData': {
                'dataType': 'payment_method_riskData',
                'dataOperation': 'add',
                'dataCountry': self.country,
                'greenId': str(uuid4()),
            },
            'details': {
                'dataType': f'credit_card_{card_type}_details',
                'dataOperation': 'add',
                'dataCountry': self.country,
                'accountHolderName': self.name[0] + ' ' + self.name[1],
                'accountToken': card_id,
                'expiryMonth': str(int(exp_month)),
                'expiryYear': exp_year,
                'cvvToken': cvv_id,
                'address': {
                    'addressType': 'billing',
                    'addressOperation': 'add',
                    'addressCountry': self.country,
                    'address_line1': self.address_line1,
                    'city': self.city,
                    'region': self.state.lower(),
                    'postal_code': self.postal_code,
                    'country': country,
                },
                'permission': {
                    'dataType': 'permission_details',
                    'dataOperation': 'add',
                    'dataCountry': self.country,
                    'hmac': {
                        'algorithm': 'hmacsha256',
                        'keyToken': r5_keyToken,
                        'data': signedData,
                    },
                    'userCredential': self.xbl_auth,
                },
                'currentContext':
                    r1.json()[0]["data_description"]["details"][0]["data_description"]["currentContext"][
                        "default_value"]
            },
            'pxmac': r1.json()[0]["data_description"]["pxmac"]["default_value"],
        }

        if captchaSolution is not None:
            payload['audioCaptchaId'] = audioCaptchaId
            payload['audioCaptchaReg'] = audioCaptchaReg
            payload['captchaId'] = captchaId
            payload['captchaReg'] = captchaReg
            payload['details']['captchaSolution'] = captchaSolution
            payload['details']['captchaType'] = captchaType

        r7 = s.post(
            url='https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx',
            params={
                'country': self.country,
                'language': self.language,
                'partner': 'webblends',
                'completePrerequisites': 'True',
            },
            headers=h,
            json=payload
        )

        if "id" in r7.json():
            self.card_id = r7.json()["id"]

        if "accountId" in r7.json():
            self.account_id = r7.json()["accountId"]

        data.vccs[full] += 1
        if data.vccs[full] >= MAX_VCC_USES:
            if config['remove_resources']:
                doFileOperation("remove:vcc", full)

        if r7.status_code == 200 and self.card_id is not None:

            log(Fore.LIGHTGREEN_EX, '[VCC]', "Added card.", {'email': self.email, 'card': card, 'provider': '1'})
            return True

        else:

            # print(r7.status_code, r7.text)

            time_amount = config['cooldown']

            if "InvalidCaptcha" in r7.text:
                log(Fore.MAGENTA, "[CAPTCHA]", "Faced captcha add VCC. Solving...", {'email': self.email})

                c_1 = self.session.get(
                    'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
                    params={
                        'type': 'visa,amex,mc',
                        'showChallenge': 'True',
                        'partner': 'webblends',
                        'orderId': orderId,
                        'operation': 'Add',
                        'language': self.language,
                        'family': 'credit_card',
                        'country': self.country,
                        'completePrerequisites': 'true',
                    },
                    headers=h,
                )

                if c_1.status_code != 200:
                    return False

                data_ = c_1.json()[2]['data_description']

                audioCaptchaId = data_['audioCaptchaId']['default_value']
                audioCaptchaReg = data_['audioCaptchaReg']['default_value']
                captchaId = data_['captchaId']['default_value']
                captchaReg = data_['captchaReg']['default_value']
                ImageURL = c_1.text.split('"sourceUrl":"data:image/png;base64,')[1].split('"')[0]

                def solvecaptcha(CAP_KEY, IMAGE):
                    r = requests.post(
                        'https://api.capmonster.cloud/createTask',
                        json={
                            "clientKey": CAP_KEY,
                            "task": {
                                "type": "ImageToTextTask",
                                "body": IMAGE,
                                "CapMonsterModule": 'hotmail'
                            }
                        }
                    )

                    taskId = r.json()['taskId']

                    for a in range(120):
                        time.sleep(1)

                        r = requests.get(
                            'https://api.capmonster.cloud/getTaskResult',
                            json={
                                "clientKey": CAP_KEY,
                                "taskId": taskId
                            }
                        )

                        if r.json()['status'] == 'processing':
                            continue
                        elif r.json()['status'] == 'ready':
                            text = r.json()['solution']['text']
                            return text
                        else:
                            return False
                    else:
                        return False

                captchaSolution = solvecaptcha(config['capmonster_key'], ImageURL)

                if captchaSolution is False:
                    debug("[CAPTCHA]", "Captcha failed...")
                    return self.addCardv2(full, card, cvv, exp_month, exp_year, cvSeed)

                log(Fore.MAGENTA, "[CAPTCHA]", "Solved Captcha.", {'email': self.email, 'solution': captchaSolution})

                return self.addCardv2(full, card, cvv, exp_month, exp_year, cvSeed, audioCaptchaId, audioCaptchaReg,
                                      captchaId, captchaReg, captchaSolution, 'image')

            if 'ValidationFailed' in r7.text:
                if config['remove_resources']:
                    doFileOperation("remove:vcc", full)
                log(Fore.RED, '[VCC]', "VCC cannot be validated.",
                    {'email': self.email, 'card': card, 'sleeping': str(time_amount) + "s"})

                if config['retry']:
                    time.sleep(time_amount)
                    return self.addCardv2(full, card, cvv, exp_month, exp_year)

                return False

            if not 'innererror' in r7.json():
                pass

            if not r7.json()["innererror"]["code"] == "ValidationFailed":
                if r7.json()["innererror"]["code"] == "InvalidRequestData":
                    log(Fore.RED, '[VCC]', "VCC endpoint rate limited.",
                        {'email': self.email, 'retrying': str(time_amount) + "s"})
                    time.sleep(time_amount)
                    return self.addCardv2(full, card, cvv, exp_month, exp_year)
                elif r7.json()["innererror"]["code"] == "ExceededMaxCardsPerAccountLimit":
                    log(Fore.RED, '[VCC]', "Maximium limit of credit cards per account has been reached.",
                        {'email': self.email})
                else:
                    log(Fore.RED, '[VCC]', 'Unknown error', {'status_code': r7.status_code, 'text': r7.json()})

            return False

    def addCard(self, full, card: str, cvv: str, exp_month: str, exp_year: str):

        return self.addCardv2(full, card, cvv, exp_month, exp_year)

        global MAX_VCC_USES

        s = tls_client.Session(
            random_tls_extension_order=True,
            client_identifier=client_identifier,
        )

        s.cookies.update(
            self.session.cookies
        )

        s.headers = self.session.headers

        ses = str(uuid4())

        s.headers.update(
            {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'authorization': self.msadelegate,
                'content-type': 'application/json',
                'correlation-context': 'v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentSelectResourceType.1,ms.b.tel.partner=northstarweb,ms.c.cfs.payments.partnerSessionId=' + ses,
                'ms-cv': 'K0VfE5shDeNFLzHDHkP7Oo.9',
                'origin': 'https://account.microsoft.com',
                'referer': 'https://account.microsoft.com/',
                'user-agent': self.USER_AGENT,
                'x-ms-flight': 'PXUsePartnerSettingsService,partnerSettingsVersion_23.01.2024-23.36.48-068',
                'x-ms-pidlsdk-version': '2.4.3_reactview',
            }
        )

        # log(Fore.LIGHTBLUE_EX, '[VCC]', "Received VCC.", {'card': card})

        language = "en-US"
        country = self.language.split("-")[-1].lower()

        if self.msadelegate is None:
            self.getDelegate()


        card_type = "visa"
        if card.startswith("5"):
            card_type = "mc"
        elif card.startswith("6"):
            card_type = "amex"

        self.card_type = card_type

        t = s.get(
            'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
            params={
                'partner': 'northstarweb',
                'operation': 'Select',
                'language': language,
                'country': country,
                'allowedPaymentMethods': '["credit_card","direct_debit.ach","direct_debit.sepa","direct_debit.ideal_billing_agreement","mobile_billing_non_sim","ewallet.paypal","ewallet.alipay_billing_agreement","ewallet.kakaopay","ewallet.venmo"]'
            },
            timeout_seconds=TIMEOUT
        )

        r4_params = {
            'type': 'visa,amex,mc',
            'partner': 'northstarweb',
            'operation': 'Add',
            'country': country,
            'language': language,
            'family': 'credit_card',
        }

        r4 = s.get(
            'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentMethodDescriptions',
            params=r4_params,
            timeout_seconds=TIMEOUT
        )

        r2 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/cvv/getToken",
            json={
                "data": cvv
            },
            headers={
                # 'Ms-Cv': 'd7py+AWTcgtQEbbOnPdyJY.4',
                'origin': 'https://account.microsoft.com',
                'referer': 'https://account.microsoft.com/'
            },
            timeout_seconds=TIMEOUT
        )
        cvv_id = r2.json()["data"]

        r3 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/pan/getToken",
            json={
                "data": card
            },
            timeout_seconds=TIMEOUT
        )
        card_id = r3.json()["data"]

        def hmac_(card, msadelegate) -> tuple[str, str]:
            key_token = random.randbytes(64)
            key_token_b64 = base64.b64encode(key_token).decode()
            msg = f"Pan:{card}|HMACKey:{key_token_b64}|UserCredential:{msadelegate}"
            return base64.b64encode(hmac.new(key_token, msg.encode(), hashlib.sha256).digest()).decode(), key_token_b64

        signedData, KeyData = hmac_(card, self.msadelegate)

        r6 = s.post(
            "https://tokenization.cp.microsoft.com/tokens/piAuthKey/getToken",
            json={
                "data": KeyData
            },
            timeout_seconds=TIMEOUT
        )

        # print(r6.status_code, r6.text)

        r5_keyToken = r6.json()["data"]

        r5_json = {
            'paymentMethodFamily': r4.json()[0]["data_description"]["paymentMethodFamily"]["default_value"],
            'paymentMethodType': card_type,
            'paymentMethodOperation': r4.json()[0]["data_description"]["paymentMethodOperation"]["default_value"],
            'paymentMethodCountry': r4.json()[0]["data_description"]["paymentMethodCountry"]["default_value"],
            'paymentMethodResource_id': 'credit_card.' + card_type,
            'sessionId': str(uuid4()),
            'context': r4.json()[0]["data_description"]["context"]["default_value"],
            'riskData': {
                'dataType': 'payment_method_riskData',
                'dataOperation': 'add',
                'dataCountry': country,
                'greenId': str(uuid4()),
            },
            'details': {
                'dataType': f'credit_card_{card_type}_details',
                'dataOperation': 'add',
                'dataCountry': country,
                'accountHolderName': self.name[0] + ' ' + self.name[1],
                'accountToken': card_id,
                'expiryMonth': str(int(exp_month)),
                'expiryYear': exp_year,
                'cvvToken': cvv_id,
                'address': {
                    'addressType': 'billing',
                    'addressOperation': 'add',
                    'addressCountry': country,
                    'address_line1': self.address_line1,
                    'city': self.city,
                    'region': self.state.lower(),
                    'postal_code': self.postal_code,
                    'country': country,
                },
                'permission': {
                    'dataType': 'permission_details',
                    'dataOperation': 'add',
                    'dataCountry': country,
                    'hmac': {
                        'algorithm': 'hmacsha256',
                        'keyToken': r5_keyToken,
                        'data': signedData,
                    },
                    'userCredential': self.msadelegate,
                },
                'currentContext': r4.json()[0]["data_description"]["details"][0]["data_description"]["currentContext"][
                    "default_value"]
            },
            'pxmac': r4.json()[0]["data_description"]["pxmac"]["default_value"],
        }
        r5_params = {
            'country': country,
            'language': language,
            'partner': 'northstarweb',
        }

        r5 = s.post(
            "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx",
            json=r5_json,
            params=r5_params,
            timeout_seconds=TIMEOUT
        )

        if "id" in r5.json():
            self.card_id = r5.json()["id"]

        if "accountId" in r5.json():
            self.account_id = r5.json()["accountId"]

        data.vccs[full] += 1
        if data.vccs[full] >= MAX_VCC_USES:
            if config['remove_resources']:
                doFileOperation("remove:vcc", full)

        print(r5.status_code, r5.text)

        if r5.status_code == 200:

            if 'captchaSolution' in r5.text:
                debug("[CAPTCHA]", "Faced captcha on adding card.", {'email': self.email, 'card': card})
            else:
                log(Fore.LIGHTGREEN_EX, '[VCC]', "Added card.", {'email': self.email, 'card': card})
                return True
        else:

            time_amount = 900

            if not r5.json()["innererror"]["code"] == "ValidationFailed":
                if r5.json()["innererror"]["code"] == "InvalidRequestData":
                    log(Fore.RED, '[VCC]', "VCC endpoint rate limited.",
                        {'email': self.email, 'retrying': str(time_amount) + "s"})
                    time.sleep(time_amount)
                    return self.addCard(full, card, cvv, exp_month, exp_year)
            else:
                if config['remove_resources']:
                    doFileOperation("remove:vcc", full)
                log(Fore.RED, '[VCC]', "VCC cannot be validated.",
                    {'email': self.email, 'card': card, 'sleeping': str(time_amount) + "s"})
                time.sleep(time_amount)
            return False

    def setBillingAdress(self):

        r1_json = {
            "address_line1": self.address_line1,
            "country": self.country,
            "addressCountry": self.country,
            "addressType": "billing",
            "postal_code": self.postal_code,
            "city": self.city,
            "region": self.state,
            'set_as_default_billing_address': 'True',
        }

        r1 = self.session.post(
            "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addresses",
            json=r1_json,
            headers={
                "origin": "https://www.microsoft.com",
                "referer": "https://www.microsoft.com/",
                "authorization": self.xbl_auth,
                "correlation-context": f"v=1,ms.b.tel.scenario=commerce.payments.PaymentInstrumentAdd.1,ms.b.te"
                                       f"l.partner=XboxCom,ms.c.cfs.payments.partnerSessionId={str(uuid4())}",
                "x-ms-flight": "enablePaymentMethodGrouping,EnableThreeDSOne",
                "x-ms-pidlsdk-version": "2.4.3_reactview"
            },
            timeout=TIMEOUT
        )

        # print(r1.text)
        if "<Id>" in r1.text:
            id = r1.text.split("<Id>")[1].split("</Id>")[0]
            self.address_id = id
        # print(id)

        if r1.ok:
            log(Fore.LIGHTGREEN_EX, "[ADRESS]", "Added payment adress.", {'email': self.email, 'id': id})
        else:
            # print("DIDNT WORK")
            print(r1.json())

    def removeCard(self):

        if self.msadelegate is None:
            self.getDelegate()
        r3 = self.session.get(
            f'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language={self.language}',
            headers={
                'accept': 'application/json',
                'authorization': self.msadelegate,
                'content-type': 'application/json',
                'origin': 'https://account.microsoft.com',
                'referer': 'https://account.microsoft.com/',
                'ms-cV': '/FGix5cmYTr0cIBeUxi2rQ.1',
            },
            timeout=TIMEOUT
        )

        try:
            r4_creditcard_id = r3.json()[0]["id"]
        except:
            log(Fore.LIGHTYELLOW_EX, '[REMOVE]', 'No linked card.', {'email': self.email})
            return False

        r4_params = {
            'partner': 'northstarweb',
            'language': f'{self.language}',
        }

        r4 = self.session.delete(
            f'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx/{r4_creditcard_id}',
            params=r4_params,
            headers={
                'accept': '*/*',
                'origin': 'https://account.microsoft.com',
                'referer': 'https://account.microsoft.com/',
                'authorization': self.msadelegate,
                'ms-cv': '/FGix5cmYTr0cIBeUxi2rQ.3',
            },
            timeout=TIMEOUT
        )

        if r4.ok:
            log(Fore.LIGHTGREEN_EX, '[REMOVE]', 'Removed card.', {'email': self.email})

    def purchase_two(self, productID):
        global REVOLUT_QUEUE, REVOLUT_WAIT_BETWEEN_OTP, TIMEOUT

        mscv = getRandom(20) + ".10"

        r1_headers = {
            'accept': '*/*',
            'connection': 'keep-alive',
            'origin': 'https://www.microsoft.com',
            'referer': 'https://www.microsoft.com/',
            'authorization': self.xbl_auth,
            'correlation-context': 'v=1,ms.b.tel.scenario=commerce.payments.AddressAdd.1,ms.b.tel.partner=AccountMicrosoftCom,ms.c.cfs.payments.partnerSessionId=d8VcHbeGb0e90kU9',
            'ms-correlationid': str(uuid4()),
            'ms-requestid': str(uuid4()),
            'x-ms-pidlsdk-version': '1.21.2_jqueryview',
        }

        r1_params = {
            'partner': 'webblends',
            'language': self.language,
            'avsSuggest': 'True',
        }

        r1_data = {
            'addressType': 'billing',
            'addressCountry': self.country,
            'address_line1': self.address_line1,
            'city': self.city,
            'region': self.state,
            'postal_code': self.postal_code,
            'country': self.country,
            'set_as_default_billing_address': 'True',
        }

        r1 = self.session.post('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx',
                               params=r1_params,
                               json=r1_data,
                               headers=r1_headers,
                               timeout=TIMEOUT)

        r2_params = {
            'partner': 'webblends',
            'language': self.language,
            'avsSuggest': 'False',
        }

        r2_data = {
            'set_as_default_shipping_address': False,
            'set_as_default_billing_address': True,
            'is_user_entered': True,
            'id': 'entered',
            'country': self.country,
            'region': self.state,
            'city': self.city,
            'address_line1': self.address_line1,
            'postal_code': self.postal_code,
            'is_customer_consented': True,
            'is_avs_full_validation_succeeded': True,
        }

        r2 = self.session.post('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/addressesEx',
                               params=r2_params,
                               json=r2_data,
                               headers=r1_headers,
                               timeout=TIMEOUT
                               )

        r4_headers = {
            'accept': '*/*',
            'authorization': self.xbl_auth,
            'ms-cv': mscv,
            'origin': 'https://www.xbox.com',
            'referer': 'https://www.xbox.com/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'x-ms-api-version': '1.0',
        }

        r4_params = {
            'locale': self.language,
        }

        r4 = self.session.get(f'https://emerald.xboxservices.com/xboxcomfd/contextualStore/productDetails/{productID}',
                              params=r4_params,
                              headers=r4_headers,
                              timeout=TIMEOUT
                              )

        avalibilityId = r4.json()["productSummaries"][0]["specificPrices"]["purchaseable"][0]["availabilityId"]
        skuId = r4.json()["productSummaries"][0]["preferredSkuId"]

        r5_params = {
            'ms-cv': mscv,
            'noCanonical': 'true',
            'market': self.country.upper(),
            'locale': self.language,
            'clientName': 'XboxCom'
        }

        r5_data = {
            'data': '{"products":[{"productId":"' + productID + '","skuId":"' + skuId + '","availabilityId":"' + avalibilityId + '"}],"campaignId":"xboxcomct","callerApplicationId":"XboxCom","expId":["EX:sc_xboxgamepad","EX:sc_xboxspinner","EX:sc_xboxclosebutton","EX:sc_xboxuiexp","EX:sc_disabledefaultstyles","EX:sc_gamertaggifting"],"flights":["sc_xboxgamepad","sc_xboxspinner","sc_xboxclosebutton","sc_xboxuiexp","sc_disabledefaultstyles","sc_gamertaggifting"],"clientType":"XboxCom","data":{"usePurchaseSdk":"true"},"layout":"Modal","cssOverride":"XboxCom2NewUI","theme":"dark","scenario":"","suppressGiftThankYouPage":"false"}',
            'auth': '{"XToken":"' + self.xbl_auth + '"}',
        }

        r5_headers = {
            'accept': 'text/html,application/xhtml+xml,''application/xml;q=0.9,image/webp,*/*;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'accept-encoding': 'gzip, deflate, br',
            # 'Accept-Language': 'en-US,en;q=0.5',
            'referer': 'https://www.xbox.com/',
            'origin': 'https://www.xbox.com',
            'upgrade-insecure-requests': '1',
            'Sec-Fetch-Dest': 'iframe',
            'Sec-Fetch-User': '?1',
        }

        s = tls_client.Session(
            client_identifier=client_identifier,
            random_tls_extension_order=True
        )
        s.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }

        s.timeout_seconds = TIMEOUT

        r5 = s.post(
            'https://www.microsoft.com/store/buynow',
            params=r5_params,
            data=r5_data,
            headers=r5_headers
        )

        self.session.cookies.update(
            r5.cookies
        )

        if r5.status_code != 200:
            error("[CART]", "Error while buying",
                  {'email': self.email, 'r': 5, 'code': r5.status_code, 'text': r5.text})
            return False

        cvSeed = r5.text.split('"cv":"')[1].split('"')[0]

        pi_id = self.card_id

        flights = r5.text.split('"flights":[')[1].split(']')[0]
        prePareCartFlights = flights.replace("\"", "").split(',')

        riskId = r5.text.split('"riskId":"')[1].split('"')[0]

        ses_id = riskId
        cartId = r5.text.split('"cartId":"')[1].split('"')[0]

        muid = r5.text.split('"alternativeMuid":"')[1].split('"')[0]
        vectorId = r5.text.split('"vectorId":"')[1].split('"')[0]
        corId = r5.text.split('"correlationId":"')[1].split('"')[0]
        trackId = r5.text.split('"trackingId":"')[1].split('"')[0]
        akkuId = self.account_id
        id_id = r5.text.split(',"soldToAddressId":"')[1].split('"')[0]

        r7_headers = {
            'accept': '*/*',
            'authorization': self.xbl_auth,
            'ms-cv': cvSeed + ".2",
            'origin': 'https://www.microsoft.com',
            'referer': 'https://www.microsoft.com/',
            'x-authorization-muid': muid,
            'x-ms-correlation-id': corId,
            'x-ms-tracking-id': trackId,
            'x-ms-vector-id': vectorId,
        }

        r7_params = {
            'appId': 'BuyNow',
            'cartId': cartId,
        }

        r7_data = {
            "locale": self.language,
            "market": self.country.upper(),
            "catalogClientType": "",
            "clientContext": {
                "client": "XboxCom",
                "deviceFamily": "Web"
            },
            "flights": prePareCartFlights,
            "paymentInstrumentId": self.card_id,
            "csvTopOffPaymentInstrumentId": None,
            "billingAddressId":
                {
                    "accountId": akkuId,
                    "id": id_id
                },
            "sessionId": ses_id,
            "orderState": "CheckingOut"
        }

        r7 = self.session.put('https://cart.production.store-web.dynamics.com/v1.0/cart/updateCart',
                              params=r7_params,
                              json=r7_data,
                              headers=r7_headers,
                              timeout=TIMEOUT
                              )

        if not r7.ok:
            return self.purchase_two('CFQ7TTC0KHS0')

        totalAmount = r7.json()['cart']['totalAmount']
        currencyCode = r7.json()['cart']['currencyCode']

        r6_headers = {
            'accept': '*/*',
            'connection': 'keep-alive',
            'origin': 'https://www.microsoft.com',
            'referer': 'https://www.microsoft.com/',
            'authorization': self.xbl_auth,
            'content-type': 'application/json',
            'correlation-context': f'v=1,ms.b.tel.scenario=commerce.payments.PaymentSessioncreatePaymentSession.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId={cvSeed.split(".")[0]}',
            'x-ms-flight': 'enablePaymentMethodGrouping,enableGlobalPiInAddResource,HonorNewRiskCode,EnableThreeDSOne',
            'x-ms-pidlsdk-version': '2.4.3_reactview',
        }

        payment_data = {
            "piid": self.card_id,
            "language": self.language,
            "partner": "webblends",
            "piCid": self.account_id,
            "amount": float(totalAmount),  # Always depends on taxes etc.
            "currency": currencyCode,
            "country": self.country.upper(),
            "hasPreOrder": "false",
            "challengeScenario": "RecurringTransaction",
            "challengeWindowSize": "03",
            "purchaseOrderId": cartId
        }

        r6_params = {
            'paymentSessionData': str(payment_data),
            'operation': 'Add',
        }

        r6 = self.session.get('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/PaymentSessionDescriptions',
                              params=r6_params,
                              headers=r6_headers,
                              timeout=TIMEOUT
                              )

        expectedClientActionId = None
        if not r6.ok:
            expectedClientActionId = False

        try:
            t = r6.json()[0]
        except:
            expectedClientActionId = False

        if expectedClientActionId is False:
            error("[3DS ERROR]", "Error occured, send this to OculusVision.",
                  {'status': r6.status_code, 'text': r6.text})
            return self.purchase_two("CFQ7TTC0KHS0")

        if "clientAction" in r6.json()[0]:
            if "context" in r6.json()[0]["clientAction"]:
                if r6.json()[0]["clientAction"]["context"]["challengeStatus"] == "Unknown":
                    payment_data = r6.json()[0]["clientAction"]["context"].copy()
                    payment_data["cv"] = f"PyFAkIBb{getRandom(5)}8+tx8zbXo.33.3"

                    r6_headers["ms-cv"] = payment_data["cv"]

                    r6_1_params = {
                        "timezoneOffset": random.choice([-120, -60, 60, 120]),
                        "paymentSessionOrData": str(payment_data).replace("True", "true").replace("False", "false"),
                        "operation": "RenderPidlPage"
                    }

                    r6_1 = self.session.get(
                        'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/challengeDescriptions',
                        params=r6_1_params,
                        headers=r6_headers,
                        timeout=TIMEOUT
                    )

                    if type(r6_1.json()) != list:
                        print("FOR OCULUSVISION:" + str(r6_1.status_code) + " "+ str(r6_1.json()))
                        print("----")
                        print(str(r6.json()))
                        print("----")

                    revolut_session = requests.Session()
                    revolut_session.headers = self.session.headers

                    if not config['proxyless_otp']:
                        revolut_session.proxies = self.session.proxies

                    if "identity" in r6_1.json()[0]:
                        if "description_type" in r6_1.json()[0]["identity"]:
                            if r6_1.json()[0]["identity"]["description_type"] == "threeDSChallengeIFrame":
                                # debug("[3DS IFRAME]", "Faced 3DS Iframe...", {'email': self.email})

                                displayContent = r6_1.json()[0]["displayDescription"][0]["members"][0]["displayContent"]
                                expectedClientActionId = r6_1.json()[0]["displayDescription"][0]["members"][0][
                                    "expectedClientActionId"]

                                threeDSSessionData = \
                                    displayContent.split('name=\"threeDSSessionData\" value=\"')[1].split('\"')[0]
                                cres = displayContent.split('name=\"creq\" value=\"')[1].split('\"')[0]

                                if config['separate_otp']:

                                    REVOLUT_QUEUE.append(self.email)

                                    while True:
                                        if REVOLUT_QUEUE[0] != self.email:
                                            time.sleep(2)
                                        else:
                                            time.sleep(REVOLUT_WAIT_BETWEEN_OTP)
                                            break

                                r7 = revolut_session.post(
                                    f'https://acs.revolut.com/challenges/browser',
                                    data={
                                        "creq": cres,
                                        "threeDSSessionData": threeDSSessionData,
                                        "cspStep": "cspNone"
                                    },
                                    timeout=TIMEOUT
                                )

                                try:
                                    ID = \
                                        r7.text.split(
                                            "transactionInfoURL: 'https://acs.revolut.com/transactions/status/")[
                                            1].split("'")[0]
                                except:
                                    error("[REVOLUT 3DS]",
                                          "Failed to load Revolut transaction confirmation, retrying...",
                                          {'email': self.email})

                                    if config['separate_otp']:
                                        REVOLUT_QUEUE.remove(self.email)

                                    return self.purchase_two(productID)

                                debug("[REVOLUT 3DS]", "Please confirm the transaction in your app.",
                                      {'email': self.email})

                                STATUS = "PENDING"

                                i = 0

                                while STATUS == "PENDING":
                                    r8 = revolut_session.get(f'https://acs.revolut.com/transactions/status/{ID}',
                                                          timeout=TIMEOUT)
                                    STATUS = r8.json()["status"]
                                    sleeper = 2
                                    time.sleep(sleeper)
                                    i += 1

                                    conf_timeout = 60

                                    if i >= conf_timeout:
                                        debug("[REVOLUT 3DS]", "Confirmation timed out, retrying...",
                                              {'email': self.email, 'time': str(conf_timeout * sleeper) + 's'})

                                        if config['separate_otp']:
                                            REVOLUT_QUEUE.remove(self.email)

                                        return self.purchase_two(productID)
                                else:
                                    if STATUS == "AUTHENTICATED":
                                        info("[REVOLUT 3DS]", "Successfully confirmed in app.", {'email': self.email})
                                        revolut_session.post(f'https://acs.revolut.com/challenges/browser/{ID}/submit',
                                                          json={"reason": "AUTHENTICATED"},
                                                          timeout=TIMEOUT)

                                cres += "=" * (4 - (len(cres) % 4))
                                cres = json.loads(base64.b64decode(cres))

                                def creq():
                                    text = {
                                        "threeDSServerTransID": cres["threeDSServerTransID"],
                                        "transStatus": "Y",
                                        "acsTransID": cres["acsTransID"],
                                        "messageType": cres["messageType"],
                                        "messageVersion": cres["messageVersion"]
                                    }
                                    text = json.dumps(text, separators=(',', ':'))
                                    return base64.b64encode(text.encode("utf-8")).decode()

                                creq = creq()

                                r6_2 = self.session.post(
                                    f'https://paymentinstruments.mp.microsoft.com/V6.0/paymentSessions/{expectedClientActionId}/NotifyThreeDSChallengeCompleted',
                                    data={
                                        "cres": creq.replace("=", ""),
                                        "threeDSSessionData": threeDSSessionData
                                    },
                                    timeout=TIMEOUT
                                )

                                if config['separate_otp']:
                                    REVOLUT_QUEUE.remove(self.email)

        if not r6.ok:
            error("[3DS ID]", "Error while getting 3ds ID", {'email': self.email})
            return False
        threedsId = r6.json()[0]["clientAction"]["context"]["id"]

        r8_headers = {
            'accept': '*/*',
            'authorization': self.xbl_auth,
            'content-type': 'application/json',
            'ms-cv': cvSeed,
            'origin': 'https://www.microsoft.com',
            'referer': 'https://www.microsoft.com/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'x-authorization-muid': muid,
            'x-ms-correlation-id': corId,
            'x-ms-tracking-id': trackId,
            'x-ms-vector-id': vectorId,
        }

        r8_params = {
            'appId': 'BuyNow',
        }

        r8_data = {
            'cartId': cartId,
            'market': self.country.upper(),
            'locale': self.language,
            'catalogClientType': '',
            'callerApplicationId': '_CONVERGED_XboxCom',
            'clientContext': {
                'client': 'XboxCom',
                'deviceFamily': 'Web',
            },
            'paymentSessionId': ses_id,
            'riskChallengeData': {
                'type': 'threeds2',
                'data': threedsId,
            },
            'paymentInstrumentId': pi_id,
            'paymentInstrumentType': self.card_type,
            'email': self.email,
            'csvTopOffPaymentInstrumentId': None,
            'billingAddressId': {
                'accountId': akkuId,
                'id': id_id,
            },
            'currentOrderState': 'CheckingOut',
            'flights': prePareCartFlights,
            'itemsToAdd': {},
        }

        if expectedClientActionId is not None:
            r8_data["rdsAsyncPaymentStatusCheck"] = False

        r8 = self.session.post('https://cart.production.store-web.dynamics.com/cart/v1.0/Cart/purchase',
                               params=r8_params,
                               json=r8_data,
                               headers=r8_headers,
                               timeout=TIMEOUT
                               )

        if r8.ok:
            if "cart" in r8.json():
                if "id" in r8.json()["cart"]:
                    info("[PURCHASE]", "Purchased xbox game pass.", {'email': self.email})
                    return True

            elif "events" in r8.json():
                print(r8.json())
                if "cart" in r8.json()["events"]:
                    if "data" in r8.json()["events"]["cart"][0]:
                        if "reason" in r8.json()["events"]["cart"][0]["data"]:
                            if "subReasons" in r8.json()["events"]["cart"][0]["data"]["reason"]:
                                subreason = r8.json()["events"]["cart"][0]["data"]["subReasons"]
                            else:
                                subreason = "User error (maybe not enough money on bank account)"
                            error("[PURCHASE]", "Error while buying",
                                  {'email': self.email, 'reason': r8.json()["events"]["cart"][0]["data"]["reason"],
                                   'subreasons': subreason}
                                  )
                            return False
            print(r8.json())
        else:
            error("[CART]", "Error while buying",
                  {'email': self.email, 'r': 8, 'code': str(r8.status_code), 'text': str(r8.text)})
            return False

    def hasSubscriptions(self, print=False):

        r4_params = {
            'fref': 'home.drawers.payment-options.manage-payment',
            'refd': 'account.microsoft.com',
        }

        r4 = self.session.get(
            'https://account.microsoft.com/services',
            params=r4_params,
            headers={
                'referer': 'https://account.microsoft.com/billing/orders',
            },
            timeout=TIMEOUT
        )

        r4_verificationtoken = \
            r4.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]

        r1_params = {
            "excludeWindowsStoreInstallOptions": False,
            "excludeLegacySubscriptions": False,
            "isReact": True,
            "includeCmsData": False
        }

        mscv = f"fdPaYz{getRandom(5)}r9vg/.12.27"

        r1_headers = {
            '__RequestVerificationToken': r4_verificationtoken,
            "correlation-context": f"v=1,ms.b.tel.market={self.language},ms.b.tel.scenario=ust.amc.services.amcserviceslanding,ms.c.ust.scenarioStep=AmcServicesLanding.Index",
            "Ms-Cv": mscv,
            "referer": "https://account.microsoft.com/services",
            "x-iscloudos": "false",
            "x-requested-with": "XMLHttpRequest",
            "x-tzoffset": "120"

        }

        r1 = self.session.get("https://account.microsoft.com/services/api/subscriptions-and-alerts",
                              params=r1_params,
                              headers=r1_headers,
                              timeout=TIMEOUT)

        if r1.ok:
            if "active" in r1.json():
                if len(r1.json()["active"]) == 0 and len(r1.json()["canceled"]) == 0 and len(
                        r1.json()["commercial"]) == 0:
                    return False
                if len(r1.json()["active"]) > 0:
                    if config['refund_on_start']:
                        if print:
                            debug(f"[NOT REFUNDED]", "Starting refund...", {'email': self.email})
                        self.cancelAndRefundPlan()
                        return None
                    else:
                        # debug(f"[NOT REFUNDED]", "Account is not refunded.", {'email': self.email})
                        return True
        if print:
            log(Fore.LIGHTYELLOW_EX, "[ALREADY]", "Account already purchased gamepass.", {'email': self.email})
        if config['remove_resources'] or config['remove_already_purchased']:
            doFileOperation('remove:account', self.combo)
        return None

    def cancelAndRefundPlan(self):

        r4_params = {
            'fref': 'home.drawers.payment-options.manage-payment',
            'refd': 'account.microsoft.com',
        }

        r4 = self.session.get(
            'https://account.microsoft.com/services',
            params=r4_params,
            headers={
                'referer': 'https://account.microsoft.com/billing/orders',
            },
            timeout=TIMEOUT
        )

        r4_verificationtoken = \
            r4.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]

        r1_params = {
            "excludeWindowsStoreInstallOptions": False,
            "excludeLegacySubscriptions": False,
            "isReact": True,
            "includeCmsData": False
        }

        mscv = f"fdPaYz{getRandom(5)}r9vg/.12.27"

        r1_headers = {
            '__RequestVerificationToken': r4_verificationtoken,
            "correlation-context": f"v=1,ms.b.tel.market={self.language},ms.b.tel.scenario=ust.amc.services.amcserviceslanding,ms.c.ust.scenarioStep=AmcServicesLanding.Index",
            "Ms-Cv": mscv,
            "referer": "https://account.microsoft.com/services",
            "x-iscloudos": "false",
            "x-requested-with": "XMLHttpRequest",
            "x-tzoffset": "120"

        }

        r1 = self.session.get("https://account.microsoft.com/services/api/subscriptions-and-alerts",
                              params=r1_params,
                              headers=r1_headers,
                              timeout=TIMEOUT)

        if r1.ok:
            if "active" in r1.json():

                if len(r1.json()["active"]) == 0:
                    debug("[SUBSCRIPTION]", "No active subscription found.", {'email': self.email})
                    return True

                for ob in r1.json()["active"]:
                    id = ob["id"]
                    type = ob["type"]

                    r3_params = {
                        "serviceId": id,
                        "serviceType": type,
                        "cancelType": "NotDefined",
                        "conversionPathTypes": ""
                    }

                    r3_headers = {
                        '__RequestVerificationToken': r4_verificationtoken,
                        "correlation-context": f"v=1,ms.b.tel.market={self.language}",
                        "Ms-Cv": mscv,
                        "referer": "https://account.microsoft.com/services/xboxgamepassultimate/cancel?fref=billing-cancel",
                        "x-iscloudos": "false",
                        "x-requested-with": "XMLHttpRequest",
                        "x-tzoffset": "120"
                    }

                    r3 = self.session.get("https://account.microsoft.com/services/api/cancelrefunddata",
                                          params=r3_params,
                                          headers=r3_headers,
                                          timeout=TIMEOUT)

                    if r3.ok:
                        amount = r3.json()["data"]["refundData"]["amount"]

                    r2_headers = {
                        '__RequestVerificationToken': r4_verificationtoken,
                        "correlation-context": f"v=1,ms.b.tel.market={self.language},ms.b.tel.scenario=ust.amc.services.amccancel,ms.c.ust.scenarioStep=XboxSave.Final",
                        "Ms-Cv": mscv,
                        "origin": "https://account.microsoft.com",
                        "referer": "https://account.microsoft.com/services/xboxgamepassultimate/cancel?fref=billing-cancel",
                        "X-iscloudos": "false",
                        "x-requested-with": "XMLHttpRequest",
                        "x-tzoffset": "120",
                    }

                    # print(id, type, amount)

                    r2_json = {
                        "serviceId": id,
                        "serviceType": type,
                        "refundAmount": amount,
                        "riskToken": "",
                        "isDunning": False,
                        "locale": self.language,
                        "market": self.country.upper()
                    }

                    r2 = self.session.put("https://account.microsoft.com/services/api/cancelservice",
                                          headers=r2_headers,
                                          json=r2_json,
                                          timeout=TIMEOUT)

                    if r2.ok:
                        log(Fore.LIGHTGREEN_EX, '[SUBSCRIPTION]', "Cancelled and refunded money.",
                            {'email': self.email})
                        return True
                    else:
                        return self.login()
        else:
            return self.login()

    def getLink(self, proxies=None):
        global TIMEOUT

        if proxies is None:
            proxies = self.session.proxies

        s = requests.session()

        s.proxies = proxies

        s.headers = {
            "user-agent": self.USER_AGENT
        }

        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'identity',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Sec-GPC': '1',
            'Upgrade-Insecure-Requests': '1',
        }
        r1 = s.get(
            'https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=token&redirect_uri=https://login.live.com/oauth20_desktop.srf',
            headers=headers,
            timeout=TIMEOUT)
        try:
            ppft = r1.text.split(
                ''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
            log_url = r1.text.split(",urlPost:'")[1].split("'")[0]
        except:
            print(r1.text)
            return
        log_data = f'i13=0&login={self.email}&loginfmt={self.email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={self.password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
        headers = {
            'accept':
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://login.live.com',
            'referer': 'https://login.live.com/',
            'sec-gpcC': '1',
            'upgrade-insecure-requests': '1',
        }
        r2 = s.post(log_url, timeout=TIMEOUT, data=log_data, headers=headers)

        if 'https://account.live.com/proofs/Add' in r2.url:
            headers = {
                'authority': 'account.live.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.8',
                'cache-control': 'max-age=0',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://account.live.com',
                'referer': r2.url,
                'sec-ch-ua': '"Chromium";v="112", "Brave";v="112", "Not:A-Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'sec-gpc': '1',
                'upgrade-insecure-requests': '1',
            }

            _data = {
                'iProofOptions': 'Email',
                'DisplayPhoneCountryISO': 'US',
                'DisplayPhoneNumber': '',
                'EmailAddress': '',
                'canary': r2.text.split('id="canary" name="canary" value="')[1].split('"')[0],
                'action': 'Skip',
                'PhoneNumber': '',
                'PhoneCountryISO': '',
            }

            r2 = s.post(r2.text.split('id="frmAddProof" method="post" action="')[1].split('"')[0],
                        headers=headers, data=_data, timeout=TIMEOUT)

        try:
            rpsTicket = r2.url.split('access_token=')[1].split('&')[0]
        except:
            self.getLink()
            return

        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.7',
            'connection': 'keep-alive',
            'origin': 'https://www.xbox.com',
            'referer': 'https://www.xbox.com/',
            'Sec-GPC': '1',
            'content-type': 'application/json',
            'ms-cv': '6XHlfdK3HMhZEz8LfxSLAl.12',
            'x-xbl-contract-version': '1',
        }

        json_data = {
            'Properties': {
                'AuthMethod': 'RPS',
                'RpsTicket': rpsTicket,
                'SiteName': 'user.auth.xboxlive.com',
            },
            'RelyingParty': 'http://auth.xboxlive.com',
            'TokenType': 'JWT',
        }
        r3 = s.post('https://user.auth.xboxlive.com/user/authenticate', headers=headers, json=json_data,
                    timeout=TIMEOUT)

        userToken = r3.json()['Token']
        while True:
            try:
                deviceToken = DeviceToken.get_device_token()
                break
            except Exception as e:
                continue
        headers = {
            'authority': 'xsts.auth.xboxlive.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.7',
            'content-type': 'application/json',
            'ms-cv': 'u9Vh9cnctxQKKt3hYD1o37.22',
            'origin': 'https://www.xbox.com',
            'referer': 'https://www.xbox.com/',
            'sec-ch-ua': '"Chromium";v="112", "Brave";v="112", "Not:A-Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'sec-gpc': '1',
            'x-xbl-contract-version': '1',
        }

        json_data = {
            'Properties': {
                'SandboxId': 'RETAIL',
                'UserTokens': [
                    userToken,
                ],
                'DeviceToken': deviceToken
            },
            'RelyingParty': 'http://xboxlive.com',
            'TokenType': 'JWT',
        }

        r5 = s.post('https://xsts.auth.xboxlive.com/xsts/authorize', headers=headers, json=json_data, timeout=TIMEOUT)

        xsts = r5.json()['Token']
        uhs = r5.json()['DisplayClaims']['xui'][0]['uhs']
        xbl = f"XBL3.0 x={uhs};{xsts}"

        # print(self.session.headers)

        r6 = self.session.post(
            "https://profile.gamepass.com/v2/offers/47D97C390AAE4D2CA336D2F7C13BA074/",
            headers={
                'authorization': xbl,
            }
        )

        if r6.ok:
            resource = r6.json()["resource"]
            if config['no_duplicates']:
                if resource.strip() in getFileLines(
                        './assets/output/promo_links.txt') or resource.strip() in getFileLines('./assets/output/all/all_links.txt'):
                    log(Fore.LIGHTYELLOW_EX, '[DUPLICATE]', "Received 3 months nitro link.",
                        {'link': resource, 'email': self.email})
                    return True

            data.promos += 1

            log(Fore.LIGHTGREEN_EX, '[PROMO]', "Received 3 months nitro link.", {'link': resource, 'email': self.email})
            save(text=str(resource), filename='assets/output/promo_links.txt')
            save(text=str(resource), filename='assets/output/all/all_links.txt')

            return True
        else:
            log(Fore.RED, '[PROMO]', "Unable to pull promo.",
                {'email': self.email, 'reason': r6.json()["reason"], 'retry': config['force_pull_if_fails']})
            return False


class data:
    start_time = time.time()

    success = 0
    fail = 0
    errors = 0

    promos = 0

    vccs = {}


def titleManager():
    try:
        while True:

            vccs = 0
            for a in data.vccs:
                if data.vccs[a] < MAX_VCC_USES:
                    vccs += 1

            profit = ""
            if config['price'] > 0:
                profit = f" | Profit: {config['price'] * data.success}$"
            ctypes.windll.kernel32.SetConsoleTitleW(
                f"Xbox AIO Tool by @OCULUS4VISION | Success: {data.success} | Locked: {data.fail} | Errors: {data.errors}{profit} | VCCs left: {vccs} | Generated Promotions: {data.promos} | Time Elapsed: {time.strftime('%H:%M:%S', time.gmtime(time.time() - data.start_time))} | by OculusVision"
            )
            time.sleep(0.5)
    except Exception as e:
        print(e)
        pass


def task(combo, LANGUAGE_CODE, card):
    global city, state, postal

    if combo is None:
        for a in range(10):
            try:
                result = Creator(config['captcha_key']).start()
                if result is not None:
                    combo = result
                    break
                else:
                    error("[FAIL]", "Failed to create outlook account. --> Retrying")
                    continue
            except Exception as e:
                error("[FAIL]", "Failed to create outlook account. --> Retrying", {'error': str(e)})
                continue

    try:
        s = Session(combo, LANGUAGE_CODE, city, state, postal)
        logger = s.login()
        addCard = True
        
        # Force continue even after successful login3
        if logger is True:
            subs = s.hasSubscriptions(True)

            if config['purchaser'] and subs is False:
                a, b, c, d = parseVCC(card)
                addCard = s.addCard(card, a, b, c, d)

                if addCard is True:
                    purchase = s.purchase_two("CFQ7TTC0KHS0")
                    
            if config['puller']:
                if s.hasSubscriptions() is True:
                    result = False
                    proxies = None
                    while result is False:
                        result = s.getLink(proxies)
                        if config['force_pull_if_fails'] is False:
                            break
                        if result is False:
                            proxy = getProxy() if config['proxyless'] is False else None
                            proxies = {'http': proxy, 'https': proxy}

            if config['refunder']:
                s.cancelAndRefundPlan()

            if subs is False:
                data.success += 1

            if addCard is True:
                if config['remove_resources']:
                    doFileOperation('remove:account', combo)

    except Exception as e:
        if 'Login error' in str(e) or "KeyError: 'Token'" in str(e) or 'list index out of range' in str(e):
            return task(combo, LANGUAGE_CODE, card)
        elif 'Child account' in str(e):
            debug("[CHILD]", "The account seems to be under 18.", {'email': mail})
            if config['remove_resources']:
                doFileOperation('remove:account', combo)
            return
        elif 'Connection aborted.' in str(e) or 'Connection broken' in str(e):
            return task(combo, LANGUAGE_CODE, card)
        elif 'Cannot connect to proxy' in str(e):
            error("[PROXY ISSUE]", "The proxy wasnt working properly. Retrying... [1]", {'email': mail})
            return task(combo, LANGUAGE_CODE, card)
        elif 'HTTPSConnectionPool' in str(e):
            error("[PROXY ISSUE]", "The proxy wasnt working properly. Retrying... [2]",
                  {'email': mail})
            return task(combo, LANGUAGE_CODE, card)
        elif 'EOF' in str(e):
            error("[PROXY ISSUE]", "The proxy wasnt working properly. Retrying... [3]", {'email': mail})
            return task(combo, LANGUAGE_CODE, card)
        elif 'json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)' in str(e):
            error("[PROXY ISSUE]", "The proxy wasnt working properly. Retrying... [4]", {'email': mail})
            return task(combo, LANGUAGE_CODE, card)
        data.errors += 1
        error("[ERROR OCCURED]", "An error occured.",
              {'email': mail, 'error': str(e), 'traceback': str(traceback.format_exc())})
        pass


for i in range(1):
    threading.Thread(target=titleManager, daemon=True).start()

ACCOUNT_LIST = getFileLines('./assets/accounts.txt')
VCC_LIST = getFileLines('./assets/vccs.txt')
PROXY_LIST = getFileLines('./assets/proxies.txt')

for vcc in VCC_LIST:
    if vcc.strip() != "" and len(vcc.split(':')) == 3:
        data.vccs[vcc] = 0

print()

ressources = {'accounts': len(ACCOUNT_LIST), 'vccs': len(VCC_LIST),
                            'proxies': len(PROXY_LIST) if not config['proxyless'] else 0}

if cre is True and config['creator'] is True:
    ressources['accounts'] = 0

debug("[RESSOURCES]", "-", ressources)

modules = {'purchaser': config['purchaser'], 'puller': config['puller'], 'refunder': config['refunder']}

if cre is True:
    modules['creator'] = config['creator']

debug("[MODULES]", "-", modules)
print()
inp("[START]", "Press any key to start: ")
input()
print()


def main():
    global MAX_VCC_USES, THREADS, ACCOUNT_LIST, VCC_LIST

    with open("./assets/vccs.txt") as f:
        VCC_LIST = [v.strip() for v in f.read().split('\n') if v.strip()]

    # Create a queue of work
    work_queue = []
    
    if not config['rotate_vccs']:
        for vcc_count in range(len(VCC_LIST)):
            for _ in range(MAX_VCC_USES):
                if len(work_queue) >= len(ACCOUNT_LIST):
                    break
                work_queue.append((ACCOUNT_LIST[len(work_queue)], VCC_LIST[vcc_count]))
    else:
        for i in range(len(ACCOUNT_LIST)):
            work_queue.append((ACCOUNT_LIST[i], VCC_LIST[i % len(VCC_LIST)]))

    # Process work with ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS, thread_name_prefix='xbox_worker') as executor:
        futures = []
        for account, vcc in work_queue:
            futures.append(executor.submit(task, account, LANGUAGE_CODE, vcc))
        
        # Wait for all tasks and keep program running
        concurrent.futures.wait(futures)
        
        # Process results if needed
        for future in futures:
            try:
                future.result()
            except Exception as e:
                data.errors += 1
                

main()

print()
info(f"[FINISHED]", "Operation done.")
input()

