import string
import threading
import time
import requests
import tls_client
import random
import datetime
import execjs
import secrets
import codecs
import imap_tools
import concurrent.futures
import json
import yaml
import ctypes

from log import *

config = yaml.safe_load(open('./assets/config.yml', "r"))

package_pwd_script = open("./scripts/packagepwd.js").read()
script = execjs.compile(package_pwd_script)

TIMEOUT = 30


class Helper:

    @staticmethod
    def getCipher(password, random_num, key):
        pwd = script.call("encrypt", password, random_num, key)
        return pwd

    @staticmethod
    def getProxy():
        with open("./assets/proxies.txt") as f:
            proxies = f.read().split('\n')
        return "http://" + random.choice(proxies)

    @staticmethod
    def getPassword():
        if config['custom_password'] is False:
            return Helper.getRandomChars(12)
        else:
            return config['custom_password']

    @staticmethod
    def getRandomChars(amount: int):
        s = ""
        for a in range(amount):
            s += random.choice(string.ascii_letters)
        return s

    @staticmethod
    def getRandomNumbers(amount: int):
        s = ""
        for a in range(amount):
            s += random.choice(string.digits)
        return s

    @staticmethod
    def getBirthday():
        day = random.randint(1, 27)
        month = random.randint(1, 9)
        year = random.randint(1969, 2000)
        return f"{day}:0{month}:{year}"

    @staticmethod
    def getName():

        with open('./scripts/surname.json') as f:
            surnames = json.load(f)

        with open('./scripts/firstname.json') as f:
            firstnames = json.load(f)

        return random.choice(firstnames["data"]), random.choice(surnames["data"])

    @staticmethod
    def save(text="", filename=None):
        file = open(filename, "a")
        add = ""
        add += text
        add += "\n"
        file.write(add)
        file.close()


class Captcha:
    def __init__(self, apikey, sitekey, siteurl, datablob, proxy):

        self.api = config['captcha_api']
        self.api = self.api.lower()

        self.apikey = apikey
        self.sitekey = sitekey
        self.siteurl = siteurl
        self.datablob = datablob
        self.proxy = proxy.replace('http://', '')

    def solve(self):
        c = self.create()

        if c is False:
            return False

        taskId = None
        if "rockcaptcha" in self.api:
            TaskId = c["TaskId"]
        elif "capsolver" in self.api:
            TaskId = c["taskId"]

        started = datetime.datetime.now(datetime.UTC)

        while True:
            c = self.check(TaskId)

            time.sleep(0.05)

            if c is not None:
                return c

            if started + datetime.timedelta(minutes=1) < datetime.datetime.now(datetime.UTC):
                return False

    def create(self):
        if "rockcaptcha" in self.api:
            r = requests.get(
                f'https://api.rockcaptcha.com/FunCaptchaTokenTask?apikey={self.apikey}&sitekey={self.sitekey}&siteurl={self.siteurl}&datablob={self.datablob}&proxy={self.proxy}&affiliateid=36541'
            )
            if r.json()["Message"] == "OK":
                return r.json()
            else:
                log(Fore.RED, '[CAPTCHA]', 'Captcha failed to solve.',
                    {'message': r.json()["Message"], 'action': 'retry'})
                return self.create()
        elif "capsolver" in self.api:
            r = requests.post(
                'https://api.capsolver.com/createTask',
                json={
                    "clientKey": self.apikey,
                    "appId": "98402642-F78F-4F8B-8432-822B439B25DF",
                    "task": {
                        "type": "FunCaptchaTask",
                        "websiteURL": self.siteurl,
                        "websitePublicKey": self.sitekey,
                        "data": "{\"blob\": \"" + self.datablob + "\"}",
                        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                        "proxy": self.proxy
                    }
                }
            )

            if r.json()["errorId"] == 0:
                return r.json()
            elif r.json()["errorCode"] == "ERROR_PROXY_CONNECT_REFUSED":
                log(Fore.RED, '[CAPTCHA]', 'Captcha failed to solve.', {'message': r.json(), 'action': 'retry'})
                return False
            else:
                log(Fore.RED, '[CAPTCHA]', 'Captcha failed to solve.', {'message': r.json(), 'action': 'retry'})
                return self.create()

    def check(self, TaskId):

        if "rockcaptcha" in self.api:

            r = requests.get(
                f'https://api.rockcaptcha.com/getresult?apikey={self.apikey}&taskId={TaskId}'
            )
            if r.json()["Status"] == "SUCCESS":
                log(Fore.BLUE, "[CAPTCHA]", "Captcha solved.", {'solution': r.json()["Data"]["Token"][:28]})
                return r.json()["Data"]["Token"]
            elif r.json()["Status"] == "ERROR":
                log(Fore.RED, '[CAPTCHA]', 'Captcha failed to solve.',
                    {'message': r.json()["Message"], 'action': 'retry'})
                return False
            else:
                return None

        elif "capsolver" in self.api:

            r = requests.post(
                'https://api.capsolver.com/getTaskResult',
                json={
                    "clientKey": self.apikey,
                    "taskId": TaskId
                }
            )

            if r.json()["status"] == "ready":
                token = r.json()["solution"]["token"]
                log(Fore.BLUE, "[CAPTCHA]", "Captcha solved.", {'solution': token[:28]})
                return token
            elif r.json()["status"] == "error":
                log(Fore.RED, '[CAPTCHA]', 'Captcha failed to solve.', {'message': r.json(), 'action': 'retry'})
                return False
            else:
                return None


class IMAP:
    def __init__(self, email, password):
        self.email = email
        self.password = password

    def login(self):
        host = "outlook.office365.com:993"
        if ":" in host:
            box = imap_tools.MailBox(host.split(":")[0], host.split(":")[1])
        else:
            box = imap_tools.MailBox(host)
        try:
            imap_client = box.login(username=self.email, password=self.password)
            return True
        except Exception as e:
            if str(e) == 'Response status "OK" expected, but "NO" received. Data: [b\'LOGIN failed.\']':
                return False
            else:
                return self.login()


class Creator:
    def __init__(self, captcha_api_key):
        self.proxy = Helper.getProxy()
        self.session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)

        self.apikey = captcha_api_key

        self.market = "en-US"

        if self.proxy is not None:
            self.session.proxies = {
                "https": self.proxy,
                "http": self.proxy,
            }

        self.session.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Dnt": "1",
            "Sec-Ch-Ua": "\"(Not(A:Brand\";v=\"99\", \"Chromium\";v=\"121\", \"Google Chrome\";v=\"121\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Gpc": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        }

        self.captchakey = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
        self.hf_id = secrets.token_hex(16)

        # Personal Details

        self.first, self.sur = Helper.getName()

        self.email = self.first.lower() + "." + self.sur.lower() + Helper.getRandomNumbers(6) + "@outlook.com"

        self.password = Helper.getPassword()
        self.birthday = Helper.getBirthday()

    def start(self):
        try:
            r = self.session.get(
                f'https://signup.live.com/signup?lic=1&mkt={self.market}',
                timeout_seconds=TIMEOUT
            )
        except Exception as e:
            if 'unexpected EOF' in str(e):
                return Creator(self.apikey).start()
            raise()
        try:
            uaid = r.text.split('"clientTelemetry":{"uaid":"')[1].split('"')[0]
        except Exception as e:
            return Creator(self.apikey).start()
        tcxt = codecs.decode(r.text.split('"clientTelemetry":{"uaid":"')[1].split(',"tcxt":"')[1].split('"},')[0],
                             'unicode-escape')
        canary = codecs.decode(r.text.split('"apiCanary":"')[1].split('"')[0], 'unicode-escape')
        random_num = r.text.split('var randomNum="')[1].split('"')[0]
        key = r.text.split('var Key="')[1].split('"')[0]
        ski = r.text.split('var SKI="')[1].split('"')[0]

        return self.registerAccount(self.email, Helper.getCipher(self.password, random_num, key), ski, uaid, self.hf_id,
                                    tcxt, canary)

    def registerAccount(self, email, cipher, ski, uaid, hf_id, tcxt, canary, encAttemptToken="", dfpRequestId="",
                        captcha_key=""):

        first, sur = self.first, self.sur

        body = {
            "RequestTimeStamp": str(datetime.datetime.utcnow()).replace(" ", "T")[:-3] + "Z",
            "MemberName": email,
            "CheckAvailStateMap": [
                f"{email}:undefined"
            ],
            "EvictionWarningShown": [],
            "UpgradeFlowToken": {},
            "FirstName": first,
            "LastName": sur,
            "MemberNameChangeCount": 1,
            "MemberNameAvailableCount": 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue": cipher,
            "SKI": ski,
            "BirthDate": self.birthday,
            "Country": self.market.split('-')[-1],
            "AltEmail": None,
            "IsOptOutEmailDefault": False,
            "IsOptOutEmailShown": True,
            "IsOptOutEmail": True,
            "LW": True,
            "SiteId": "68692",
            "IsRDM": 0,
            "WReply": None,
            "ReturnUrl": None,
            "SignupReturnUrl": None,
            "uiflvr": 1001,
            "uaid": uaid,
            "SuggestedAccountType": "EASI",
            "RiskAssessmentDetails": "",
            "HFId": hf_id,
            "encAttemptToken": encAttemptToken,
            "dfpRequestId": dfpRequestId,
            "scid": 100118,
            "hpgid": 200650,
        }

        if captcha_key != "":
            body["HSol"] = captcha_key
            body["HPId"] = self.captchakey
            body["HType"] = "enforcement"

        r = self.session.post(
            "https://signup.live.com/API/CreateAccount?lic=1",
            json=body,
            headers={
                "canary": canary,
                "hpgid": f"2006{random.randint(10, 99)}",
                "origin": "https://signup.live.com",
                "scid": "100118",
                "tcxt": tcxt,
                "uaid": uaid,
                "uiflvr": "1001",
                "x-ms-apitransport": "xhr",
                "x-ms-apiversion": "2",
                "referrer": "https://signup.live.com/?lic=1"
            },
            timeout_seconds=TIMEOUT
        )

        if 'error' in r.json():
            if 'code' in r.json()["error"]:
                if r.json()["error"]["code"] == '1041':

                    # print(r.json())

                    t = json.loads(r.text)
                    # print(t)

                    data = json.loads(t['error']['data'])
                    try:
                        encAttemptToken = codecs.decode(
                            r.json()["error"]["data"].split('encAttemptToken":"')[1].split('"')[0], 'unicode-escape')
                    except:
                        return Creator(captcha_api_key=self.apikey).start()
                    dfpRequestId = codecs.decode(r.json()["error"]["data"].split('dfpRequestId":"')[1].split('"')[0],
                                                 'unicode-escape')
                    arkoseBlob = codecs.decode(r.json()["error"]["data"].split('arkoseBlob":"')[1].split('"')[0],
                                               'unicode-escape')
                    captcha_key = Captcha(self.apikey, self.captchakey, "https://signup.live.com/", arkoseBlob, self.proxy.split('@')[1]+':'+self.proxy.split('@')[0]).solve()
                    return self.registerAccount(self.email, cipher, ski, uaid, hf_id, tcxt, canary, encAttemptToken,
                                                dfpRequestId, captcha_key)
                else:
                    pass
        else:
            if config['enable_imap']:
                return self.enableIMAP()
            else:
                info("[CREATED]", "Account created.", {'email': self.email, 'password': self.password})
                Helper.save(self.email + ':' + self.password, './assets/output/accounts.txt')
                return self.email, self.password

    def enableIMAP(self):

        r = self.session.get(
            "https://outlook.live.com/owa/?nlp=1",
            allow_redirects=True,
            headers={
                'accept-encoding': 'identify'
            },
            timeout_seconds=TIMEOUT
        )

        r_ppft = r.text.split(''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        r_url = r.text.split(",urlPost:'")[1].split("'")[0]

        f = self.session.post(
            r_url,
            data={
                "i13": "0",
                "login": self.email,
                "loginfmt": self.email,
                "type": "11",
                "LoginOptions": "3",
                "Irt": "",
                "IrtPartition": "",
                "hisRegion": "",
                "hisScaleUnit": "",
                "passwd": self.password,
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": "",
                "ctx": "",
                "hpgrequestid": "",
                "PPFT": r_ppft,
                "PPSX": "Passpo",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "1",
                "isSignupPost": "0",
                "isRecoveryAttemptPost": "0",
                "i19": str(random.randint(300000, 400000))
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "identity"
            },
            timeout_seconds=TIMEOUT
        )

        f_url = f.text.split(",urlPost:'")[1].split("'")[0]
        f_ppft = f.text.split(',sFT:\'')[1].split('\'')[0]

        g = self.session.post(
            f_url,
            data={
                "LoginOptions": "3",
                "type": "28",
                "ctx": "",
                "hpgrequestid": "",
                "PPFT": f_ppft,
                "i19": str(random.randint(1000, 5000))
            },
            allow_redirects=True,
            headers={
                "Content_Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                          "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;"
                          "q=0.9",
                "Host": "login.live.com",
                "Origin": "https://login.live.com"
            },
            timeout_seconds=TIMEOUT
        )

        g_url = g.text.split('name="fmHF" id="fmHF" action="')[1].split('"')[0]

        g_data = {
            "pprid": g.text.split('type="hidden" name="pprid" id="pprid" value="')[1].split('"')[0],
            "NAP": g.text.split('type="hidden" name="NAP" id="NAP" value="')[1].split('"')[0],
            "ANON": g.text.split('type="hidden" name="ANON" id="ANON" value="')[1].split('"')[0],
            "t": g.text.split('<input type="hidden" name="t" id="t" value="')[1].split('"')[0],
            "wbids": "0",
            "wbid": "MSFT"
        }

        h = self.session.post(
            g_url,
            data=g_data,
            allow_redirects=True,
            headers={
                "Referer": "https://login.live.com/",
                "Origin": "https://login.live.com",
                "Host": "outlook.live.com",
                "Content_Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            },
            timeout_seconds=TIMEOUT
        )

        x_canary = ""
        for k in self.session.cookies.items():
            if k[0] == "X-OWA-CANARY":
                x_canary = k[1]
                break

        j = self.session.post(
            f'https://outlook.live.com/owa/0/lang.owa',
            data={
                "localeName": "en-US",
                "tzid": "Europe/London",
                "saveLanguageAndTimezone": "1"
            },
            headers={
                "Content_Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Host": "outlook.live.com",
                "Origin": "https://outlook.live.com",
                "x_owa_canary": x_canary
            },
            timeout_seconds=TIMEOUT
        )

        i = self.session.post(
            f'https://outlook.live.com/owa/0/service.svc',
            params={
                "action": 'SetConsumerMailbox',
                "app": 'Mail',
                "n": str(random.randint(50, 99))
            },
            headers={
                'Host': 'outlook.live.com',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://outlook.live.com/',
                'action': 'SetConsumerMailbox',
                'content-type': 'application/json; charset=utf-8',
                'x-owa-canary': x_canary,
                'x-owa-urlpostdata': '{"__type":"SetConsumerMailboxRequest:#Exchange","Header":{'
                                     '"__type":"JsonRequestHeaders:#Exchange","RequestServerVersion":"V2018_01_08",'
                                     '"TimeZoneContext":{"__type":"TimeZoneContext:#Exchange","TimeZoneDefinition":{'
                                     '"__type":"TimeZoneDefinitionType:#Exchange","Id":"Eastern Standard Time"}}},'
                                     '"Options":{"PopEnabled":true,"PopMessageDeleteEnabled":false}}',
                'x-req-source': 'Mail',
                'Origin': 'https://outlook.live.com',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Connection': 'keep-alive',
                'TE': 'trailers'
            },
            timeout_seconds=TIMEOUT
        )

        if r.status_code in [449, 200]:
            Helper.save(self.email + ':' + self.password, './assets/output/accounts.txt')
            info("[CREATED]", "Account created.", {'email': self.email, 'password': self.password})
            return self.email, self.password
        else:
            error("[FAIL]", "Account creation failed.", {'email': self.email})


def task(key):
    while True:
        try:
            Creator(key).start()
            break
        except Exception as e:
            if "timeout" in str(e).lower():
                debug("[PROXY]", "Proxy was too slow --> Retrying")
            else:
                error("[FAIL]", "Failed to create account.", {'error': str(traceback.format_exc())})
                return


def checker(combo: str):
    combo = combo.split(':')
    email = combo[0]
    password = combo[1]
    check = IMAP(email, password).login()
    if check is True:
        info("[VALID]", "Microsoft account is valid.", {'email': email})
    else:
        error("[INVALID]", "Microsoft account is invalid.", {'email': email})


def IMAPenabler(combo):
    combo = combo.split(':')
    email = combo[0]
    password = combo[1]
    s = Creator('a')
    s.email = email
    s.password = password
    s.enableIMAP()


def main():
    menu = """
    1 - Create Accounts
    2 - Check Accounts (IMAP, Outlook)
    3 - Enable IMAP for Accounts
    """

    print(menu)
    inp("[?]", "Your choice: ") # , end=''
    input_var = int(input())

    threads = config['threads']

    if input_var == 1:

        inp("[?]", "Enter amount of accounts: ")
        amount = int(input())

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for i in range(amount):
                executor.submit(task, config['captcha_key'])

    elif input_var == 2:
        with open("./assets/output/accounts.txt") as f:
            accounts = f.read().split('\n')
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for account in accounts:
                executor.submit(checker, account)
    elif input_var == 3:
        with open("./assets/output/accounts.txt") as f:
            accounts = f.read().split('\n')
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for account in accounts:
                executor.submit(IMAPenabler, account)


# main()
