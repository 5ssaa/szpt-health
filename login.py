import urllib.request,urllib.error,urllib.parse,urllib.response
import http.cookiejar
import math
import random
import requests
from Crypto.Cipher import AES
import base64
import json

username=''#用户名
password=''#密码
check_login='id":"'
login_success=check_login+username


headers={
    'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0'
}
json_headers={
    'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
    'Accept':'application/json, text/plain, */*'
}

get_session_url='https://ehall.szpt.edu.cn/amp-auth-adapter/login?service=https%3A%2F%2Fehall.szpt.edu.cn%3A443%2Fpublicappinternet%2Fsys%2Fszptpubxsjkxxbs%2F*default%2Findex.do'
get_info_url='https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/mrxxbs/getSaveReportInfo.do'
update_cookie_url='https://ehall.szpt.edu.cn/publicappinternet/sys/itpub/MobileCommon/getMenuInfo.do'
reporting_url='https://ehall.szpt.edu.cn/publicappinternet/sys/emapflow/tasks/startFlow.do'
save_info_url='https://ehall.szpt.edu.cn/publicappinternet/sys/szptpubxsjkxxbs/mrxxbs/saveReportInfo.do'


handler=http.cookiejar.CookieJar()
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(handler))


def get_login_url():
    global login_url
    token=requests.get(get_session_url,allow_redirects=False)
    login_url=token.headers['Location']

class AESCipher:

    def __init__(self, key):
        self.key = key[0:16].encode('utf-8')  # 只截取16位
        self.iv = self.random_string(16).encode()  # 16位字符，用来填充缺失内容，可固定值也可随机字符串，具体选择看需求。

    def __pad(self, text):
        """填充方式，加密内容必须为16字节的倍数，若不足则使用self.iv进行填充"""
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]

    def encrypt(self, text):
        """加密"""
        raw = self.random_string(64) + text
        raw = self.__pad(raw).encode()
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        """解密"""
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(enc).decode("utf-8"))

    @staticmethod
    def random_string(length):
        aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
        aes_chars_len = len(aes_chars)
        retStr = ''
        for i in range(0, length):
            retStr += aes_chars[math.floor(random.random() * aes_chars_len)]
        return retStr

def pwd_aes(salt):
    aes_key=AESCipher(salt)
    aes_pwd=aes_key.encrypt(password)
    return aes_pwd

def login():
    login_req=urllib.request.Request(login_url,headers=headers,method='GET')
    login_response=opener.open(login_req)
    get_html=login_response.read().decode('utf-8')
    pwd_salt=get_html[get_html.find('id="pwdDefaultEncryptSalt"')+34:get_html.find('</form>')-25]
    token=get_html[get_html.find('name="lt"')+17:get_html.find('name="dllt"')-50]
    execution=get_html[get_html.find('name="execution"')+24:get_html.find('name="_eventId"')-50]
    password_aes=pwd_aes(pwd_salt)
    POST_data={
        "username":username,
        "password":password_aes,
        "lt":token,
        "dllt":"userNamePasswordLogin",
        "execution":execution,
        "_eventId":"submit",
        "rmShown":"1"
    }
    #数据提交开始登录
    post_req=urllib.request.Request(login_url,method='POST',headers=headers,data=urllib.parse.urlencode(POST_data).encode('utf-8'))
    post_response=opener.open(post_req)
    login_html=post_response.read().decode('utf-8')
    #判断登录状态
    if(login_html.find(login_success)==-1):
        print("登陆失败")
        exit(0)
    else:
        print("登陆成功,继续执行")
        global APPID,APPNAME
        APPID=login_html[login_html.find("APPID='")+7:login_html.find("';",login_html.find("APPID='"))]
        APPNAME=login_html[login_html.find("APPNAME='")+9:login_html.find("';",login_html.find("APPNAME='"))]
        #return login_html

def POST_reporting():
    reporting_data={
        
    }
    report_req=urllib.request.Request(reporting_url,method='POST',headers=json_headers)

def get_info():
    global post_json_data
    #访问网页获取新cookie
    update_cookie_json_data={}
    update_cookie_json_data['APPID']=APPID
    update_cookie_json_data['APPNAME']=APPNAME
    update_cookie_data={
        'data':json.dumps(update_cookie_json_data)
    }
    update_cookie_req=urllib.request.Request(update_cookie_url,headers=json_headers,method='POST',data=urllib.parse.urlencode(update_cookie_data).encode('utf-8'))
    opener.open(update_cookie_req)
    #带着cookie去获取健康信息
    info_req=urllib.request.Request(get_info_url,headers=json_headers,method='GET')
    info_response=opener.open(info_req)
    info_json=json.loads(info_response.read().decode('utf-8'))
    #print(info_json)
    update_json={"WID":"","ZRCXFHJZXCLX":"","JRFXXCLX":"","ZSDZ":"","SXFS":"","SFZZSXDWSS":"","QYTZWTW":"","QYTWSTW":"","DTZSTW":"","FHTJGJ":"","QTXYSMDJWQK":"","SSSQ":"","XSQBDSJ":"","JSJJGCJTSJ":"","JSJTGCJTSJ":"","JSJJJTGCYY":"","STYCZK":"","STYXZK":"","HSJCBG":"","XGYMJZJJ":"","SFYYYXGYMJZ":""}
    info_json['datas'].update(update_json)
    #print(info_json['datas'])
    post_json_data={
        'formData':info_json['datas']
    }
    
def health_Send():
    send_req=urllib.request.Request(url=save_info_url,headers=json_headers,data=urllib.parse.urlencode(post_json_data).encode('utf-8'),method='POST')
    send_response=opener.open(send_req)
    send_response_json=json.loads(send_response.read().decode('utf-8'))
    if(send_response_json['code']=='0'):
        print('\n健康填报成功，继续下一步')
    else:
        print('出错')
        exit(0)


get_login_url()
login()
get_info()
health_Send()