from Crypto.Cipher import AES
from flask import Flask, request, jsonify
import hashlib
import time
import base64
import xml.etree.ElementTree as ET
import random
import string

app = Flask(__name__)

# 企业微信配置
CORP_ID = "wwe9c50b7b88f8a29b1"  # 企业ID
TOKEN = "oiSO6dMwD8IN1"  # 接收消息的Token
EncodingAESKey = "xhu3qH47om7eXeuJFbBGFTirlc6l3qs8FSEZ4FDHF4e1"  # 43位AESKey


class WXBizMsgCrypt:
    """消息加解密工具类 (官方算法实现)"""

    def __init__(self, sToken, sEncodingAESKey, sCorpId):
        self.key = base64.b64decode(sEncodingAESKey + "=")
        self.token = sToken
        self.corp_id = sCorpId
        self.iv = self.key[:16]
        self.block_size = AES.block_size

    def decrypt(self, encrypted_msg):
        # AES解密
        cipher = AES.new(self.key, AES.MODE_CBC, self.key[:16])
        decrypted = cipher.decrypt(base64.b64decode(encrypted_msg))
        # 移除补位字符
        pad = ord(decrypted[-1:])
        content = decrypted[:-pad]
        # 解析XML
        xml_len = int.from_bytes(content[16:20], byteorder='big')  # 大端序
        xml_content = content[20:20 + xml_len].decode('utf-8')
        return xml_content

    def encrypt(self, reply_msg):
        """加密回复消息"""
        # 生成随机字符串
        nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        # 构造待加密消息
        msg = reply_msg.encode('utf-8')
        msg_len = len(msg)
        # 拼接消息
        byte_buf = bytearray()
        byte_buf.extend(nonce.encode('utf-8'))
        byte_buf.extend(msg_len.to_bytes(4, byteorder='big'))
        byte_buf.extend(msg)
        byte_buf.extend(self.corp_id.encode('utf-8'))
        # PKCS#7 填充
        pad_len = self.block_size - (len(byte_buf) % self.block_size)
        byte_buf.extend(bytes([pad_len] * pad_len))
        # AES-CBC 加密
        iv = self.key[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(byte_buf)
        # Base64 编码
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def _generate_random_str():
        """生成16位随机字符串"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

    @staticmethod
    def _pkcs7_pad(data):
        """PKCS#7填充"""
        block_size = AES.block_size
        padding = block_size - len(data) % block_size
        return data + bytes([padding] * padding)

    def generate_signature(self, timestamp, nonce, encrypted_msg):
        """生成消息签名"""
        # 参数按字典序排序
        params = sorted([self.token, timestamp, nonce, encrypted_msg])
        # 拼接字符串
        raw_str = ''.join(params)
        # SHA1加密
        sha1 = hashlib.sha1()
        sha1.update(raw_str.encode('utf-8'))
        return sha1.hexdigest()

    def verify_url(self, msg_signature, timestamp, nonce, echostr):
        # 验证URL有效性
        signature = self.get_signature(timestamp, nonce, echostr)
        if signature != msg_signature:
            return None
        decrypted = self.decrypt(echostr)
        return decrypted

    def get_signature(self, timestamp, nonce, data=None):
        # 计算签名
        s = sorted([self.token, timestamp, nonce, data or ""])
        sha1 = hashlib.sha1()
        sha1.update("".join(s).encode('utf-8'))
        return sha1.hexdigest()


# 初始化加解密工具
wxcpt = WXBizMsgCrypt(TOKEN, EncodingAESKey, CORP_ID)


@app.route('/wx', methods=['GET', 'POST'])
def handle_wx():
    # 验证服务器配置 (GET请求)
    if request.method == 'GET':
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')

        # 验证URL
        decrypted = wxcpt.verify_url(msg_signature, timestamp, nonce, echostr)
        if decrypted:
            return decrypted
        return "Verification failed", 403

    # 处理消息 (POST请求)
    elif request.method == 'POST':
        # 解析请求参数
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')

        # 获取加密的XML消息
        encrypted_xml = request.data.decode('utf-8')
        root = ET.fromstring(encrypted_xml)
        encrypted_msg = root.find('Encrypt').text

        # 验证签名
        signature = wxcpt.get_signature(timestamp, nonce, encrypted_msg)
        if signature != msg_signature:
            return "Invalid signature", 403

        # 解密消息
        decrypted_xml = wxcpt.decrypt(encrypted_msg)
        msg_root = ET.fromstring(decrypted_xml)

        # 提取消息内容
        msg_type = msg_root.find('MsgType').text
        from_user = msg_root.find('FromUserName').text
        content = msg_root.find('Content').text if msg_type == 'text' else ''

        print(f"Received {msg_type} message from {from_user}: {content}")

        # 构造回复消息 (示例: 回复相同内容)
        reply_xml = f"""
        <xml>
            <ToUserName><![CDATA[{from_user}]]></ToUserName>
            <FromUserName><![CDATA[{CORP_ID}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[Received: ZTE金易本地AI一体机对消息的回复: {content}]]></Content>
       </xml>
        """
        # 加密回复
        encrypted_reply = wxcpt.encrypt(reply_xml)
        signature = wxcpt.generate_signature(timestamp, nonce, encrypted_reply)
        final_xml = f"""
                <xml>
                    <Encrypt><![CDATA[{encrypted_reply}]]></Encrypt>
                    <MsgSignature><![CDATA[{signature}]]></MsgSignature>
                    <TimeStamp>{timestamp}</TimeStamp>
                    <Nonce><![CDATA[{nonce}]]></Nonce>
                </xml>
                """
        print("response:", final_xml)
        return final_xml, 200, {'Content-Type': 'application/xml'}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

