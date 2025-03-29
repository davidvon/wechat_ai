import requests

# 获取 Access Token
def get_access_token(corpid, corpsecret):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"
    response = requests.get(url)
    return response.json().get("access_token")

def get_media(access_token, media_id):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token={access_token}&media_id={media_id}"
    response = requests.get(url)
    return response.text

def download_voice(access_token, media_id):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token={access_token}&media_id={media_id}"
    response = requests.get(url)
    file_name = "voice_%s.amr" % media_id
    with open(file_name, "wb") as f:
        f.write(response.content)
    return file_name


# 上传语音文件
def upload_voice(access_token, file_path):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=voice"
    files = {'media': open(file_path, 'rb')}
    response = requests.post(url, files=files)
    return response.json().get("media_id")

# 转换语音为文字
def voice_to_text(access_token, media_id):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/voice/trans?access_token={access_token}"
    data = {
        "media_id": media_id,
        "lang": "zh_CN"
    }
    response = requests.post(url, json=data)
    print(response.json())


if __name__== '__main__':
    # 使用示例
    corpid = "wwe9c50b7b88f8a29b1"
    corpsecret = "mROdmdPtz2vzJ5zWIyQJ8r6dgOt7q7u69v2Y1JUP8lw1"
    access_token = get_access_token(corpid, corpsecret)
    media_id =  '118NddZ2fqtCW4_ReT5_YFPfXVoF9j360s27WdAiONRmdbbZ0BHzV6DC4QjQXj5Oq'  #upload_voice(access_token, "your_voice_file.amr")
    download_voice(access_token, media_id)
