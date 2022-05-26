from selenium import webdriver
import time
import re
import requests
from openpyxl import Workbook
from openpyxl.styles import Alignment

def xf_vul(cve):
    try:
        url = f'https://api.xforce.ibmcloud.com/vulnerabilities/search/{cve}'
        headers = {"Authorization": "Basic OTExNjU1YWMtMGMwMi00YzBmLTg5ZTAtNzAwNjZiYzBkMDRlOmU0YmZmMzA3LWQxYTgtNDIxMC04MzMwLTViOGYxZjYwMDA1ZA==","Accept": "application/json"}
        response = requests.get(url=url, headers=headers, timeout=8)
        s = response.json()
        severity = float(s[0]["risk_level"])
        if severity <= 0:
            return f"{cve} ({severity} None)"
        elif severity > 0 and severity < 4:
            return f"{cve} ({severity} Low)"
        elif severity >= 4 and severity < 7:
            return f"{cve} ({severity} Medium)"
        elif severity >= 7 and severity < 9:
            return f"{cve} ({severity} High)"
        elif severity >= 9:
            return f"{cve} ({severity} Critical)"
    except:
        return f"{cve} (N/A)"


option = webdriver.ChromeOptions()
option.add_argument("-incognito")

browser = webdriver.Chrome(executable_path="C:\\chromedriver.exe",options=option)
browser.get("http://172.19.6.93/advisory/8417")

email = browser.find_element_by_xpath('//*[@id="loginform-username"]')
password = browser.find_element_by_xpath('//*[@id="loginform-password"]')
login = browser.find_element_by_xpath('//*[@id="LoginForm"]/div[6]/div[1]/button')

email.send_keys('')                                  # put password here for the login account
password.send_keys('')                               # put password here for the login account
login.click()


result_list = []
force_matches = []

with open("C:\\Users\\Areesh\\PycharmProjects\\pythonProject1\\cve_list.txt",'r') as f:
    for line in f:
        try:
            start_advisory = int(line.strip()) + 5045
            time.sleep(5)
            browser.get(f"http://172.19.6.93/advisory/{start_advisory}")
            players = browser.find_element_by_id("analysis_summary")
            matches = re.findall(r"CVE-\d{4}-\d{3,7}", players.text)
            print(matches)
            matches = list(dict.fromkeys(matches))
            print(matches)
            for line1 in matches:
                force_output = xf_vul(line1)
                time.sleep(2)
                print(force_output)
                force_matches.append(force_output)
            result_list.append(force_matches)
            matches = []
            force_matches = []
            print(result_list)
        except:
            print("failed")


test = result_list

fu = 'A'
workbook = Workbook()
worksheet = workbook.worksheets[0]
worksheet.title = "Sheet1"
for count,values in enumerate(test,start=1):
    joined_string = "\n".join(values)
    worksheet[fu+str(count)] = joined_string
    worksheet.alignment = Alignment(wrapText=True)
workbook.save('C:\\Users\\Areesh\\PycharmProjects\\pythonProject1\\Cve_text1.xlsx')











