import pickle
import random
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import os.path
import time
import base64
import re
import os
from urllib.parse import quote
import secrets
import hashlib
import base64
from datetime import datetime
import logging
import httpx
import asyncio

class API:        
    cookies = None

    def __init__(self, user_id, email, api_key):
        self.user_id = user_id
        self.email = email
        self.api_key = api_key

    # If modifying these scopes, delete the file token.json.
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    async def async_post(self, url, headers=None, json=None, data=None):
        async with httpx.AsyncClient() as client:
            response = await client.post(url, cookies=self.cookies, headers=headers, json=json, data=data, timeout=30)
            self.cookies = response.cookies
            return response

    async def async_get(self, url, headers=None):
        async with httpx.AsyncClient() as client:
            response = await client.get(url, cookies=self.cookies, headers=headers, timeout=30)
            self.cookies = response.cookies
            return response
        
    def generate_code_verifier(self):
        # Generate a random string of 43 bytes
        return secrets.token_urlsafe(32)

    def generate_code_challenge(self, code_verifier):
        # Transform the code verifier to code challenge using SHA-256
        code_challenge = hashlib.sha256(code_verifier.encode()).digest()
        # Encode the bytes to base64 and remove any trailing '='
        code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=')
        return code_challenge.decode()

    async def get_session_token(self,): 
        # login to iec
        username  = self.user_id + '@iec.co.il'
  
        headers = {"accept": "application/json", "content-type":"application/json"}
        response = await self.async_post("https://iec-ext.okta.com/api/v1/authn", 
                                headers=headers, 
                                json={"username": username})
    
        # if initial auth call is successful
        if (response.status_code == 200):
            response_data = response.json()
            
            state_token = response_data["stateToken"]

            # run the "verify" command (using email)
            response = await self.async_post(response_data["_embedded"]["factors"][0]["_links"]["verify"]["href"],
                                        headers=headers,
                                        json={"stateToken": state_token})
            
            # if verification succeeded
            if (response.status_code == 200):
                response_data = response.json()      
                state_token = response_data["stateToken"]
                verify_url = response_data["_links"]["next"]["href"]
                # Wait for an incoming email matching the search query with a timeout of 300 seconds (5 minutes)
                #sender_email = 'Hashmal103@iec.co.il'
                timeout_duration = 60
                start_time = time.time()
                while True:
                    otp_code = await self.check_email()
                    if otp_code != None:
                        break
                    if time.time() - start_time > timeout_duration:
                        print(f'Timeout! No matching email found in the last {timeout_duration} seconds.')
                        break
                    await asyncio.sleep(1)

                if otp_code != None:
                    response = await self.async_post(verify_url, 
                                            headers=headers,
                                            json={"passCode":otp_code[0], "stateToken": state_token})
                    #print(response.status_code)
                    #print(response.text)
                    if (response.status_code == 200):
                        response_data = response.json()
                        session_token = response_data["sessionToken"]
                        return session_token
                    else:
                        print(response.text)
                else:
                    print("cannot find data code:")
                    print(response.text)
            else:                
                print(response.text)                
        return None               
    
    async def get_id_token(self, session_token):
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)

        print("Code Verifier:", code_verifier)
        print("Code Challenge:", code_challenge)

        url = "https://iec-ext.okta.com/oauth2/default/v1/authorize?client_id=0oantydrc56Nyf1qV2p7&code_challenge=" + code_challenge + "&code_challenge_method=S256&nonce=V9fzooaxsQXflkX1qn5khN3WsjX5kVGsXv4fRESPsgAZySnSsrgNzYM1hH49r65K&prompt=none&redirect_uri=https%3A%2F%2Fwww.iec.co.il%2F&response_mode=okta_post_message&response_type=code&sessionToken="+session_token+"&state=rNwbDUNURhUrgoChIgcZlxd96EcTFpgsaGSvnOZH07DOFVlpnj9xpIuPD3nbAHkB&scope=openid%20profile%20email"
        response = await self.async_get(url)
        
        if (response.status_code == 200):
            # find the data code in the response text
            match = re.search(r"data\.code\s*=\s*'([^']*)'", response.text)
            if match:
                data_code = eval("\"" + match.group(1) + "\"")
                response = await self.async_post("https://iec-ext.okta.com/oauth2/default/v1/token", 
                                headers={"content-type":"application/x-www-form-urlencoded", "accept": "application/json"},
                                data= {
                                    'client_id' : '0oantydrc56Nyf1qV2p7',
                                    'redirect_uri': 'https://www.iec.co.il/',
                                    'grant_type': 'authorization_code',
                                    'code_verifier': code_verifier,
                                    'code': data_code
                                })
                if (response.status_code == 200):
                    print("Identification completed successfully")
                    print(response.text)
                    response_data = response.json()
                    jwt = response_data["id_token"]
                    return jwt
                else:
                    print(response.text)
            else:
                print("no code found in response")
        else:
            print(response.text)

    async def check_email(self):
        email = quote(self.email)
        # authorize mailsac with api_key
        url = "https://mailsac.com/api/addresses/"+self.email+"/messages?until=2999-12-31T23%3A59%3A59.999Z&limit=1&_mailsacKey=" + self.api_key
        response = await self.async_get(url)
        if (response.status_code == 200):
            result = response.json()
            if (len(result)> 0):
                message_id = result[0]["_id"]
                received = datetime.strptime(result[0]["received"], '%Y-%m-%dT%H:%M:%S.%fZ')
                if datetime.utcnow() - received <= timedelta(minutes=1):                                
                    url = "https://mailsac.com/api/text/"+self.email+"/"+message_id+"?_mailsacKey="+self.api_key
                    response = await self.async_get(url)
                    if (response.status_code == 200):
                        message = response.text
                        
                        # Use regular expression to find any 6-digit number
                        six_digit_numbers = re.findall(r'\b\d{6}\b', message)
                        
                        if six_digit_numbers:
                            print(f'Found 6-digit number(s) in the email: {six_digit_numbers[0]}')
                            return six_digit_numbers
                        else:
                            print('No 6-digit numbers found in the last email')
                            return None
                    else:
                        print("couldn't get email body")
                        return None
                else:
                    print("No emails received in the last minute")
            else:
                print('No new emails found')
                return None 


    async def get_accounts(self, id_token):
        headers = {"accept": "application/json", "content-type":"application/json", "x-iec-idt": "1", "authorization": "Bearer " + id_token}   
        response = await self.async_get("https://iecapi.iec.co.il//api/outages/accounts?CustomLoader=true", headers=headers)
        if (response.status_code == 200):
            return response.json()["data"]
        else:
            print(f'get_account request failed with status code {response.status_code}.')
            print('Response:', response.text)
            return []

    async def get_contracts(self, id_token, account_id):
        headers = {"accept": "application/json", "content-type":"application/json", "x-iec-idt": "1", "authorization": "Bearer " + id_token}   
        response = await self.async_get("https://iecapi.iec.co.il//api/customer/contract/0102370814", headers=headers)
        if (response.status_code == 200):
            return response.json()["data"]
        else:
            print(f'get_contracts request failed with status code {response.status_code}.')
            print('Response:', response.text)
            return []

    async def get_device_info(self, id_token, contract_id):
        headers = {"accept": "application/json", "content-type":"application/json", "x-iec-idt": "1", "authorization": "Bearer " + id_token}   
        response = await self.async_get("https://iecapi.iec.co.il//api/Device/000341681679", headers=headers)
        if (response.status_code == 200):
            return response.json()[0]
        else:
            print(f'get_device_info request failed with status code {response.status_code}.')
            print('Response:', response.text)
            return {}
    
    async def get_remote_stats(self, id_token, meter_serial_number, meter_code, from_date):
        # read the stats from there
        headers = {"accept": "application/json", "content-type":"application/json", "x-iec-idt": "1", "authorization": "Bearer " + id_token}   
        json = {"meterSerialNumber":meter_serial_number,"meterCode":meter_code,"lastInvoiceDate":from_date,"fromDate":from_date,"resolution":1}
        response = await self.async_post("https://iecapi.iec.co.il//api/Consumption/RemoteReadingRange", headers=headers, json=json)
        if (response.status_code == 200):
            print(response.json())
            return response.json()
        else:
            print(f'get_remote_stats request failed with status code {response.status_code}.')
            print('Response:', response.text)
            return {"data":[]}

    async def get_token(self):  
        # retrieve a session token by identifing with OTP code
        print("obtaining session token...")
        session_token = await self.get_session_token()          

        # login to iec
        id_token = await self.get_id_token(session_token)

        return id_token
    
    async def fetch(self, id_token) -> list[tuple[datetime, float]]:
        async def fetch_stats(start: datetime):                                 
            accounts = await self.get_accounts(id_token)
            print(accounts)
            if (len(accounts) > 0):
                account_id = accounts[0]['accountNumber']
                contracts = await self.get_contracts(id_token, account_id)
                print(contracts)
                if (len(contracts) > 0):
                    contract_id = contracts["contracts"][0]["contractId"]
                    device = await self.get_device_info(id_token, contract_id)
                    print(device)
                    for i in range(2,-1,-1):
                        date_str = (datetime.now()- timedelta(days=i)).strftime('%Y-%m-%d')
                        stats = await self.get_remote_stats(id_token, device["deviceNumber"], device["deviceCode"], date_str)
                        print("fetched "+str(len(stats["data"]))+" values for "+ date_str)
                        for stat in stats["data"]:
                            v = (datetime.strptime(stat["date"], '%Y-%m-%dT%H:%M:%S.%f'), stat["value"])
                            yield v                             
            
        print("fetching historical data...")        
        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)    
        result = []
        async for stat in fetch_stats(start):
            result.append(stat)

        print(result)
        return list(result) 