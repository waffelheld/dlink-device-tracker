import xml.etree.ElementTree as ET
import hashlib
import hmac
import time
import logging
import xmltodict
from collections import defaultdict
import pprint
from homeassistant.helpers.aiohttp_client import (
  async_create_clientsession,
  async_get_clientsession,
)


_LOGGER = logging.getLogger(__name__)

class DLinkHNAP(object):
    """
    HNAP integration from @LinuxChristian https://github.com/LinuxChristian/pyW215
    Note:
    The library is greatly inspired by the javascript library by @bikerp (https://github.com/bikerp).
    Class layout is inspired by @rkabadi (https://github.com/rkabadi) for the Edimax Smart plug.
    """

    def __init__(self, ip, password, hass, user="Admin"):
        self.ip = ip
        self.url = "http://{}/HNAP1/".format(ip)
        self.user = user
        self.password = password
        self.authenticated = None
        self._error_report = False
        self.session = async_get_clientsession(hass)
        #self.model_name = self.SOAPAction(Action="GetDeviceSettings", responseElement="ModelName", params="")
        
    
    
    
    def requestBody(self, Action, params):
        """Returns the request payload for an action as XML>.

        :type Action: str
        :type params: str
        :param Action: Which action to perform
        :param params: Any parameters required for request
        :return XML payload for request
        """
        return '''<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <{} xmlns="http://purenetworks.com/HNAP1/">
            {}
        </{}>
        </soap:Body>
        </soap:Envelope>
               '''.format(Action, params, Action)
    
    @property
    async def get_authenticated(self):
        
        return self.authenticated
    
    async def SOAPAction(self, Action, responseElement, params="", recursive=False):
        """Generate the SOAP action call.

        :type Action: str
        :type responseElement: str
        :type params: str
        :type recursive: bool
        :param Action: The action to perform on the device
        :param responseElement: The XML element that is returned upon success
        :param params: Any additional parameters required for performing request (i.e. RadioID, moduleID, ect)
        :param recursive: True if first attempt failed and now attempting to re-authenticate prior
        :return: Text enclosed in responseElement brackets
        """
        auth = self.authenticated
        payload = self.requestBody(Action, params)

        # Timestamp in microseconds
        time_stamp = str(round(time.time() / 1e6))

        action_url = '"http://purenetworks.com/HNAP1/{}"'.format(Action)
        AUTHKey = hmac.new(auth[0].encode(), (time_stamp + action_url).encode(), digestmod=hashlib.md5).hexdigest().upper() + " " + time_stamp

        headers = {'Content-Type': '"text/xml; charset=utf-8"',
                   'SOAPAction': '"http://purenetworks.com/HNAP1/{}"'.format(Action),
                   'HNAP_AUTH': '{}'.format(AUTHKey),
                   'Cookie': 'uid={}'.format(auth[1])}
        _LOGGER.warning(headers)

        async with self.session.post(self.url, data=payload, headers=headers) as response:
          #response = urlopen(Request(self.url, payload.encode(), headers))
          xmlData = await response.text()
          #_LOGGER.warning(xmlData)
          return xmltodict.parse(xmlData)
        
    @property
    async def client_list(self):
        """Get the current power consumption in Watt."""
        res = 'N/A'
        res = await self.SOAPAction('GetClientInfo', 'ClientInfoLists')
        clientsRaw = res["soap:Envelope"]["soap:Body"]["GetClientInfoResponse"]["ClientInfoLists"]["ClientInfo"]
        
        result = {}
        for client in clientsRaw :
            if client["Type"] != "OFFLINE":
                result[client["MacAddress"]] = {
                    'name': client["DeviceName"],
                    'nickName': client["NickName"],
                    'is_connected': client["Type"] == "OFFLINE" and 0 or 1,
                    'mac': client["MacAddress"]
                }
        return result
            
        
    async def auth(self):
        """Authenticate using the SOAP interface.

        Authentication is a two-step process. First a initial payload
        is sent to the device requesting additional login information in the form
        of a publickey, a challenge string and a cookie.
        These values are then hashed by a MD5 algorithm producing a privatekey
        used for the header and a hashed password for the XML payload.

        If everything is accepted the XML returned will contain a LoginResult tag with the
        string 'success'.

        See https://github.com/bikerp/dsp-w215-hnap/wiki/Authentication-process for more information.
        """

        payload = self.initial_auth_payload()

        # Build initial header
        headers = {'Content-Type': '"text/xml; charset=utf-8"',
                   'SOAPAction': '"http://purenetworks.com/HNAP1/Login"'}

        # Request privatekey, cookie and challenge
        
        
        async with self.session.post(self.url, data=payload, headers=headers) as response:
          xmlData = await response.text()
          #response = urlopen(Request(self.url, payload, headers))
          #_LOGGER.warning(response.read().decode())
          #_LOGGER.warning(response)
          root = ET.fromstring(xmlData)

          # Find responses
          ChallengeResponse = root.find('.//{http://purenetworks.com/HNAP1/}Challenge')
          CookieResponse = root.find('.//{http://purenetworks.com/HNAP1/}Cookie')
          PublickeyResponse = root.find('.//{http://purenetworks.com/HNAP1/}PublicKey')

          if (
                  ChallengeResponse == None or CookieResponse == None or PublickeyResponse == None) and self._error_report is False:
              _LOGGER.warning("Failed to receive initial authentication from smartplug.")
              self._error_report = True
              return

          if self._error_report is True:
              return

          Challenge = ChallengeResponse.text
          Cookie = CookieResponse.text
          Publickey = PublickeyResponse.text

          # Generate hash responses
          PrivateKey = hmac.new((Publickey + self.password).encode(), (Challenge).encode(), digestmod=hashlib.md5).hexdigest().upper()
          login_pwd = hmac.new(PrivateKey.encode(), Challenge.encode(), digestmod=hashlib.md5).hexdigest().upper()

          response_payload = self.auth_payload(login_pwd)
          # Build response to initial request
          headers = {'Content-Type': '"text/xml; charset=utf-8"',
                     'SOAPAction': '"http://purenetworks.com/HNAP1/Login"',
                     'HNAP_AUTH': '"{}"'.format(PrivateKey),
                     'Cookie': 'uid={}'.format(Cookie)}
                     
          async with self.session.post(self.url, data=response_payload, headers=headers) as response:
            xmlData = await response.text()
            root = ET.fromstring(xmlData)
            #_LOGGER.warning(xmlData)

            # Find responses
            login_status = root.find('.//{http://purenetworks.com/HNAP1/}LoginResult').text.lower()

            if login_status != "success" and self._error_report is False:
                _LOGGER.error("Failed to authenticate with DLink Router {}".format(self.ip))
                self._error_report = True
                return

            self._error_report = False  # Reset error logging
            self.authenticated = (PrivateKey, Cookie)

    def initial_auth_payload(self):
        """Return the initial authentication payload."""

        return b'''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <Login xmlns="http://purenetworks.com/HNAP1/">
        <Action>request</Action>
        <Username>admin</Username>
        <LoginPassword/>
        <Captcha/>
        </Login>
        </soap:Body>
        </soap:Envelope>
        '''

    def auth_payload(self, login_pwd):
        """Generate a new payload containing generated hash information.

        :type login_pwd: str
        :param login_pwd: hashed password generated by the auth function.
        """

        payload = '''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <Login xmlns="http://purenetworks.com/HNAP1/">
        <Action>login</Action>
        <Username>{}</Username>
        <LoginPassword>{}</LoginPassword>
        <Captcha/>
        </Login>
        </soap:Body>
        </soap:Envelope>
        '''.format(self.user, login_pwd)

        return payload.encode()
