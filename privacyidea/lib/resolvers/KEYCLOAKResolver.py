# -*- coding: utf-8 -*-
#
#  2022 Michael Otto
#  http://www.privacyidea.org
#
#  product:  PrivacyIDEA
#  module:   keycloakresolver
#  tool:     KEYCLOAKResolver
#  edition:  Comunity Edition
#
#  License:  AGPLv3
#  contact:  http://www.linotp.org
#            http://www.lsexperts.de
#            linotp@lsexperts.de
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import json
import logging
from typing import Any
from dataclasses import dataclass
from keycloak_wrapper import access_token, get_user
from keycloak_wrapper import realm_users

from .UserIdResolver import UserIdResolver

ENCODING = "utf-8"

__name__ = "KEYCLOAK_RESOLVER"

log = logging.getLogger(__name__)


@dataclass
class KeycloakToken:
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    session_state: str
    scope: str

    @staticmethod
    def from_dict(obj: Any) -> 'Root':
        _access_token = str(obj.get("access_token"))
        _expires_in = int(obj.get("expires_in"))
        _refresh_expires_in = int(obj.get("refresh_expires_in"))
        _refresh_token = str(obj.get("refresh_token"))
        _token_type = str(obj.get("token_type"))
        _session_state = str(obj.get("session_state"))
        _scope = str(obj.get("scope"))
        return KeycloakToken(_access_token, _expires_in, _refresh_expires_in, _refresh_token, _token_type,
                             _session_state, _scope)


@dataclass
class KeycloakUser:
    id: str
    username: str
    firstName: str
    username: str
    lastName: str
    email: str

    @staticmethod
    def from_dict(obj: Any) -> 'KeycloakUser':
        _id = str(obj.get("id"))
        _username = str(obj.get("username"))
        _firstName = str(obj.get("firstName"))
        _lastName = str(obj.get("lastName"))
        _email = str(obj.get("email"))
        return KeycloakUser(_id, _username, _firstName, _lastName, _email)

@dataclass
class PiUser:
    def __init__(self, username, userid, description, phone, mobile, email, givenname, surname, gender):
        self.username = username
        self.userid = userid
        self.description = description
        self.phone = phone
        self.mobile = mobile
        self.email = email
        self.givenname = givenname
        self.surname = surname
        self.gender = gender



class KEYCLOAKResolver(UserIdResolver):

    fields = {
        "keycloak_url": 1,
        "realm": 1,
        "client": 1,
        "secret": 1,
        "user": 1,
        "password": 0
    }

    def __init__(self):
        super(KEYCLOAKResolver, self).__init__()
        self.config = {}

    @staticmethod
    def getResolverClassType():
        """
        provide the resolver type for registration
        """
        return 'keycloakresolver'

    @staticmethod
    def getResolverType():
        """
        getResolverType - return the type of the resolver

        :return: returns the string 'keycloakresolver'
        :rtype:  string
        """
        return KEYCLOAKResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.KEYCLOAKResolver.KEYCLOAKResolver"
        descriptor['config'] = {
            'keycloak_url': 'string',
            'realm': 'string',
            'client': 'string',
            'secret': 'string',
            'user': 'string',
            'password': 'string',
        }
        return {typ: descriptor}

    @staticmethod
    def getResolverDescriptor():
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        return KEYCLOAKResolver.getResolverClassDescriptor()

    def getUserId(self, loginName):
        """
        This method only echo's the loginName parameter
        """
        return loginName

    def getUsername(self, userid):
        """
        This method only echo's the userid parameter
        """
        return userid

    def getUserInfo(self, userid):
        """
        This function returns all user information for a given user object
        identified by UserID.
        :param userid: ID of the user in the resolver
        :type userid: int or string
        :return:  dictionary, if no object is found, the dictionary is empty
        :rtype: dict
        """
        return getUser(self, userid)

    def getUserList(self, searchDict=None):
        """
        Since it is an HTTP resolver,
        users are not stored in the database
        """

        param = self.config
        keycloak_url = param.get('keycloak_url')
        realm = param.get('realm')
        client = param.get('client')
        secret = param.get('secret')
        query_user = param.get('user')
        query_password = param.get('password')

        token = access_token(keycloak_url, realm, client, secret, query_user, query_password)
        keycloak_token = KeycloakToken.from_dict(token)
        users = realm_users(keycloak_url, realm, keycloak_token.access_token)

        data = json.dumps(users)
        user = json.loads(data)

        user_list = []

        for u in user:

            mobile = ""
            phone = ""
            gender = ""
            description = ""
            firstname = ""
            lastname = ""
            email = ""
            if "firstName" in u.keys():
                firstname = u['firstName']
            if "lastName" in u.keys():
                lastname = u['lastName']
            if "email" in u.keys():
                email = u['email']
            if "attributes" in u.keys():
                user_attributes = json.loads(json.dumps(u['attributes']))
                if "mobile" in user_attributes.keys():
                    mobile = user_attributes['mobile'][0]
                if "phone" in user_attributes.keys():
                    phone = user_attributes['phone'][0]
                if "gender" in user_attributes.keys():
                    gender = user_attributes['gender'][0]
                if "description" in user_attributes.keys():
                    description = user_attributes['description'][0]

            pi_user = PiUser(u['username'], u['id'], description, phone, mobile, email, firstname, lastname, gender)
            user_list.append(pi_user)

        userdata = json.dumps(user_list, default=lambda o: o.__dict__, sort_keys=False, indent=4)

        return json.loads(userdata)

    def getResolverId(self):
        """
        get resolver specific information
        :return: the resolver identifier string - empty string if not exist
        """
        return self.config['keycloak_url'] + "realms/" + self.config['realm'] if 'keycloak_url' in self.config else ''

    def loadConfig(self, config):
        """
        Load the configuration from the dict into the Resolver object.
        If attributes are missing, need to set default values.
        If required attributes are missing, this should raise an
        Exception.

        :param config: The configuration values of the resolver
        :type config: dict
        """
        self.config = config
        return self


    @classmethod
    def testconnection(cls, param):
        """
        This function lets you test if the parameters can be used to create a
        working resolver. Also, you can use it anytime you see if the API is
        running as expected.
        The implementation should try to make a request to the HTTP API and verify
        if user can be retrieved.
        In case of success it should return the raw http response.

        :param param: The parameters that should be saved as the resolver
        :type param: dict
        :return: returns True in case of success and a raw response
        :rtype: tuple
        @param param:
        @return:
        """
        desc = ""
        success = False
        try:
            resolver = KEYCLOAKResolver()
            resolver.loadConfig(param)
            response = resolver.getUserList()
            desc = "Success found: {0!s} users in realm".format(len(response))
            success = True
        except Exception as e:
            success = False
            desc = "failed: {0!s}".format(e)
        return success, desc

def getUser(self, userid):
    param = self.config
    keycloak_url = param.get('keycloak_url')
    realm = param.get('realm')
    client = param.get('client')
    secret = param.get('secret')
    query_user = param.get('user')
    query_password = param.get('password')

    token = access_token(keycloak_url, realm, client, secret, query_user, query_password)
    keycloak_token = KeycloakToken.from_dict(token)

    keycloak_user = get_user(keycloak_url, realm, keycloak_token.access_token, userid)
    data = json.dumps(keycloak_user)
    pi_single_user = json.loads(data)

    mobile = ""
    phone = ""
    gender = ""
    description = ""
    firstname = ""
    lastname = ""
    email = ""
    if "firstName" in pi_single_user.keys():
        firstname = pi_single_user['firstName']
    if "lastName" in pi_single_user.keys():
        lastname = pi_single_user['lastname']
    if "email" in pi_single_user.keys():
        email = pi_single_user['email']

    if "attributes" in pi_single_user.keys():
        user_attributes = json.loads(json.dumps(pi_single_user['attributes']))
        if "mobile" in user_attributes.keys():
            mobile = user_attributes['mobile'][0]
        if "phone" in user_attributes.keys():
            phone = user_attributes['phone'][0]
        if "gender" in user_attributes.keys():
            gender = user_attributes['gender'][0]
        if "description" in user_attributes.keys():
            description = user_attributes['description'][0]

    pi_user = PiUser(pi_single_user['username'], pi_single_user['id'], description, phone, mobile,
                     email, firstname, lastname, gender)

    userdata = json.dumps(pi_user, default=lambda o: o.__dict__, sort_keys=False, indent=4)
    return json.loads(userdata)