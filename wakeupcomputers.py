##############################################################################
# -*- coding: utf-8 -*-
# Project:      WakeUp Computers
# Module:       wakeupcomputers.py
# Purpose:      Wake up computers from LDAP
# Language:     Python 3
# Date:         13-Sep-2024
# Ver:          13-Sep-2024
# Author:       Manuel Mora Gordillo
# Copyright:    2024 - Manuel Mora Gordillo <manuel.mora.gordillo @no-spam@ gmail.com>
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
##############################################################################

from ldap3 import Server, Connection, ALL, SUBTREE
from wakeonlan import send_magic_packet
import os

LDAP_SERVER = "servidor"
LDAP_BASE = "dc=instituto,dc=extremadura,dc=es"
COMPUTERS = os.getenv("COMPUTERS", "*-pro *-aio *-sia")

class LdapConnection(object):
    def makeFilter(self):
        items = ["(cn=" + computer.strip() + ")" for computer in COMPUTERS.split()]
        return "(|" + "".join(items) + ")"

    def connectauth(self):
        server = Server(LDAP_SERVER, get_info=ALL)
        self.connectauth = Connection(server, "", "")
        self.connectauth.bind()

    def search(self, baseDN, filter, retrieveAttributes):
        self.connectauth.search("%s,%s" % (baseDN, LDAP_BASE), filter, SUBTREE, attributes=retrieveAttributes)
        entries = list()
        for entry in self.connectauth.entries:
            entries.append(entry)
        return entries

    def getMacs(self):
        macs = list()
        search = self.search("cn=DHCP Config", self.makeFilter(), ["dhcpHWAddress", "cn"])
        for s in search:
            if len(s['dhcpHWAddress']) > 0:
                macs.append(
                    dict(
                        host=s['cn'],
                        mac=s['dhcpHWAddress'][0].replace("ethernet ", "")
                    )
                )
        return macs

def main():
    l = LdapConnection()
    l.connectauth()
    macs  = l.getMacs()
    for item in macs:
        try:
            send_magic_packet(item.get("mac"))
            print(f"WoL package sent to {item.get('host')} - {item.get('mac')}.")
        except Exception as e:
            print(f"WoL package could not be sent: {e}")

if __name__ == '__main__':
    main()
