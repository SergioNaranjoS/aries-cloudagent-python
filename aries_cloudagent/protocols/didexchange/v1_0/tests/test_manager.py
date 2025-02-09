import json

from unittest import IsolatedAsyncioTestCase
from aries_cloudagent.tests import mock
from pydid import DIDDocument

from .. import manager as test_module
from .....cache.base import BaseCache
from .....cache.in_memory import InMemoryCache
from .....connections.models.conn_record import ConnRecord
from .....connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from .....core.in_memory import InMemoryProfile
from .....core.oob_processor import OobMessageProcessor
from .....did.did_key import DIDKey
from .....ledger.base import BaseLedger
from .....messaging.decorators.attach_decorator import AttachDecorator
from .....messaging.responder import BaseResponder, MockResponder
from .....multitenant.base import BaseMultitenantManager
from .....multitenant.manager import MultitenantManager
from .....resolver.did_resolver import DIDResolver
from .....resolver.tests import DOC
from .....storage.error import StorageNotFoundError
from .....transport.inbound.receipt import MessageReceipt
from .....wallet.did_info import DIDInfo
from .....wallet.did_method import DIDMethods, SOV
from .....wallet.error import WalletError
from .....wallet.in_memory import InMemoryWallet
from .....wallet.key_type import ED25519
from ....coordinate_mediation.v1_0.manager import MediationManager
from ....coordinate_mediation.v1_0.models.mediation_record import MediationRecord
from ....coordinate_mediation.v1_0.route_manager import RouteManager
from ....didcomm_prefix import DIDCommPrefix
from ....discovery.v2_0.manager import V20DiscoveryMgr
from ....out_of_band.v1_0.manager import OutOfBandManager
from ....out_of_band.v1_0.messages.invitation import HSProto, InvitationMessage
from ....out_of_band.v1_0.messages.service import Service as OOBService
from ..manager import DIDXManager, DIDXManagerError
from ..messages.problem_report import DIDXProblemReport, ProblemReportReason


class TestConfig:
    test_seed = "testseed000000000000000000000001"
    test_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_endpoint = "http://localhost"

    test_target_did = "GbuDUYXaUZRfHD2jeDuQuP"
    test_target_verkey = "9WCgWKUaAJj3VWxxtzvvMQN3AoFxoBtBDo9ntwJnVVCC"

    def make_did_doc(self, did, verkey):
        doc = DIDDoc(did=did)
        controller = did
        ident = "1"
        pk_value = verkey
        pk = PublicKey(
            did, ident, pk_value, PublicKeyType.ED25519_SIG_2018, controller, False
        )
        doc.set(pk)
        recip_keys = [pk]
        router_keys = []
        service = Service(
            did, "indy", "IndyAgent", recip_keys, router_keys, TestConfig.test_endpoint
        )
        doc.set(service)
        return doc


class TestDidExchangeManager(IsolatedAsyncioTestCase, TestConfig):
    async def asyncSetUp(self):
        self.responder = MockResponder()

        self.oob_mock = mock.MagicMock(
            clean_finished_oob_record=mock.CoroutineMock(return_value=None)
        )

        self.route_manager = mock.MagicMock(RouteManager)
        self.route_manager.routing_info = mock.CoroutineMock(
            return_value=([], self.test_endpoint)
        )
        self.route_manager.mediation_record_if_id = mock.CoroutineMock(
            return_value=None
        )
        self.route_manager.mediation_record_for_connection = mock.CoroutineMock(
            return_value=None
        )

        self.profile = InMemoryProfile.test_profile(
            {
                "default_endpoint": "http://aries.ca/endpoint",
                "default_label": "This guy",
                "additional_endpoints": ["http://aries.ca/another-endpoint"],
                "debug.auto_accept_invites": True,
                "debug.auto_accept_requests": True,
                "multitenant.enabled": True,
                "wallet.id": True,
            },
            bind={
                BaseResponder: self.responder,
                BaseCache: InMemoryCache(),
                OobMessageProcessor: self.oob_mock,
                RouteManager: self.route_manager,
                DIDMethods: DIDMethods(),
            },
        )
        self.context = self.profile.context
        async with self.profile.session() as session:
            self.did_info = await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
            )

        self.ledger = mock.create_autospec(BaseLedger)
        self.ledger.__aenter__ = mock.CoroutineMock(return_value=self.ledger)
        self.ledger.get_endpoint_for_did = mock.CoroutineMock(
            return_value=TestConfig.test_endpoint
        )
        self.context.injector.bind_instance(BaseLedger, self.ledger)
        self.resolver = mock.MagicMock()
        did_doc = DIDDocument.deserialize(DOC)
        self.resolver.resolve = mock.CoroutineMock(return_value=did_doc)
        assert did_doc.verification_method
        self.resolver.dereference_verification_method = mock.CoroutineMock(
            return_value=did_doc.verification_method[0]
        )
        self.context.injector.bind_instance(DIDResolver, self.resolver)

        self.multitenant_mgr = mock.MagicMock(MultitenantManager, autospec=True)
        self.context.injector.bind_instance(
            BaseMultitenantManager, self.multitenant_mgr
        )
        self.multitenant_mgr.get_default_mediator = mock.CoroutineMock(
            return_value=None
        )

        self.manager = DIDXManager(self.profile)
        assert self.manager.profile
        self.oob_manager = OutOfBandManager(self.profile)
        self.test_mediator_routing_keys = [
            DIDKey.from_public_key_b58(
                "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRR", ED25519
            ).did
        ]
        self.test_mediator_conn_id = "mediator-conn-id"
        self.test_mediator_endpoint = "http://mediator.example.com"

    async def test_verify_diddoc(self):
        async with self.profile.session() as session:
            did_doc = self.make_did_doc(
                TestConfig.test_target_did,
                TestConfig.test_target_verkey,
            )
            did_doc_attach = AttachDecorator.data_base64(did_doc.serialize())
            with self.assertRaises(DIDXManagerError):
                await self.manager.verify_diddoc(session.wallet, did_doc_attach)

            await did_doc_attach.data.sign(self.did_info.verkey, session.wallet)

            await self.manager.verify_diddoc(session.wallet, did_doc_attach)

            did_doc_attach.data.base64_ = "YmFpdCBhbmQgc3dpdGNo"
            with self.assertRaises(DIDXManagerError):
                await self.manager.verify_diddoc(session.wallet, did_doc_attach)

    async def test_receive_invitation(self):
        async with self.profile.session() as session:
            self.profile.context.update_settings({"public_invites": True})
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            with mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                self.multitenant_mgr, "get_default_mediator"
            ) as mock_get_default_mediator:
                mock_get_default_mediator.return_value = mediation_record
                invi_rec = await self.oob_manager.create_invitation(
                    my_endpoint="testendpoint",
                    hs_protos=[HSProto.RFC23],
                )
                invi_msg = invi_rec.invitation
                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                invitee_record = await self.manager.receive_invitation(invi_msg)
                assert invitee_record.state == ConnRecord.State.REQUEST.rfc23

    async def test_receive_invitation_oob_public_did(self):
        async with self.profile.session() as session:
            self.profile.context.update_settings({"public_invites": True})
            public_did_info = None
            await session.wallet.create_public_did(
                SOV,
                ED25519,
            )
            public_did_info = await session.wallet.get_public_did()
            with mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                self.multitenant_mgr, "get_default_mediator"
            ) as mock_get_default_mediator, mock.patch.object(
                self.manager, "resolve_connection_targets", mock.CoroutineMock()
            ) as mock_resolve_targets:
                mock_resolve_targets.return_value = [
                    mock.MagicMock(recipient_keys=["test"])
                ]
                mock_get_default_mediator.return_value = None
                invi_rec = await self.oob_manager.create_invitation(
                    my_endpoint="testendpoint",
                    hs_protos=[HSProto.RFC23],
                )
                invi_msg = invi_rec.invitation
                invi_msg.services = [public_did_info.did]
                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                invitee_record = await self.manager.receive_invitation(
                    invi_msg, their_public_did=public_did_info.did
                )
                assert invitee_record.state == ConnRecord.State.REQUEST.rfc23

    async def test_receive_invitation_no_auto_accept(self):
        async with self.profile.session() as session:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)
            with mock.patch.object(
                self.multitenant_mgr, "get_default_mediator"
            ) as mock_get_default_mediator:
                mock_get_default_mediator.return_value = mediation_record
                invi_rec = await self.oob_manager.create_invitation(
                    my_endpoint="testendpoint",
                    hs_protos=[HSProto.RFC23],
                )

                invitee_record = await self.manager.receive_invitation(
                    invi_rec.invitation,
                    auto_accept=False,
                )
                assert invitee_record.state == ConnRecord.State.INVITATION.rfc23

    async def test_receive_invitation_bad_invitation(self):
        x_invites = [
            InvitationMessage(),
            InvitationMessage(services=[OOBService()]),
            InvitationMessage(
                services=[
                    OOBService(
                        recipient_keys=["3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"]
                    )
                ]
            ),
        ]

        for x_invite in x_invites:
            with self.assertRaises(DIDXManagerError):
                await self.manager.receive_invitation(x_invite)

    async def test_create_request_implicit(self):
        async with self.profile.session() as session:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            with mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc, mock.patch.object(
                self.multitenant_mgr, "get_default_mediator"
            ) as mock_get_default_mediator:
                mock_get_default_mediator.return_value = mediation_record
                mock_create_did_doc.return_value = mock.MagicMock(
                    serialize=mock.MagicMock(return_value={})
                )
                conn_rec = await self.manager.create_request_implicit(
                    their_public_did=TestConfig.test_target_did,
                    my_label=None,
                    my_endpoint=None,
                    mediation_id=mediation_record._id,
                    alias="Tester",
                )

                assert conn_rec

    async def test_create_request_implicit_use_public_did(self):
        async with self.profile.session() as session:
            info_public = await session.wallet.create_public_did(
                SOV,
                ED25519,
            )
            conn_rec = await self.manager.create_request_implicit(
                their_public_did=TestConfig.test_target_did,
                my_label=None,
                my_endpoint=None,
                mediation_id=None,
                use_public_did=True,
                alias="Tester",
                auto_accept=True,
            )

            assert info_public.did == conn_rec.my_did
            assert self.responder.messages
            request, kwargs = self.responder.messages[0]
            assert isinstance(request, test_module.DIDXRequest)
            assert request.did_doc_attach is None

    async def test_create_request_implicit_no_public_did(self):
        with self.assertRaises(WalletError) as context:
            await self.manager.create_request_implicit(
                their_public_did=TestConfig.test_target_did,
                my_label=None,
                my_endpoint=None,
                mediation_id=None,
                use_public_did=True,
                alias="Tester",
            )

        assert "No public DID configured" in str(context.exception)

    async def test_create_request_implicit_x_public_self(self):
        async with self.profile.session() as session:
            info_public = await session.wallet.create_public_did(
                SOV,
                ED25519,
            )
        with self.assertRaises(DIDXManagerError) as context:
            await self.manager.create_request_implicit(
                their_public_did=info_public.did,
                my_label=None,
                my_endpoint=None,
                mediation_id=None,
                use_public_did=True,
                alias="Tester",
            )

        assert "Cannot connect to yourself" in str(context.exception)

    async def test_create_request_implicit_x_public_already_connected(self):
        async with self.profile.session() as session:
            info_public = await session.wallet.create_public_did(
                SOV,
                ED25519,
            )
        with self.assertRaises(DIDXManagerError) as context, mock.patch.object(
            test_module.ConnRecord, "retrieve_by_did", mock.CoroutineMock()
        ) as mock_retrieve_by_did:
            await self.manager.create_request_implicit(
                their_public_did=TestConfig.test_target_did,
                my_label=None,
                my_endpoint=None,
                mediation_id=None,
                use_public_did=True,
                alias="Tester",
            )

        assert "Connection already exists for their_did" in str(context.exception)

    async def test_create_request(self):
        mock_conn_rec = mock.MagicMock(
            connection_id="dummy",
            my_did=self.did_info.did,
            their_did=TestConfig.test_target_did,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.REQUEST.rfc23,
            retrieve_invitation=mock.CoroutineMock(
                return_value=mock.MagicMock(
                    services=[TestConfig.test_target_did],
                )
            ),
            save=mock.CoroutineMock(),
        )

        with mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={})
            )

            didx_req = await self.manager.create_request(mock_conn_rec)
            assert didx_req

    async def test_create_request_multitenant(self):
        self.context.update_settings(
            {"multitenant.enabled": True, "wallet.id": "test_wallet"}
        )

        with mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc, mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={})
            )
            mock_wallet_create_local_did.return_value = DIDInfo(
                TestConfig.test_did,
                TestConfig.test_verkey,
                None,
                method=SOV,
                key_type=ED25519,
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            await self.manager.create_request(
                mock.MagicMock(
                    invitation_key=TestConfig.test_verkey,
                    their_label="Hello",
                    their_role=ConnRecord.Role.RESPONDER.rfc160,
                    alias="Bob",
                    my_did=None,
                    retrieve_invitation=mock.CoroutineMock(
                        return_value=mock.MagicMock(
                            services=[TestConfig.test_target_did],
                        )
                    ),
                    save=mock.CoroutineMock(),
                )
            )

            self.route_manager.route_connection_as_invitee.assert_called_once()

    async def test_create_request_mediation_id(self):
        async with self.profile.session() as session:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            invi = InvitationMessage(
                comment="test",
                handshake_protocols=[
                    pfx.qualify(HSProto.RFC23.name) for pfx in DIDCommPrefix
                ],
                services=[TestConfig.test_did],
            )
            record = ConnRecord(
                invitation_key=TestConfig.test_verkey,
                invitation_msg_id=invi._id,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
                my_did=None,
            )

            await record.save(session)
            await record.attach_invitation(session, invi)

            with mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc:
                mock_create_did_doc.return_value = mock.MagicMock(
                    serialize=mock.MagicMock(return_value={})
                )

                didx_req = await self.manager.create_request(
                    record,
                    my_endpoint="http://testendpoint.com/endpoint",
                    mediation_id=mediation_record._id,
                )
                assert didx_req

            self.route_manager.route_connection_as_invitee.assert_called_once()

    async def test_create_request_my_endpoint(self):
        mock_conn_rec = mock.MagicMock(
            connection_id="dummy",
            my_did=None,
            their_did=TestConfig.test_target_did,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            their_label="Bob",
            invitation_key=TestConfig.test_verkey,
            state=ConnRecord.State.REQUEST.rfc23,
            alias="Bob",
            retrieve_invitation=mock.CoroutineMock(
                return_value=mock.MagicMock(
                    services=[TestConfig.test_target_did],
                )
            ),
            save=mock.CoroutineMock(),
        )

        with mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={})
            )

            didx_req = await self.manager.create_request(
                mock_conn_rec,
                my_endpoint="http://testendpoint.com/endpoint",
            )
            assert didx_req

    async def test_create_request_public_did(self):
        mock_conn_rec = mock.MagicMock(
            connection_id="dummy",
            my_did=self.did_info.did,
            their_did=TestConfig.test_target_did,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.REQUEST.rfc23,
            retrieve_invitation=mock.CoroutineMock(
                return_value=mock.MagicMock(
                    services=[TestConfig.test_target_did],
                )
            ),
            save=mock.CoroutineMock(),
        )

        request = await self.manager.create_request(mock_conn_rec, use_public_did=True)
        assert request.did_doc_attach is None

    async def test_receive_request_explicit_public_did(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            STATE_REQUEST = ConnRecord.State.REQUEST
            self.profile.context.update_settings({"public_invites": True})
            ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                test_module, "DIDXResponse", autospec=True
            ) as mock_response, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(
                    return_value={"id": "did:sov:" + TestConfig.test_did}
                ),
            ), mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc, mock.patch.object(
                MediationManager, "prepare_request", autospec=True
            ) as mock_mediation_mgr_prep_req, mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_create_did_doc.return_value = mock.MagicMock(
                    serialize=mock.MagicMock(return_value={})
                )
                mock_mediation_mgr_prep_req.return_value = (
                    mediation_record,
                    mock_request,
                )

                mock_conn_record = mock.MagicMock(
                    accept=ACCEPT_AUTO,
                    my_did=None,
                    state=STATE_REQUEST.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    metadata_get=mock.CoroutineMock(return_value=True),
                    save=mock.CoroutineMock(),
                )

                mock_conn_rec_cls.ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
                mock_conn_rec_cls.State.REQUEST = STATE_REQUEST
                mock_conn_rec_cls.State.get = mock.MagicMock(return_value=STATE_REQUEST)
                mock_conn_rec_cls.retrieve_by_id = mock.CoroutineMock(
                    return_value=mock.MagicMock(save=mock.CoroutineMock())
                )
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )
                mock_conn_rec_cls.return_value = mock_conn_record

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                mock_response.return_value = mock.MagicMock(
                    assign_thread_from=mock.MagicMock(),
                    assign_trace_from=mock.MagicMock(),
                )

                conn_rec = await self.manager.receive_request(
                    request=mock_request,
                    recipient_did=TestConfig.test_did,
                    recipient_verkey=None,
                    my_endpoint=None,
                    alias=None,
                    auto_accept_implicit=None,
                )
                assert conn_rec
                self.oob_mock.clean_finished_oob_record.assert_called_once_with(
                    self.profile, mock_request
                )

    async def test_receive_request_invi_not_found(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=None,
                _thread=mock.MagicMock(pthid="explicit-not-a-did"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls:
                mock_conn_rec_cls.retrieve_by_invitation_key = mock.CoroutineMock(
                    side_effect=StorageNotFoundError()
                )
                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=TestConfig.test_verkey,
                        my_endpoint=None,
                        alias=None,
                        auto_accept_implicit=None,
                    )
                assert "No explicit invitation found" in str(context.exception)

    async def test_receive_request_public_did_no_did_doc_attachment(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=None,
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            STATE_REQUEST = ConnRecord.State.REQUEST
            self.profile.context.update_settings({"public_invites": True})
            ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                test_module, "DIDXResponse", autospec=True
            ) as mock_response, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(return_value={"id": TestConfig.test_did}),
            ), mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc, mock.patch.object(
                self.manager, "record_did", mock.CoroutineMock()
            ), mock.patch.object(
                MediationManager, "prepare_request", autospec=True
            ) as mock_mediation_mgr_prep_req:
                mock_create_did_doc.return_value = mock.MagicMock(
                    serialize=mock.MagicMock(return_value={})
                )
                mock_mediation_mgr_prep_req.return_value = (
                    mediation_record,
                    mock_request,
                )

                mock_conn_record = mock.MagicMock(
                    accept=ACCEPT_AUTO,
                    my_did=None,
                    state=STATE_REQUEST.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    metadata_get=mock.CoroutineMock(return_value=True),
                    save=mock.CoroutineMock(),
                )

                mock_conn_rec_cls.ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
                mock_conn_rec_cls.State.REQUEST = STATE_REQUEST
                mock_conn_rec_cls.State.get = mock.MagicMock(return_value=STATE_REQUEST)
                mock_conn_rec_cls.retrieve_by_id = mock.CoroutineMock(
                    return_value=mock.MagicMock(save=mock.CoroutineMock())
                )
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )
                mock_conn_rec_cls.return_value = mock_conn_record

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                mock_response.return_value = mock.MagicMock(
                    assign_thread_from=mock.MagicMock(),
                    assign_trace_from=mock.MagicMock(),
                )

                conn_rec = await self.manager.receive_request(
                    request=mock_request,
                    recipient_did=TestConfig.test_did,
                    recipient_verkey=None,
                    my_endpoint=None,
                    alias=None,
                    auto_accept_implicit=None,
                )
                assert conn_rec
                self.oob_mock.clean_finished_oob_record.assert_called_once_with(
                    self.profile, mock_request
                )

    async def test_receive_request_public_did_no_did_doc_attachment_no_did(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=None,
                did_doc_attach=None,
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            STATE_REQUEST = ConnRecord.State.REQUEST
            self.profile.context.update_settings({"public_invites": True})
            ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture:
                mock_conn_record = mock.MagicMock(
                    accept=ACCEPT_AUTO,
                    my_did=None,
                    state=STATE_REQUEST.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    metadata_get=mock.CoroutineMock(return_value=True),
                    save=mock.CoroutineMock(),
                )

                mock_conn_rec_cls.ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
                mock_conn_rec_cls.State.REQUEST = STATE_REQUEST
                mock_conn_rec_cls.State.get = mock.MagicMock(return_value=STATE_REQUEST)
                mock_conn_rec_cls.retrieve_by_id = mock.CoroutineMock(
                    return_value=mock.MagicMock(save=mock.CoroutineMock())
                )
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )
                mock_conn_rec_cls.return_value = mock_conn_record

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=None,
                        my_endpoint=None,
                        alias=None,
                        auto_accept_implicit=None,
                    )
                assert "No DID in request" in str(context.exception)

    async def test_receive_request_public_did_x_not_public(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})
            mock_conn_rec_state_request = ConnRecord.State.REQUEST
            with mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture:
                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.WALLET_ONLY
                )

                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=None,
                        my_endpoint=TestConfig.test_endpoint,
                        alias="Alias",
                        auto_accept_implicit=False,
                    )

                assert "is not public" in str(context.exception)

    async def test_receive_request_public_did_x_wrong_did(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})
            mock_conn_rec_state_request = ConnRecord.State.REQUEST
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(return_value={"id": "LjgpST2rjsoxYegQDRm7EL"}),
            ), mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_conn_record = mock.MagicMock(
                    accept=ConnRecord.ACCEPT_MANUAL,
                    my_did=None,
                    state=mock_conn_rec_state_request.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    save=mock.CoroutineMock(),
                )
                mock_conn_rec_cls.return_value = mock_conn_record
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=None,
                        my_endpoint=TestConfig.test_endpoint,
                        alias="Alias",
                        auto_accept_implicit=False,
                    )

                assert "does not match" in str(context.exception)

    async def test_receive_request_public_did_x_did_doc_attach_bad_sig(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})
            mock_conn_rec_state_request = ConnRecord.State.REQUEST
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(side_effect=DIDXManagerError),
            ):
                mock_conn_record = mock.MagicMock(
                    accept=ConnRecord.ACCEPT_MANUAL,
                    my_did=None,
                    state=mock_conn_rec_state_request.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    save=mock.CoroutineMock(),
                )
                mock_conn_rec_cls.return_value = mock_conn_record
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                with self.assertRaises(DIDXManagerError):
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=None,
                        my_endpoint=TestConfig.test_endpoint,
                        alias="Alias",
                        auto_accept_implicit=False,
                    )

    async def test_receive_request_public_did_no_public_invites(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": False})
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                test_module, "DIDXResponse", autospec=True
            ) as mock_response, mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc:
                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=None,
                        my_endpoint=TestConfig.test_endpoint,
                        alias="Alias",
                        auto_accept_implicit=False,
                    )
                assert "Public invitations are not enabled" in str(context.exception)

    async def test_receive_request_public_did_no_auto_accept(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings(
                {"public_invites": True, "debug.auto_accept_requests": False}
            )
            mock_conn_rec_state_request = ConnRecord.State.REQUEST
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                test_module, "DIDXResponse", autospec=True
            ) as mock_response, mock.patch.object(
                self.manager, "create_did_document", mock.CoroutineMock()
            ) as mock_create_did_doc, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(
                    return_value={"id": "did:sov:" + TestConfig.test_did}
                ),
            ), mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_conn_record = mock.MagicMock(
                    accept=ConnRecord.ACCEPT_MANUAL,
                    my_did=None,
                    state=mock_conn_rec_state_request.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    save=mock.CoroutineMock(),
                )
                mock_conn_rec_cls.return_value = mock_conn_record
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=mock_conn_record
                )

                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )

                conn_rec = await self.manager.receive_request(
                    request=mock_request,
                    recipient_did=TestConfig.test_did,
                    recipient_verkey=None,
                    my_endpoint=TestConfig.test_endpoint,
                    alias="Alias",
                    auto_accept_implicit=False,
                )
                assert conn_rec

            messages = self.responder.messages
            assert not messages

    async def test_receive_request_implicit_public_did_not_enabled(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})

            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(
                    return_value={"id": "did:sov:" + TestConfig.test_did}
                ),
            ), mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )
                mock_conn_rec_cls.retrieve_by_invitation_key = mock.CoroutineMock(
                    side_effect=StorageNotFoundError()
                )
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=None
                )

                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        my_endpoint=None,
                        alias=None,
                        auto_accept_implicit=None,
                    )
                assert "Unsolicited connection requests" in str(context.exception)

    async def test_receive_request_implicit_public_did(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="did:sov:publicdid0000000000000"),
            )
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})
            self.profile.context.update_settings({"requests_through_public_did": True})
            ACCEPT_AUTO = ConnRecord.ACCEPT_AUTO
            STATE_REQUEST = ConnRecord.State.REQUEST

            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "DIDPosture", autospec=True
            ) as mock_did_posture, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(
                    return_value={"id": "did:sov:" + TestConfig.test_did}
                ),
            ), mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_did_posture.get = mock.MagicMock(
                    return_value=test_module.DIDPosture.PUBLIC
                )
                mock_conn_rec_cls.retrieve_by_invitation_key = mock.CoroutineMock(
                    side_effect=StorageNotFoundError()
                )
                mock_conn_rec_cls.retrieve_by_invitation_msg_id = mock.CoroutineMock(
                    return_value=None
                )

                mock_conn_record = mock.MagicMock(
                    accept=ACCEPT_AUTO,
                    my_did=None,
                    state=STATE_REQUEST.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    metadata_get_all=mock.CoroutineMock(return_value={}),
                    metadata_get=mock.CoroutineMock(return_value=True),
                    save=mock.CoroutineMock(),
                )

                mock_conn_rec_cls.return_value = mock_conn_record

                conn_rec = await self.manager.receive_request(
                    request=mock_request,
                    recipient_did=TestConfig.test_did,
                    recipient_verkey=None,
                    my_endpoint=None,
                    alias=None,
                    auto_accept_implicit=None,
                )
                assert conn_rec
                self.oob_mock.clean_finished_oob_record.assert_called_once_with(
                    self.profile, mock_request
                )

    async def test_receive_request_peer_did(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="dummy-pthid"),
            )

            mock_conn = mock.MagicMock(
                my_did=TestConfig.test_did,
                their_did=TestConfig.test_target_did,
                invitation_key=TestConfig.test_verkey,
                connection_id="dummy",
                is_multiuse_invitation=True,
                state=ConnRecord.State.INVITATION.rfc23,
                their_role=ConnRecord.Role.REQUESTER.rfc23,
                save=mock.CoroutineMock(),
                attach_request=mock.CoroutineMock(),
                accept=ConnRecord.ACCEPT_MANUAL,
                metadata_get_all=mock.CoroutineMock(return_value={"test": "value"}),
            )
            mock_conn_rec_state_request = ConnRecord.State.REQUEST

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            self.profile.context.update_settings({"public_invites": True})
            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls, mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco, mock.patch.object(
                test_module, "DIDXResponse", autospec=True
            ) as mock_response, mock.patch.object(
                self.manager,
                "verify_diddoc",
                mock.CoroutineMock(
                    return_value={"id": "did:sov:" + TestConfig.test_did}
                ),
            ), mock.patch.object(
                self.manager, "store_did_document", mock.CoroutineMock()
            ):
                mock_conn_rec_cls.retrieve_by_invitation_key = mock.CoroutineMock(
                    return_value=mock_conn
                )
                mock_conn_rec_cls.return_value = mock.MagicMock(
                    accept=ConnRecord.ACCEPT_AUTO,
                    my_did=None,
                    state=mock_conn_rec_state_request.rfc23,
                    attach_request=mock.CoroutineMock(),
                    retrieve_request=mock.CoroutineMock(),
                    save=mock.CoroutineMock(),
                    metadata_set=mock.CoroutineMock(),
                )
                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                mock_response.return_value = mock.MagicMock(
                    assign_thread_from=mock.MagicMock(),
                    assign_trace_from=mock.MagicMock(),
                )

                conn_rec = await self.manager.receive_request(
                    request=mock_request,
                    recipient_did=TestConfig.test_did,
                    recipient_verkey=TestConfig.test_verkey,
                    my_endpoint=TestConfig.test_endpoint,
                    alias="Alias",
                    auto_accept_implicit=False,
                )
                assert conn_rec
                mock_conn_rec_cls.return_value.metadata_set.assert_called()

            assert not self.responder.messages

    async def test_receive_request_peer_did_not_found_x(self):
        async with self.profile.session() as session:
            mock_request = mock.MagicMock(
                did=TestConfig.test_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(return_value="dummy-did-doc")
                        ),
                    )
                ),
                _thread=mock.MagicMock(pthid="dummy-pthid"),
            )

            await session.wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
                seed=None,
                did=TestConfig.test_did,
            )

            with mock.patch.object(
                test_module, "ConnRecord", mock.MagicMock()
            ) as mock_conn_rec_cls:
                mock_conn_rec_cls.retrieve_by_invitation_key = mock.CoroutineMock(
                    side_effect=StorageNotFoundError()
                )
                with self.assertRaises(DIDXManagerError):
                    await self.manager.receive_request(
                        request=mock_request,
                        recipient_did=TestConfig.test_did,
                        recipient_verkey=TestConfig.test_verkey,
                        my_endpoint=TestConfig.test_endpoint,
                        alias="Alias",
                        auto_accept_implicit=False,
                    )

    async def test_create_response(self):
        conn_rec = ConnRecord(
            connection_id="dummy", state=ConnRecord.State.REQUEST.rfc23
        )

        with mock.patch.object(
            test_module.ConnRecord, "retrieve_request", mock.CoroutineMock()
        ) as mock_retrieve_req, mock.patch.object(
            conn_rec, "save", mock.CoroutineMock()
        ) as mock_save, mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco, mock.patch.object(
            test_module, "DIDXResponse", autospec=True
        ) as mock_response, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock()
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            await self.manager.create_response(conn_rec, "http://10.20.30.40:5060/")

    async def test_create_response_mediation_id(self):
        async with self.profile.session() as session:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            invi = InvitationMessage(
                comment="test",
                handshake_protocols=[
                    pfx.qualify(HSProto.RFC23.name) for pfx in DIDCommPrefix
                ],
                services=[TestConfig.test_did],
            )
            record = ConnRecord(
                invitation_key=TestConfig.test_verkey,
                invitation_msg_id=invi._id,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
                my_did=None,
                state=ConnRecord.State.REQUEST.rfc23,
            )

            await record.save(session)
            await record.attach_invitation(session, invi)

            with mock.patch.object(
                ConnRecord, "log_state", autospec=True
            ) as mock_conn_log_state, mock.patch.object(
                ConnRecord, "retrieve_request", autospec=True
            ) as mock_conn_retrieve_request, mock.patch.object(
                ConnRecord, "save", autospec=True
            ) as mock_conn_save, mock.patch.object(
                record, "metadata_get", mock.CoroutineMock(return_value=False)
            ), mock.patch.object(
                test_module, "AttachDecorator", autospec=True
            ) as mock_attach_deco:
                mock_attach_deco.data_base64 = mock.MagicMock(
                    return_value=mock.MagicMock(
                        data=mock.MagicMock(sign=mock.CoroutineMock())
                    )
                )
                await self.manager.create_response(
                    record, mediation_id=mediation_record.mediation_id
                )

            self.route_manager.route_connection_as_inviter.assert_called_once()

    async def test_create_response_mediation_id_invalid_conn_state(self):
        async with self.profile.session() as session:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_GRANTED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(session)

            invi = InvitationMessage(
                comment="test",
                handshake_protocols=[
                    pfx.qualify(HSProto.RFC23.name) for pfx in DIDCommPrefix
                ],
                services=[TestConfig.test_did],
            )
            record = ConnRecord(
                invitation_key=TestConfig.test_verkey,
                invitation_msg_id=invi._id,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
                my_did=None,
            )

            await record.save(session)
            await record.attach_invitation(session, invi)

            with mock.patch.object(
                ConnRecord, "log_state", autospec=True
            ) as mock_conn_log_state, mock.patch.object(
                ConnRecord, "retrieve_request", autospec=True
            ) as mock_conn_retrieve_request, mock.patch.object(
                ConnRecord, "save", autospec=True
            ) as mock_conn_save, mock.patch.object(
                record, "metadata_get", mock.CoroutineMock(return_value=False)
            ):
                with self.assertRaises(DIDXManagerError) as context:
                    await self.manager.create_response(
                        record, mediation_id=mediation_record.mediation_id
                    )
                    assert "Connection not in state" in str(context.exception)

    async def test_create_response_multitenant(self):
        conn_rec = ConnRecord(
            connection_id="dummy", state=ConnRecord.State.REQUEST.rfc23
        )

        self.manager.profile.context.update_settings(
            {
                "multitenant.enabled": True,
                "wallet.id": "test_wallet",
            }
        )

        with mock.patch.object(
            test_module.ConnRecord, "retrieve_request"
        ), mock.patch.object(conn_rec, "save", mock.CoroutineMock()), mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc, mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                TestConfig.test_did,
                TestConfig.test_verkey,
                None,
                method=SOV,
                key_type=ED25519,
            )
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock()
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            await self.manager.create_response(conn_rec)
            self.route_manager.route_connection_as_inviter.assert_called_once()

    async def test_create_response_conn_rec_my_did(self):
        conn_rec = ConnRecord(
            connection_id="dummy",
            my_did=TestConfig.test_did,
            state=ConnRecord.State.REQUEST.rfc23,
        )

        with mock.patch.object(
            test_module.ConnRecord, "retrieve_request", mock.CoroutineMock()
        ) as mock_retrieve_req, mock.patch.object(
            conn_rec, "save", mock.CoroutineMock()
        ) as mock_save, mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco, mock.patch.object(
            test_module, "DIDXResponse", autospec=True
        ) as mock_response, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc, mock.patch.object(
            InMemoryWallet, "get_local_did", mock.CoroutineMock()
        ) as mock_get_loc_did:
            mock_get_loc_did.return_value = self.did_info
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock()
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            await self.manager.create_response(conn_rec, "http://10.20.30.40:5060/")

    async def test_create_response_bad_state(self):
        with self.assertRaises(DIDXManagerError):
            await self.manager.create_response(
                ConnRecord(
                    invitation_key=TestConfig.test_verkey,
                    their_label="Hello",
                    their_role=ConnRecord.Role.REQUESTER.rfc23,
                    state=ConnRecord.State.ABANDONED.rfc23,
                    alias="Bob",
                )
            )

    async def test_create_response_use_public_did(self):
        async with self.profile.session() as session:
            info_public = await session.wallet.create_public_did(
                SOV,
                ED25519,
            )

        conn_rec = ConnRecord(
            connection_id="dummy", state=ConnRecord.State.REQUEST.rfc23
        )

        with mock.patch.object(
            test_module.ConnRecord, "retrieve_request", mock.CoroutineMock()
        ) as mock_retrieve_req, mock.patch.object(
            conn_rec, "save", mock.CoroutineMock()
        ) as mock_save, mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco, mock.patch.object(
            test_module, "DIDXResponse", autospec=True
        ) as mock_response, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock()
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            await self.manager.create_response(
                conn_rec, "http://10.20.30.40:5060/", use_public_did=True
            )

    async def test_create_response_use_public_did_x_no_public_did(self):
        conn_rec = ConnRecord(
            connection_id="dummy", state=ConnRecord.State.REQUEST.rfc23
        )

        with mock.patch.object(
            test_module.ConnRecord, "retrieve_request", mock.CoroutineMock()
        ) as mock_retrieve_req, mock.patch.object(
            conn_rec, "save", mock.CoroutineMock()
        ) as mock_save, mock.patch.object(
            test_module, "AttachDecorator", autospec=True
        ) as mock_attach_deco, mock.patch.object(
            test_module, "DIDXResponse", autospec=True
        ) as mock_response, mock.patch.object(
            self.manager, "create_did_document", mock.CoroutineMock()
        ) as mock_create_did_doc:
            mock_create_did_doc.return_value = mock.MagicMock(
                serialize=mock.MagicMock()
            )
            mock_attach_deco.data_base64 = mock.MagicMock(
                return_value=mock.MagicMock(
                    data=mock.MagicMock(sign=mock.CoroutineMock())
                )
            )

            with self.assertRaises(DIDXManagerError) as context:
                await self.manager.create_response(
                    conn_rec, "http://10.20.30.40:5060/", use_public_did=True
                )
            assert "No public DID configured" in str(context.exception)

    async def test_accept_response_find_by_thread_id(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(
                        return_value=json.dumps(
                            {"id": "did:sov:" + TestConfig.test_target_did}
                        )
                    )
                ),
            )
        )

        receipt = MessageReceipt(
            recipient_did=TestConfig.test_did,
            recipient_did_public=True,
        )

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_id, mock.patch.object(
            self.manager, "store_did_document", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(
                                return_value=json.dumps({"dummy": "did-doc"})
                            )
                        ),
                    )
                ),
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
                metadata_get=mock.CoroutineMock(),
                connection_id="test-conn-id",
            )
            mock_conn_retrieve_by_id.return_value = mock.MagicMock(
                their_did=TestConfig.test_target_did,
                save=mock.CoroutineMock(),
            )

            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == TestConfig.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_accept_response_find_by_thread_id_auto_disclose_features(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(
                        return_value=json.dumps(
                            {"id": "did:sov:" + TestConfig.test_target_did}
                        )
                    )
                ),
            )
        )

        receipt = MessageReceipt(
            recipient_did=TestConfig.test_did,
            recipient_did_public=True,
        )
        self.context.update_settings({"auto_disclose_features": True})

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_id, mock.patch.object(
            V20DiscoveryMgr, "proactive_disclose_features", mock.CoroutineMock()
        ) as mock_proactive_disclose_features, mock.patch.object(
            self.manager, "store_did_document", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(
                                return_value=json.dumps({"dummy": "did-doc"})
                            )
                        ),
                    )
                ),
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
                metadata_get=mock.CoroutineMock(),
                connection_id="test-conn-id",
            )
            mock_conn_retrieve_by_id.return_value = mock.MagicMock(
                their_did=TestConfig.test_target_did,
                save=mock.CoroutineMock(),
            )

            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == TestConfig.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED
            mock_proactive_disclose_features.assert_called_once()

    async def test_accept_response_not_found_by_thread_id_receipt_has_sender_did(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(
                        return_value=json.dumps(
                            {"id": "did:sov:" + TestConfig.test_target_did}
                        )
                    )
                ),
            )
        )

        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_did", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did, mock.patch.object(
            self.manager, "store_did_document", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_did.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(
                                return_value=json.dumps({"dummy": "did-doc"})
                            )
                        ),
                    )
                ),
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
                metadata_get=mock.CoroutineMock(return_value=False),
                connection_id="test-conn-id",
            )

            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == TestConfig.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_accept_response_not_found_by_thread_id_nor_receipt_sender_did(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(return_value=json.dumps({"dummy": "did-doc"}))
                ),
            )
        )

        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_did", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did:
            mock_conn_retrieve_by_req_id.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_did.side_effect = StorageNotFoundError()

            with self.assertRaises(DIDXManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_find_by_thread_id_bad_state(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(return_value=json.dumps({"dummy": "did-doc"}))
                ),
            )
        )

        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                state=ConnRecord.State.ABANDONED.rfc23
            )

            with self.assertRaises(DIDXManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_find_by_thread_id_no_did_doc_attached(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = None

        receipt = MessageReceipt(
            recipient_did=TestConfig.test_did,
            recipient_did_public=True,
        )

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_id, mock.patch.object(
            self.manager, "record_did", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
                metadata_get=mock.CoroutineMock(),
                connection_id="test-conn-id",
            )
            mock_conn_retrieve_by_id.return_value = mock.MagicMock(
                their_did=TestConfig.test_target_did,
                save=mock.CoroutineMock(),
            )

            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == TestConfig.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_accept_response_find_by_thread_id_no_did_doc_attached_no_did(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = None
        mock_response.did_doc_attach = None

        receipt = MessageReceipt(
            recipient_did=TestConfig.test_did,
            recipient_did_public=True,
        )

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_id, mock.patch.object(
            self.manager, "record_did", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
                metadata_get=mock.CoroutineMock(),
                connection_id="test-conn-id",
            )
            mock_conn_retrieve_by_id.return_value = mock.MagicMock(
                their_did=TestConfig.test_target_did,
                save=mock.CoroutineMock(),
            )

            with self.assertRaises(DIDXManagerError) as context:
                await self.manager.accept_response(mock_response, receipt)
            assert "No DID in response" in str(context.exception)

    async def test_accept_response_find_by_thread_id_did_mismatch(self):
        mock_response = mock.MagicMock()
        mock_response._thread = mock.MagicMock()
        mock_response.did = TestConfig.test_target_did
        mock_response.did_doc_attach = mock.MagicMock(
            data=mock.MagicMock(
                verify=mock.CoroutineMock(return_value=True),
                signed=mock.MagicMock(
                    decode=mock.MagicMock(
                        return_value=json.dumps(
                            {"id": "did:sov:" + TestConfig.test_did}
                        )
                    )
                ),
            )
        )

        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_id, mock.patch.object(
            self.manager, "store_did_document", mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = mock.MagicMock(
                did=TestConfig.test_target_did,
                did_doc_attach=mock.MagicMock(
                    data=mock.MagicMock(
                        verify=mock.CoroutineMock(return_value=True),
                        signed=mock.MagicMock(
                            decode=mock.MagicMock(
                                return_value=json.dumps({"dummy": "did-doc"})
                            )
                        ),
                    )
                ),
                state=ConnRecord.State.REQUEST.rfc23,
                save=mock.CoroutineMock(),
            )
            mock_conn_retrieve_by_id.return_value = mock.MagicMock(
                their_did=TestConfig.test_target_did,
                save=mock.CoroutineMock(),
            )

            with self.assertRaises(DIDXManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_complete(self):
        mock_complete = mock.MagicMock()
        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.return_value.save = mock.CoroutineMock()
            conn_rec = await self.manager.accept_complete(mock_complete, receipt)
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_accept_complete_with_disclose(self):
        mock_complete = mock.MagicMock()
        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)
        self.context.update_settings({"auto_disclose_features": True})
        with mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, mock.patch.object(
            V20DiscoveryMgr, "proactive_disclose_features", mock.CoroutineMock()
        ) as mock_proactive_disclose_features:
            mock_conn_retrieve_by_req_id.return_value.save = mock.CoroutineMock()
            conn_rec = await self.manager.accept_complete(mock_complete, receipt)
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED
            mock_proactive_disclose_features.assert_called_once()

    async def test_accept_complete_x_not_found(self):
        mock_complete = mock.MagicMock()
        receipt = MessageReceipt(sender_did=TestConfig.test_target_did)

        with mock.patch.object(
            ConnRecord, "retrieve_by_request_id", mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.side_effect = StorageNotFoundError()
            with self.assertRaises(DIDXManagerError):
                await self.manager.accept_complete(mock_complete, receipt)

    async def test_reject_invited(self):
        mock_conn = ConnRecord(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.INVITATION.rfc23,
            their_role=ConnRecord.Role.RESPONDER,
        )
        mock_conn.abandon = mock.CoroutineMock()
        reason = "He doesn't like you!"
        report = await self.manager.reject(mock_conn, reason=reason)
        assert report

    async def test_reject_requested(self):
        mock_conn = ConnRecord(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.REQUEST.rfc23,
            their_role=ConnRecord.Role.REQUESTER,
        )
        mock_conn.abandon = mock.CoroutineMock()
        reason = "I don't like you either! You just watch yourself!"
        report = await self.manager.reject(mock_conn, reason=reason)
        assert report

    async def test_reject_invalid(self):
        mock_conn = ConnRecord(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )
        mock_conn.abandon = mock.CoroutineMock()
        reason = "I'll be careful."
        with self.assertRaises(DIDXManagerError) as context:
            await self.manager.reject(mock_conn, reason=reason)
        assert "Cannot reject connection in state" in str(context.exception)

    async def test_receive_problem_report(self):
        mock_conn = mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )
        mock_conn.abandon = mock.CoroutineMock()
        report = DIDXProblemReport(
            description={
                "code": ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
                "en": "You'll be dead!",
            }
        )
        await self.manager.receive_problem_report(mock_conn, report)
        mock_conn.abandon.assert_called_once()

    async def test_receive_problem_report_x_missing_description(self):
        mock_conn = mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )
        mock_conn.abandon = mock.CoroutineMock()
        report = DIDXProblemReport()
        with self.assertRaises(DIDXManagerError) as context:
            await self.manager.receive_problem_report(mock_conn, report)
        assert "Missing description" in str(context.exception)

    async def test_receive_problem_report_x_unrecognized_code(self):
        mock_conn = mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=TestConfig.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )
        mock_conn.abandon = mock.CoroutineMock()
        report = DIDXProblemReport(description={"code": "something random"})
        with self.assertRaises(DIDXManagerError) as context:
            await self.manager.receive_problem_report(mock_conn, report)
        assert "unrecognized problem report" in str(context.exception)
