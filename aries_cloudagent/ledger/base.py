"""Ledger base class."""

import json
import logging
import re

from abc import ABC, abstractmethod, ABCMeta
from enum import Enum
from hashlib import sha256
from typing import List, Sequence, Tuple, Union

from ..messaging.valid import IndyDID
from ..utils import sentinel
from ..wallet.did_info import DIDInfo

from .error import (
    BadLedgerRequestError,
    LedgerError,
    LedgerTransactionError,
    LedgerObjectAlreadyExistsError,
)

from .endpoint_type import EndpointType

LOGGER = logging.getLogger(__name__)


class BaseLedger(ABC, metaclass=ABCMeta):
    """Base class for ledger."""

    BACKEND_NAME: str = None

    async def __aenter__(self) -> "BaseLedger":
        """Context manager entry.

        Returns:
            The current instance

        """
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit."""

    @property
    def backend(self) -> str:
        """Accessor for the ledger backend name."""
        return self.__class__.BACKEND_NAME

    @property
    @abstractmethod
    def read_only(self) -> bool:
        """Accessor for the ledger read-only flag."""

    @abstractmethod
    async def is_ledger_read_only(self) -> bool:
        """Check if ledger is read-only including TAA."""

    @abstractmethod
    async def get_key_for_did(self, did: str) -> str:
        """Fetch the verkey for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """

    @abstractmethod
    async def get_endpoint_for_did(
        self, did: str, endpoint_type: EndpointType = EndpointType.ENDPOINT
    ) -> str:
        """Fetch the endpoint for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
            endpoint_type: The type of the endpoint (default 'endpoint')
        """

    @abstractmethod
    async def get_all_endpoints_for_did(self, did: str) -> dict:
        """Fetch all endpoints for a ledger DID.

        Args:
            did: The DID to look up on the ledger or in the cache
        """

    async def _construct_attr_json(
        self,
        endpoint: str,
        endpoint_type: EndpointType = None,
        all_exist_endpoints: dict = None,
        routing_keys: List[str] = None,
    ) -> str:
        """Create attr_json string.

        Args:
            all_exist_endpoings: Dictionary of all existing endpoints
            endpoint: The endpoint address
            endpoint_type: The type of the endpoint
            routing_keys: List of routing_keys if mediator is present
        """

        if not routing_keys:
            routing_keys = []

        if all_exist_endpoints:
            all_exist_endpoints[endpoint_type.indy] = endpoint
            all_exist_endpoints["routingKeys"] = routing_keys
            attr_json = json.dumps({"endpoint": all_exist_endpoints})

        else:
            endpoint_dict = {endpoint_type.indy: endpoint}
            endpoint_dict["routingKeys"] = routing_keys
            attr_json = json.dumps({"endpoint": endpoint_dict})

        return attr_json

    @abstractmethod
    async def update_endpoint_for_did(
        self,
        did: str,
        endpoint: str,
        endpoint_type: EndpointType = EndpointType.ENDPOINT,
        write_ledger: bool = True,
        endorser_did: str = None,
        routing_keys: List[str] = None,
    ) -> bool:
        """Check and update the endpoint on the ledger.

        Args:
            did: The ledger DID
            endpoint: The endpoint address
            endpoint_type: The type of the endpoint (default 'endpoint')
        """

    @abstractmethod
    async def register_nym(
        self,
        did: str,
        verkey: str,
        alias: str = None,
        role: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[bool, dict]:
        """Register a nym on the ledger.

        Args:
            did: DID to register on the ledger.
            verkey: The verification key of the keypair.
            alias: Human-friendly alias to assign to the DID.
            role: For permissioned ledgers, what role should the new DID have.
        """

    @abstractmethod
    async def get_nym_role(self, did: str):
        """Return the role registered to input public DID on the ledger.

        Args:
            did: DID to register on the ledger.
        """

    @abstractmethod
    def nym_to_did(self, nym: str) -> str:
        """Format a nym with the ledger's DID prefix."""

    @abstractmethod
    async def rotate_public_did_keypair(self, next_seed: str = None) -> None:
        """Rotate keypair for public DID: create new key, submit to ledger, update wallet.

        Args:
            next_seed: seed for incoming ed25519 keypair (default random)
        """

    def did_to_nym(self, did: str) -> str:
        """Remove the ledger's DID prefix to produce a nym."""
        if did:
            return re.sub(r"^did:\w+:", "", did)

    @abstractmethod
    async def get_wallet_public_did(self) -> DIDInfo:
        """Fetch the public DID from the wallet."""

    @abstractmethod
    async def get_txn_author_agreement(self, reload: bool = False):
        """Get the current transaction author agreement, fetching it if necessary."""

    @abstractmethod
    async def fetch_txn_author_agreement(self):
        """Fetch the current AML and TAA from the ledger."""

    @abstractmethod
    async def accept_txn_author_agreement(
        self, taa_record: dict, mechanism: str, accept_time: int = None
    ):
        """Save a new record recording the acceptance of the TAA."""

    @abstractmethod
    async def get_latest_txn_author_acceptance(self):
        """Look up the latest TAA acceptance."""

    def taa_digest(self, version: str, text: str):
        """Generate the digest of a TAA record."""
        if not version or not text:
            raise ValueError("Bad input for TAA digest")
        taa_plaintext = version + text
        return sha256(taa_plaintext.encode("utf-8")).digest().hex()

    @abstractmethod
    async def txn_endorse(
        self,
        request_json: str,
        endorse_did: DIDInfo = None,
    ) -> str:
        """Endorse (sign) the provided transaction."""

    @abstractmethod
    async def txn_submit(
        self,
        request_json: str,
        sign: bool,
        taa_accept: bool = None,
        sign_did: DIDInfo = sentinel,
        write_ledger: bool = True,
    ) -> str:
        """Write the provided (signed and possibly endorsed) transaction to the ledger."""

    @abstractmethod
    async def fetch_schema_by_id(self, schema_id: str) -> dict:
        """Get schema from ledger.

        Args:
            schema_id: The schema id (or stringified sequence number) to retrieve

        Returns:
            Indy schema dict

        """

    @abstractmethod
    async def fetch_schema_by_seq_no(self, seq_no: int) -> dict:
        """Fetch a schema by its sequence number.

        Args:
            seq_no: schema ledger sequence number

        Returns:
            Indy schema dict

        """

    async def check_existing_schema(
        self,
        schema_id: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, dict]:
        """Check if a schema has already been published."""
        schema = await self.fetch_schema_by_id(schema_id)
        if schema:
            fetched_attrs = schema["attrNames"].copy()
            if set(fetched_attrs) != set(attribute_names):
                raise LedgerTransactionError(
                    "Schema already exists on ledger, but attributes do not match: "
                    + f"{schema_id} {fetched_attrs} != {attribute_names}"
                )
            return schema_id, schema

    async def send_schema(
        self,
        schema_id: str,
        schema_def: dict,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict]:
        """Send schema to ledger.

        Args:
            issuer: The issuer instance to use for schema creation
            schema_name: The schema name
            schema_version: The schema version
            attribute_names: A list of schema attributes

        """

        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError("Cannot publish schema without a public DID")

        if not bool(IndyDID.PATTERN.match(public_info.did)):
            raise BadLedgerRequestError(
                "Cannot publish schema when public DID is not an IndyDID"
            )

        schema_info = await self.check_existing_schema(
            schema_id, schema_def["attrNames"]
        )

        if schema_info:
            LOGGER.warning("Schema already exists on ledger. Returning details.")
            schema_id, schema_def = schema_info
        else:
            if await self.is_ledger_read_only():
                raise LedgerError(
                    "Error cannot write schema when ledger is in read only mode, "
                    "or TAA is required and not accepted"
                )

        if await self.is_ledger_read_only():
            raise LedgerError(
                "Error cannot write schema when ledger is in read only mode"
            )

        schema_req = await self._create_schema_request(
            public_info,
            json.dumps(schema_def),
            write_ledger=write_ledger,
            endorser_did=endorser_did,
        )

        try:
            resp = await self.txn_submit(
                schema_req,
                sign=True,
                sign_did=public_info,
                write_ledger=write_ledger,
            )

            # TODO Clean this up
            # if not write_ledger:
            #     return schema_id, {"signed_txn": resp}

            try:
                # parse sequence number out of response
                seq_no = json.loads(resp)["result"]["txnMetadata"]["seqNo"]
                return seq_no
            except KeyError as err:
                raise LedgerError(
                    "Failed to parse schema sequence number from ledger response"
                ) from err
        except LedgerTransactionError as e:
            # Identify possible duplicate schema errors on indy-node < 1.9 and > 1.9
            if (
                "can have one and only one SCHEMA with name" in e.message
                or "UnauthorizedClientRequest" in e.message
            ):
                # handle potential race condition if multiple agents are publishing
                # the same schema simultaneously
                schema_info = await self.check_existing_schema(
                    schema_id, schema_def["attrNames"]
                )
                if schema_info:
                    LOGGER.warning(
                        "Schema already exists on ledger. Returning details."
                        " Error: %s",
                        e,
                    )
                    raise LedgerObjectAlreadyExistsError(
                        f"Schema already exists on ledger (Error: {e})", *schema_info
                    )
                else:
                    raise
            else:
                raise

    @abstractmethod
    async def _create_schema_request(
        self,
        public_info: DIDInfo,
        schema_json: str,
        write_ledger: bool = True,
        endorser_did: str = None,
    ):
        """Create the ledger request for publishing a schema."""

    @abstractmethod
    async def get_revoc_reg_def(self, revoc_reg_id: str) -> dict:
        """Look up a revocation registry definition by ID."""

    @abstractmethod
    async def send_revoc_reg_def(
        self,
        revoc_reg_def: dict,
        issuer_did: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> dict:
        """Publish a revocation registry definition to the ledger."""

    @abstractmethod
    async def send_revoc_reg_entry(
        self,
        revoc_reg_id: str,
        revoc_def_type: str,
        revoc_reg_entry: dict,
        issuer_did: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> dict:
        """Publish a revocation registry entry to the ledger."""

    async def send_credential_definition(
        self,
        schema_id: str,
        cred_def_id: str,
        cred_def: dict,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict, bool]:
        """Send credential definition to ledger and store relevant key matter in wallet.

        Args:
            issuer: The issuer instance to use for credential definition creation
            schema_id: The schema id of the schema to create cred def for
            signature_type: The signature type to use on the credential definition
            tag: Optional tag to distinguish multiple credential definitions
            support_revocation: Optional flag to enable revocation for this cred def

        Returns:
            Tuple with cred def id, cred def structure, and whether it's novel

        """
        public_info = await self.get_wallet_public_did()
        if not public_info:
            raise BadLedgerRequestError(
                "Cannot publish credential definition without a public DID"
            )

        schema = await self.get_schema(schema_id)
        if not schema:
            raise LedgerError(f"Ledger {self.pool.name} has no schema {schema_id}")

        # check if cred def is on ledger already
        ledger_cred_def = await self.fetch_credential_definition(cred_def_id)
        if ledger_cred_def:
            credential_definition_json = json.dumps(ledger_cred_def)
            raise LedgerObjectAlreadyExistsError(
                f"Credential definition with id {cred_def_id} "
                "already exists in wallet and on ledger.",
                cred_def_id,
                credential_definition_json,
            )

        if await self.is_ledger_read_only():
            raise LedgerError(
                "Error cannot write cred def when ledger is in read only mode"
            )

        cred_def_req = await self._create_credential_definition_request(
            public_info,
            json.dumps(cred_def),
            write_ledger=write_ledger,
            endorser_did=endorser_did,
        )

        resp = await self.txn_submit(
            cred_def_req, True, sign_did=public_info, write_ledger=write_ledger
        )

        # TODO Clean up
        # if not write_ledger:
        #     return (credential_definition_id, {"signed_txn": resp}, novel)

        seq_no = json.loads(resp)["result"]["txnMetadata"]["seqNo"]
        return seq_no

    @abstractmethod
    async def _create_credential_definition_request(
        self,
        public_info: DIDInfo,
        credential_definition_json: str,
        write_ledger: bool = True,
        endorser_did: str = None,
    ):
        """Create the ledger request for publishing a credential definition."""

    @abstractmethod
    async def get_credential_definition(self, credential_definition_id: str) -> dict:
        """Get a credential definition from the cache if available, otherwise the ledger.

        Args:
            credential_definition_id: The schema id of the schema to fetch cred def for

        """

    @abstractmethod
    async def get_revoc_reg_delta(
        self, revoc_reg_id: str, timestamp_from=0, timestamp_to=None
    ) -> Tuple[dict, int]:
        """Look up a revocation registry delta by ID."""

    @abstractmethod
    async def get_schema(self, schema_id: str) -> dict:
        """Get a schema from the cache if available, otherwise fetch from the ledger.

        Args:
            schema_id: The schema id (or stringified sequence number) to retrieve

        """

    @abstractmethod
    async def get_revoc_reg_entry(
        self, revoc_reg_id: str, timestamp: int
    ) -> Tuple[dict, int]:
        """Get revocation registry entry by revocation registry ID and timestamp."""


class Role(Enum):
    """Enum for indy roles."""

    STEWARD = (2,)
    TRUSTEE = (0,)
    ENDORSER = (101,)
    NETWORK_MONITOR = (201,)
    USER = (None, "")  # in case reading from file, default empty "" or None for USER
    ROLE_REMOVE = ("",)  # but indy-sdk uses "" to identify a role in reset

    @staticmethod
    def get(token: Union[str, int] = None) -> "Role":
        """Return enum instance corresponding to input token.

        Args:
            token: token identifying role to indy-sdk:
                "STEWARD", "TRUSTEE", "ENDORSER", "" or None
        """
        if token is None:
            return Role.USER

        for role in Role:
            if role == Role.ROLE_REMOVE:
                continue  # not a sensible role to parse from any configuration
            if isinstance(token, int) and token in role.value:
                return role
            if str(token).upper() == role.name or token in (str(v) for v in role.value):
                return role

        return None

    def to_indy_num_str(self) -> str:
        """Return (typically, numeric) string value that indy-sdk associates with role.

        Recall that None signifies USER and "" signifies a role undergoing reset.
        """

        return str(self.value[0]) if isinstance(self.value[0], int) else self.value[0]

    def token(self) -> str:
        """Return token identifying role to indy-sdk."""

        return self.value[0] if self in (Role.USER, Role.ROLE_REMOVE) else self.name
