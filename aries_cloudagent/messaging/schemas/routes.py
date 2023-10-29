"""Credential schema admin routes."""

import functools
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields
from marshmallow.validate import Regexp
from aries_cloudagent.anoncreds.base import AnonCredsResolutionError

from aries_cloudagent.anoncreds.issuer import AnonCredsIssuer, AnonCredsIssuerError
from aries_cloudagent.anoncreds.registry import AnonCredsRegistry
from aries_cloudagent.wallet.base import BaseWallet

from ...admin.request_context import AdminRequestContext
from ...indy.models.schema import SchemaSchema
from ...ledger.error import BadLedgerRequestError
from ...protocols.endorse_transaction.v1_0.models.transaction_record import (
    TransactionRecordSchema,
)

from ..models.openapi import OpenAPISchema
from ..valid import (
    B58,
    INDY_SCHEMA_ID_EXAMPLE,
    INDY_SCHEMA_ID_VALIDATE,
    INDY_VERSION_EXAMPLE,
    INDY_VERSION_VALIDATE,
    UUID4_EXAMPLE,
)
from .util import (
    SchemaQueryStringSchema,
    notify_schema_event,
)

from ..valid import UUIDFour


class SchemaSendRequestSchema(OpenAPISchema):
    """Request schema for schema send request."""

    schema_name = fields.Str(
        required=True, metadata={"description": "Schema name", "example": "prefs"}
    )
    schema_version = fields.Str(
        required=True,
        validate=INDY_VERSION_VALIDATE,
        metadata={"description": "Schema version", "example": INDY_VERSION_EXAMPLE},
    )
    attributes = fields.List(
        fields.Str(metadata={"description": "attribute name", "example": "score"}),
        required=True,
        metadata={"description": "List of schema attributes"},
    )


class SchemaSendResultSchema(OpenAPISchema):
    """Result schema content for schema send request with auto-endorse."""

    schema_id = fields.Str(
        required=True,
        validate=INDY_SCHEMA_ID_VALIDATE,
        metadata={
            "description": "Schema identifier",
            "example": INDY_SCHEMA_ID_EXAMPLE,
        },
    )
    schema = fields.Nested(
        SchemaSchema(), metadata={"description": "Schema definition"}
    )


class TxnOrSchemaSendResultSchema(OpenAPISchema):
    """Result schema for schema send request."""

    sent = fields.Nested(
        SchemaSendResultSchema(),
        required=False,
        metadata={"description": "Content sent"},
    )
    txn = fields.Nested(
        TransactionRecordSchema(),
        required=False,
        metadata={"description": "Schema transaction to endorse"},
    )


class SchemaGetResultSchema(OpenAPISchema):
    """Result schema for schema get request."""

    schema = fields.Nested(SchemaSchema())


class SchemasCreatedResultSchema(OpenAPISchema):
    """Result schema for a schemas-created request."""

    schema_ids = fields.List(
        fields.Str(
            validate=INDY_SCHEMA_ID_VALIDATE,
            metadata={
                "description": "Schema identifiers",
                "example": INDY_SCHEMA_ID_EXAMPLE,
            },
        )
    )


class SchemaIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking schema id."""

    schema_id = fields.Str(
        required=True,
        validate=Regexp(f"^[1-9][0-9]*|[{B58}]{{21,22}}:2:.+:[0-9.]+$"),
        metadata={
            "description": "Schema identifier",
            "example": INDY_SCHEMA_ID_EXAMPLE,
        },
    )


class CreateSchemaTxnForEndorserOptionSchema(OpenAPISchema):
    """Class for user to input whether to create a transaction for endorser or not."""

    create_transaction_for_endorser = fields.Boolean(
        required=False,
        metadata={"description": "Create Transaction For Endorser's signature"},
    )


class SchemaConnIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking connection id."""

    conn_id = fields.Str(
        required=False,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )


def error_handler(func):
    """API/Routes Error handler function."""

    @functools.wraps(func)
    async def wrapper(request):
        try:
            ret = await func(request)
            return ret
        except AnonCredsResolutionError as err:
            raise web.HTTPForbidden(reason=err.roll_up) from err
        except AnonCredsIssuerError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
        except Exception as err:
            raise err

    return wrapper


@docs(tags=["schema"], summary="Sends a schema to the ledger")
@request_schema(SchemaSendRequestSchema())
@querystring_schema(CreateSchemaTxnForEndorserOptionSchema())
@querystring_schema(SchemaConnIdMatchInfoSchema())
@response_schema(TxnOrSchemaSendResultSchema(), 200, description="")
@error_handler
async def schemas_send_schema(request: web.BaseRequest):
    """
    Request handler for creating a schema.

    Args:
        request: aiohttp request object

    Returns:
        The schema id sent

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile

    body = await request.json()

    my_public_info = None
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        my_public_info = await wallet.get_public_did()
    if not my_public_info:
        raise BadLedgerRequestError("Cannot publish schema without a public DID")

    options = {}

    issuer_id = my_public_info.did
    attr_names = body.get("attributes")
    name = body.get("schema_name")
    version = body.get("schema_version")

    issuer = AnonCredsIssuer(context.profile)
    result = await issuer.create_and_register_schema(
        issuer_id, name, version, attr_names, options=options
    )

    schema_id = result.schema_state.schema_id
    meta_data = {
        "context": {
            "schema_id": schema_id,
            "schema_name": result.schema_state.schema_value.name,
            "schema_version": result.schema_state.schema_value.version,
            "attributes": result.schema_state.schema_value.attr_names,
        },
        "processing": {},
    }
    schema_def = {
        "ver": "1.0",
        "ident": schema_id,
        "name": result.schema_state.schema_value.name,
        "version": result.schema_state.schema_value.version,
        "attr_names": result.schema_state.schema_value.attr_names,
        "seqNo": result.schema_metadata["seqNo"],
    }

    # Notify event
    await notify_schema_event(context.profile, schema_id, meta_data)
    return web.json_response(
        {
            "sent": {"schema_id": schema_id, "schema": schema_def},
            "schema_id": schema_id,
            "schema": schema_def,
        }
    )


@docs(
    tags=["schema"],
    summary="Search for matching schema that agent originated",
)
@querystring_schema(SchemaQueryStringSchema())
@response_schema(SchemasCreatedResultSchema(), 200, description="")
@error_handler
async def schemas_created(request: web.BaseRequest):
    """
    Request handler for retrieving schemas that current agent created.

    Args:
        request: aiohttp request object

    Returns:
        The identifiers of matching schemas

    """
    context: AdminRequestContext = request["context"]

    # this is a parameter, but not one we search by in anoncreds...
    # schema_id = request.query.get("schema_id")
    schema_issuer_did = request.query.get("schema_issuer_did")
    schema_name = request.query.get("schema_name")
    schema_version = request.query.get("schema_version")

    issuer = AnonCredsIssuer(context.profile)
    schema_ids = await issuer.get_created_schemas(
        schema_name, schema_version, schema_issuer_did
    )
    return web.json_response({"schema_ids": schema_ids})


@docs(tags=["schema"], summary="Gets a schema from the ledger")
@match_info_schema(SchemaIdMatchInfoSchema())
@response_schema(SchemaGetResultSchema(), 200, description="")
@error_handler
async def schemas_get_schema(request: web.BaseRequest):
    """
    Request handler for sending a credential offer.

    Args:
        request: aiohttp request object

    Returns:
        The schema details.

    """
    context: AdminRequestContext = request["context"]
    schema_id = request.match_info["schema_id"]

    anoncreds_registry = context.inject(AnonCredsRegistry)
    result = await anoncreds_registry.get_schema(context.profile, schema_id)

    # convert to expected type...
    schema = {
        "ver": "1.0",
        "id": result.schema_id,
        "name": result.schema.name,
        "version": result.schema.version,
        "attrNames": result.schema.attr_names,
        "seqNo": result.schema_metadata["seqNo"],
    }
    if result.resolution_metadata["ledger_id"]:
        return web.json_response(
            {"ledger_id": result.resolution_metadata["ledger_id"], "schema": schema}
        )
    else:
        return web.json_response({"schema": schema})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/schemas", schemas_send_schema),
            web.get("/schemas/created", schemas_created, allow_head=False),
            web.get("/schemas/{schema_id}", schemas_get_schema, allow_head=False),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "schema",
            "description": "Schema operations",
            "externalDocs": {
                "description": "Specification",
                "url": (
                    "https://github.com/hyperledger/indy-node/blob/master/"
                    "design/anoncreds.md#schema"
                ),
            },
        }
    )
