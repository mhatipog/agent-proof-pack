"""Strict PostgreSQL value canonicalization for the independent effect witness.

PG-aware values become tagged text before entering the existing HMAC encoder.
The observed PostgreSQL column type is itself included in the signed schema
fingerprint. No floats are used for NUMERIC and no local timezone is assumed.
Unsupported column types fail at schema discovery, including all-NULL columns.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import re
from uuid import UUID

from .effect import EffectError, MAX_VALUE_BYTES

_VARCHAR = re.compile(r"^(?:character varying|character)(?:\([0-9]+\))?$")
_NUMERIC = re.compile(r"^numeric(?:\([0-9]+(?:,[0-9]+)?\))?$")
_TIMESTAMPTZ = re.compile(r"^timestamp(?:\([0-9]+\))? with time zone$")
_SIMPLE = {
    "smallint", "integer", "bigint", "real", "double precision",
    "text", "bytea",
}


def pg_type_kind(type_name: str) -> str:
    """Whitelist PostgreSQL built-in types that have lossless HMAC encodings."""
    if not isinstance(type_name, str):
        raise EffectError("invalid PostgreSQL column type")
    declared = type_name.lower().strip()
    if declared in _SIMPLE or _VARCHAR.fullmatch(declared):
        return "simple"
    if declared == "uuid":
        return "uuid"
    if _NUMERIC.fullmatch(declared):
        return "numeric"
    if declared == "boolean":
        return "boolean"
    if _TIMESTAMPTZ.fullmatch(declared):
        return "timestamptz"
    raise EffectError("unsupported PostgreSQL column type")


def _decimal_tag(value: Decimal) -> str:
    if not value.is_finite():
        raise EffectError("non-finite PostgreSQL numeric")
    sign, digits, exponent = value.as_tuple()
    if not any(digits):
        return "pg:numeric:0"
    digits = list(digits)
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    # Decimal.normalize() would round under the caller's decimal context.
    number = ("-" if sign else "") + "".join(map(str, digits))
    result = f"pg:numeric:{number}e{exponent}"
    if len(result.encode("utf8")) > MAX_VALUE_BYTES:
        raise EffectError("oversized PostgreSQL numeric")
    return result


def normalize_pg_value(value, type_name: str, *, from_contract: bool = False):
    """Canonicalize one typed PG value; reject approximate/ambiguous contracts.

    For supported legacy SQL scalar types, retain the previous HMAC encoding.
    Contracts express numeric as a JSON *string*, UUID as a canonical UUID
    string, boolean as a JSON boolean, and timestamptz as an offset-aware ISO
    string. Values from Psycopg use Decimal/UUID/bool/aware datetime.
    """
    kind = pg_type_kind(type_name)
    if value is None:
        return None
    if kind == "simple":
        return value
    if kind == "uuid":
        if from_contract:
            if not isinstance(value, str) or not re.fullmatch(
                    r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", value):
                raise EffectError("UUID contract value must use canonical hyphenated form")
        elif not isinstance(value, UUID):
            raise EffectError("unexpected PostgreSQL UUID representation")
        try:
            return "pg:uuid:" + str(UUID(str(value)))
        except (ValueError, AttributeError) as exc:
            raise EffectError("invalid PostgreSQL UUID") from exc
    if kind == "numeric":
        if from_contract:
            if not isinstance(value, str) or len(value) > MAX_VALUE_BYTES or not re.fullmatch(
                    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value):
                raise EffectError("numeric contract value must be a finite decimal string")
            try:
                number = Decimal(value)
            except InvalidOperation as exc:
                raise EffectError("invalid PostgreSQL numeric contract") from exc
        else:
            if not isinstance(value, Decimal):
                raise EffectError("unexpected PostgreSQL numeric representation")
            number = value
        return _decimal_tag(number)
    if kind == "boolean":
        if type(value) is not bool:
            raise EffectError("PostgreSQL boolean requires a JSON boolean")
        return "pg:boolean:true" if value else "pg:boolean:false"
    if kind == "timestamptz":
        if from_contract:
            if not isinstance(value, str) or len(value) > 64:
                raise EffectError("timestamptz contract requires an ISO string with offset")
            try:
                parsed = datetime.fromisoformat(
                    value[:-1] + "+00:00" if value.endswith("Z") else value)
            except ValueError as exc:
                raise EffectError("invalid PostgreSQL timestamptz contract") from exc
        else:
            if not isinstance(value, datetime):
                raise EffectError("unexpected PostgreSQL timestamptz representation")
            parsed = value
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise EffectError("PostgreSQL timestamptz requires an explicit timezone")
        return "pg:timestamptz:" + parsed.astimezone(timezone.utc).isoformat(
            timespec="microseconds")
    raise EffectError("unhandled PostgreSQL type")
