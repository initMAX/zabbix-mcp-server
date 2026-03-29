"""Shared parameter sets reused across API method definitions."""

from zabbix_mcp.api.types import ParamDef

# Standard parameters for all *.get methods
COMMON_GET_PARAMS: list[ParamDef] = [
    ParamDef(
        "output", "str",
        "Fields to return: 'extend' for all fields, 'count' for count only, "
        "or comma-separated field names (e.g. 'hostid,name,status')",
    ),
    ParamDef(
        "filter", "dict",
        "Return only results that exactly match the given filter. "
        "Object with field names as keys and single value or array of values to match. "
        "Example: {\"status\": 0} or {\"status\": [0, 1]}",
    ),
    ParamDef(
        "search", "dict",
        "Return results that match the given pattern (case-insensitive by default). "
        "Example: {\"name\": \"web\"} finds 'Web Server', 'my-web-app', etc.",
    ),
    ParamDef(
        "searchByAny", "bool",
        "If true, return results matching ANY search field (OR). Default is ALL fields (AND).",
    ),
    ParamDef(
        "searchWildcardsEnabled", "bool",
        "If true, enable * and ? wildcards in search patterns.",
    ),
    ParamDef(
        "limit", "int",
        "Maximum number of results to return.",
    ),
    ParamDef(
        "sortfield", "str",
        "Field name(s) to sort by. Can be comma-separated for multiple fields.",
    ),
    ParamDef(
        "sortorder", "str",
        "Sort order: 'ASC' (ascending) or 'DESC' (descending).",
    ),
    ParamDef(
        "countOutput", "bool",
        "Return the count of matching results instead of the actual data.",
    ),
]

# Standard parameters for *.create methods (accepts full object as dict)
CREATE_PARAMS: list[ParamDef] = [
    ParamDef(
        "params", "dict",
        "Object properties as a JSON dictionary. See Zabbix API docs for required/optional fields.",
        required=True,
    ),
]

# Standard parameters for *.update methods
UPDATE_PARAMS: list[ParamDef] = [
    ParamDef(
        "params", "dict",
        "Object properties to update as a JSON dictionary. Must include the object ID field.",
        required=True,
    ),
]

# Standard parameters for *.delete methods
DELETE_PARAMS: list[ParamDef] = [
    ParamDef(
        "ids", "list[str]",
        "Array of IDs to delete.",
        required=True,
    ),
]

# Standard parameters for mass operations
MASS_PARAMS: list[ParamDef] = [
    ParamDef(
        "params", "dict",
        "Mass operation parameters as a JSON dictionary. "
        "Must include the object IDs and the properties to add/remove/update.",
        required=True,
    ),
]
