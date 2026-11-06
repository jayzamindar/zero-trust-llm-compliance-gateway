from pydantic import BaseModel, ConfigDict, Field


class GatewayRequest(BaseModel):
    """
    Data contract for incoming LLM gateway requests in a Zero-Trust architecture.

    Strictly requires non-empty `prompt`, `session_id`, and `user_id`.
    Rejects any unexpected / extra fields to prevent injection or parameter tampering.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    prompt: str = Field(
        ...,
        min_length=1,
        description="The prompt text submitted for compliance checks and LLM processing.",
        json_schema_extra={"examples": ["Analyze the following transaction for compliance."]},
    )
    session_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for the session to maintain audit trails.",
        json_schema_extra={"examples": ["sess_9f8c12a4-72b1-4b19-94b1-8b09d2e1c9a1"]},
    )
    user_id: str = Field(
        ...,
        min_length=1,
        description="Authenticated identity or subject issuing the request.",
        json_schema_extra={"examples": ["usr_secops_4021"]},
    )
    project_id: str = Field(
        default="default_project",
        min_length=1,
        description="Project, workspace, or organizational tier identifier for budget and rate limit tracking.",
        json_schema_extra={"examples": ["proj_enterprise_01"]},
    )


# Common aliases for interoperability
ComplianceGatewayRequest = GatewayRequest
ComplianceRequest = GatewayRequest

