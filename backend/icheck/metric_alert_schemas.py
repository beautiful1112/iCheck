"""Enrollment-bound thresholds; Prometheus is the only metric evaluator."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, field_validator


class StrictModel(BaseModel):
    model_config=ConfigDict(extra="forbid",from_attributes=True)


class MetricRuleDefinition(StrictModel):
    contract:Literal["icheck.metric-rule/v1"]="icheck.metric-rule/v1"
    name:str=Field(min_length=1,max_length=128)
    backend_id:str=Field(pattern=r"^[0-9a-f-]{36}$")
    enrollment_id:str=Field(pattern=r"^[0-9a-f-]{36}$")
    metric:str=Field(pattern=r"^[A-Za-z_:][A-Za-z0-9_:]{0,127}$")
    measurement:Literal["value","rate"]="value"
    rate_window_seconds:int=Field(default=300,ge=60,le=3600,strict=True)
    aggregation:Literal["min","max","avg","sum"]="max"
    comparison:Literal[">",">=","<","<=","==","!="]=">"
    threshold:FiniteFloat
    hold_seconds:int=Field(default=60,ge=0,le=3600,strict=True)
    severity:Literal["info","warning","critical"]="warning"
    enabled:bool=True

    @field_validator("threshold",mode="before")
    @classmethod
    def numeric(cls,value):
        if isinstance(value,bool): raise ValueError("Threshold must be a finite number")
        return value

    @field_validator("name")
    @classmethod
    def plain_name(cls,value):
        if any(ord(c)<32 or ord(c)==127 for c in value) or "{{" in value or "}}" in value:
            raise ValueError("Rule name must be plain text, not a Prometheus template")
        return value


class MetricRulePreview(StrictModel):
    definition:MetricRuleDefinition
    rule_id:str|None=Field(default=None,pattern=r"^[0-9a-f-]{36}$")
    expected_revision:int=Field(default=0,ge=0,strict=True)


class MetricRuleConfirm(StrictModel):
    confirm:Literal[True]
    expected_plan_hash:str=Field(pattern=r"^[0-9a-f]{64}$")


class AlertmanagerAlert(StrictModel):
    status:Literal["firing","resolved"]
    labels:dict[str,str]
    annotations:dict[str,str]=Field(default_factory=dict)
    startsAt:datetime
    endsAt:datetime
    generatorURL:str=Field(default="",max_length=2048)
    fingerprint:str=Field(default="",max_length=128)

    @field_validator("labels","annotations")
    @classmethod
    def bounded_fields(cls,value):
        if len(value)>64 or any(len(k)>128 or len(v)>4096 for k,v in value.items()):
            raise ValueError("Notification labels or annotations exceed their bounds")
        return value

    @field_validator("startsAt","endsAt")
    @classmethod
    def aware(cls,value):
        if value.tzinfo is None: raise ValueError("Notification times must include a timezone")
        return value


class AlertmanagerWebhook(StrictModel):
    version:Literal["4"]
    receiver:str=Field(min_length=1,max_length=128)
    status:Literal["firing","resolved"]
    alerts:list[AlertmanagerAlert]=Field(min_length=1,max_length=100)
    groupLabels:dict[str,str]=Field(default_factory=dict)
    routeLabels:dict[str,str]=Field(default_factory=dict)
    commonLabels:dict[str,str]=Field(default_factory=dict)
    commonAnnotations:dict[str,str]=Field(default_factory=dict)
    externalURL:str=Field(default="",max_length=2048)
    groupKey:str=Field(default="",max_length=2048)
    notification_reason:str=Field(default="",max_length=128)
    truncatedAlerts:int=Field(default=0,ge=0,strict=True)
    @field_validator("groupLabels","routeLabels","commonLabels","commonAnnotations")
    @classmethod
    def bounded_fields(cls,value):
        return AlertmanagerAlert.bounded_fields(value)
