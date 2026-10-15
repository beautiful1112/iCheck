"""System/container exporters reuse the declarative Studio template contract."""
from pydantic import BaseModel,ConfigDict,Field
from ..collector_schemas import ArtifactCreate
from ..exporter_metrics import CATALOG,PROTOCOLS,DEFAULT_PORTS,ExporterMonitorSpec,spec_hash,document
from ..models import ArtifactKind
from .http_monitoring_templates import SCHEMA,PERMISSIONS

DEPENDENCIES=["native-exporter","icheck-monitoring-gateway","prometheus","grafana"]


class ExporterTemplateDefinition(BaseModel):
    model_config=ConfigDict(extra="forbid")
    schema_version:str=Field(alias="schema",pattern=r"^icheck\.monitoring-template/v1$")
    plugin:str=Field(pattern=r"^(linux|windows|containers|vmware)$")
    exporter_monitor:ExporterMonitorSpec
    port:int=Field(ge=1,le=65535)
    unsupported_metrics:list[str]=Field(default_factory=list,max_length=32)
    required_permissions:list[str]
    dependencies:list[str]


def input_context(intent):
    request=ExporterMonitorSpec(plugin=intent.plugin,groups=["disk"] if intent.vmware_scope=="datastores" else ["cpu"],scheme=intent.scheme,
        server_name=intent.server_name,auth_mode=intent.auth_mode,container_id=intent.container_id,container_name=intent.container_name,
        vmware_scope=intent.vmware_scope,vmware_name=intent.vmware_name,vmware_datacenter=intent.vmware_datacenter)
    return {**intent.model_dump(),"port":intent.port or DEFAULT_PORTS[intent.plugin],
        "catalog":request.catalog(),"request":document(request)}


def studio_input(session):
    for message in session.messages:
        value=(message.structured_content or {}).get("exporter_monitoring_input") if message.role=="system" else None
        if isinstance(value,dict): return value
    return None


def artifact_payload(session,spec,*,actor):
    context=studio_input(session)
    monitor=ExporterMonitorSpec.model_validate({**context["request"],"groups":spec.groups})
    adapter=PROTOCOLS[monitor.plugin]
    return ArtifactCreate(name=spec.artifact_name,kind=ArtifactKind.COLLECTOR,description=spec.description,owner=actor,
        labels={"plugin":monitor.plugin,"monitoring_template":True},initial_version={"created_by":actor,
            "definition":{"schema":SCHEMA,"plugin":monitor.plugin,"port":context["port"],"exporter_monitor":document(monitor),
                "unsupported_metrics":spec.unsupported_metrics,"required_permissions":PERMISSIONS,"dependencies":DEPENDENCIES},
            "implementation":{"runtime":"prometheus_gateway_v1","adapter":adapter},"tests":[],"collector_definition":{
                "adapter_type":adapter,"mode":"poll","output_kinds":["observation"],"defaults":{},
                "config_schema":{"type":"object","additionalProperties":False},"target_schema":{"type":"object",
                    "additionalProperties":False,"properties":{"device_id":{"type":"string"},"connection_id":{"type":"string"}},
                    "required":["device_id","connection_id"]}}})


def validate_contract(definition,implementation,tests,collector):
    parsed=ExporterTemplateDefinition.model_validate(definition)
    adapter=PROTOCOLS[parsed.plugin]
    if (parsed.exporter_monitor.plugin!=parsed.plugin or implementation!={"runtime":"prometheus_gateway_v1","adapter":adapter}
            or collector is None or collector.adapter_type!=adapter or collector.defaults or collector.credential_profile_ref
            or collector.mode.value!="poll" or collector.output_kinds!=["observation"] or tests
            or parsed.required_permissions!=PERMISSIONS or parsed.dependencies!=DEPENDENCIES):
        raise ValueError("Native exporter template must use its declarative platform contract, not generated code or credentials")
    return {"runtime":"prometheus_gateway_v1","plugin":parsed.plugin,"adapter":adapter,"validation_level":"schema",
        "metric_names":list(parsed.exporter_monitor.metrics()),"collectors":parsed.exporter_monitor.collectors(),
        "spec_hash":spec_hash(parsed.exporter_monitor),"unsupported_metrics":parsed.unsupported_metrics,
        "live_target_tested":False,"continuous_collection_enabled":False}


def configuration(monitor,version_id):
    return {"exporter_monitor":document(monitor),"monitoring_template_version_id":version_id}


def evidence_matches(connection,profile,*,evidence=None):
    monitor=ExporterMonitorSpec.model_validate(connection.configuration["exporter_monitor"])
    proof=connection.last_verification_evidence if evidence is None else evidence
    if monitor.plugin=="vmware":
        if (proof.get("vmware_scope")!=monitor.vmware_scope or proof.get("vmware_name")!=monitor.vmware_name
                or not isinstance(proof.get("vmware_datacenter"),str) or not 1<=len(proof["vmware_datacenter"])<=255
                or (monitor.vmware_datacenter is not None and proof["vmware_datacenter"]!=monitor.vmware_datacenter)
                or proof.get("labels_filtered") is not True or proof.get("source_timestamp_available") is not False
                or proof.get("sample_freshness_scope")!="gateway_receipt"):
            return False
    if monitor.plugin=="containers":
        identifiers=proof.get("container_ids",[])
        if (not isinstance(identifiers,list) or not 1<=len(identifiers)<=32
                or any(not isinstance(identifier,str) or not identifier or identifier=="/" or len(identifier)>512 for identifier in identifiers)
                or len(set(identifiers))!=len(identifiers) or proof.get("container_count")!=len(identifiers)
                or proof.get("source_timestamps_preserved") is not True or proof.get("labels_filtered") is not True
                or (monitor.container_id and identifiers!=[monitor.container_id])):
            return False
    return (proof.get("check")=="native_exporter_metric_query" and proof.get("success") is True
        and proof.get("spec_hash")==spec_hash(monitor) and proof.get("metric_names")==sorted(monitor.metrics())
        and proof.get("collectors")==monitor.collectors() and proof.get("collector_success") is True
        and proof.get("target_host")==connection.device.management_ip and proof.get("target_port")==connection.port
        and isinstance(proof.get("metric_samples"),int) and not isinstance(proof["metric_samples"],bool)
        and proof["metric_samples"]>=len(monitor.metrics())
        and (monitor.scheme!="https" or proof.get("tls_tested") is True)
        and (monitor.auth_mode=="none" or (profile is not None and profile.provider=="managed_device"
            and proof.get("authentication_tested") is True and proof.get("credential_revision")==profile.revision)))
