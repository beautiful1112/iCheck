# Topology View Designer and Published Runtime

## Implemented boundary

Capability Studio can author and publish an immutable
`icheck.topology/v1` definition through conversation. A topology definition is
declarative: it selects device, endpoint, or generic knowledge node types;
device kinds, generic entity/relationship types, and sites; wired/Wi-Fi/IP or
generic edges; grouping, layout, and bounded node/edge limits. It contains no
query language or generated executable code.

The `/studio` workspace renders a graph preview beside the conversation before
human publication. Refinement creates another immutable Artifact version; it
does not mutate the current published version. The dedicated `/topology`
operator page runs the currently published version against current normalized
inventory; it never treats the validation preview as live data.

An Investigation can also request the strict
`icheck.topology-proposal/v1` output contract. The completed result must cite
persisted evidence from the same Investigation and contain a valid
`GeneratedTopologySpec`. iCheck validates its selectors and bounded preview
under the Investigation's frozen authorization scope, then stores it as a
proposal rather than an active view. `/studio/proposals` is a dedicated global
review queue. Publishing requires a human reason and atomically creates,
validates, and publishes an ordinary immutable `icheck.topology/v1` Artifact;
rejection also requires a reason and creates no Artifact.

## Data minimization and trust boundary

```text
operator intent + aggregate inventory dimensions
                         |
                         v
        governed structured model route
                         |
                         v
             GeneratedTopologySpec
                         |
                         v
 selectors checked against current kinds/sites and hard limits
                         |
                         v
 platform-owned inventory projection + bounded preview
                         |
                         v
        validated draft --human publish--> published version
```

The model catalog contains only counts and distinct device kinds, generic
entity/relationship types, and sites. Device names, external keys, IP
addresses, MAC addresses, endpoint usernames, normalized attributes, and raw
collector payloads are not sent to the model. After structured generation, the
trusted platform resolves the view against current knowledge.

Preview nodes may contain the device or endpoint display label and MAC address;
IP relationships may contain the observed address because those are the
operator-visible purpose of this view. Endpoint usernames and unstructured
`raw_data` are never projected. The preview is stored as validation evidence on
the globally governed Artifact version and is therefore visible only through
the Capability Studio authorization boundary.
Investigation proposal previews use the same minimized fields but are further
restricted by the Investigation authorization snapshot. A site-scoped proposal
cannot validate another site's selector or include that site's nodes. Only a
globally scoped `capabilities.read/manage` reviewer can read or decide the
proposal queue.
Generic nodes expose display name, type, site, status, and external key;
generic edges expose type and direction. Arbitrary generic `attributes` remain
outside the stored topology preview.

The same minimization is applied again at runtime. Runtime responses contain
only the platform-owned node/edge fields declared by
`icheck.topology/v1`; arbitrary Entity/Relationship attributes and source
payloads cannot pass through the response schema.

## Current relationship sources

The deterministic renderer reads the existing normalized inventory tables:

- devices and endpoints become nodes;
- current wired attachments become `wired_attachment` edges;
- current wireless-controller associations become `wireless_association`
  edges; and
- current endpoint IP observations become `ip_observation` edges associated
  with their observing device;
- `icheck.knowledge.entity/v1` records become `knowledge_entity` nodes; and
- `icheck.knowledge.relationship/v1` records become
  `knowledge_relationship` edges; and
- `icheck.network.device-adjacency-snapshot/v1` records from the built-in
  SNMP topology pack become active `network.l2_neighbor.lldp` or
  `network.l2_neighbor.cdp` generic relationships, with parallel physical
  ports kept in minimized internal attributes rather than exposed as raw
  collector payload.

Validation uses stricter preview ceilings of 100 nodes and 200 edges, even when
the stored definition requests a higher runtime bound. Empty selectors fail
closed. The view definition itself allows no more than 500 nodes and 1,000
edges.

## Published runtime and scope

```text
current published topology ArtifactVersion
                    |
        canonical contract revalidation
                    |
       current normalized inventory query
                    |
 assets.read + principal device/site SQL scope
                    |
      bounded minimized nodes and edges
                    |
             /topology operator page
```

Runtime discovery lists only `published` Topology versions. Draft, validated,
deprecated, or drifted contracts do not run. Every render rechecks the
canonical definition, implementation, test contract, content hash, and
publication provenance before querying inventory. A requested historical
version must still be the current published version; the runtime never silently
runs a deprecated contract.

`GET /api/v1/topology/views/{artifact_id}/render` applies the authenticated
principal's device/site scope in the device, endpoint, generic entity, and
generic relationship SQL queries. Edges are then restricted to the already
selected node IDs. A scoped user with no matching inventory receives a valid
empty graph. The response does not reveal whether matching objects exist in a
different scope.

The runtime uses the Artifact's declared bounds, capped by the contract-wide
500-node/1,000-edge ceilings. `nodes_truncated` and `edges_truncated` make a
bounded result explicit. Refresh resolves current database state; it does not
modify or republish the view.

## API and governance

Create a session with:

```text
POST /api/v1/capability-studio/sessions/topologies
```

Generation, conversational refinement, inspection, and publication use the
shared Capability Studio session endpoints. The same global-scope
`capability_author` policy, governed `capability.authoring` model route,
token accounting, prompt-hash audit, immutable Artifact lifecycle, and explicit
human publish gate apply.

Operator runtime APIs require `assets.read` and object scope rather than the
global capability-author permission:

```text
GET /api/v1/topology/views
GET /api/v1/topology/views/{artifact_id}/render
GET /api/v1/topology/views/{artifact_id}/render?version={published_version}
GET /api/v1/topology/views/{artifact_id}/render?situation_id={authorized_situation}
```

When `situation_id` is present, the runtime first derives the bounded,
authorization-scoped Situation impact node set. Those durable IDs become an
additional filter inside every device, endpoint, and generic-entity query. The
published Artifact still controls node/edge types, selectors, layout, and hard
limits. The response includes the Situation ID, root node, queue state, and the
explicit `deterministic_context_not_root_cause` boundary. `alerts.read` is
required in addition to `assets.read`; an out-of-scope Situation returns `404`.

The `/topology` page provides published-view selection, deterministic force,
hierarchical, or radial rendering, client-side node search, safe selected-node
identity, immutable version/hash provenance, scope state, truncation warnings,
and explicit unpublished/empty/error states. Raw terminal tables remain on the
Assets page rather than being duplicated on the AI L1 home.

## Deliberate limitations

This slice is a deterministic published live-view runtime, not yet a complete
topology intelligence system. The built-in SNMP adjacency pack now supplies a
vendor-neutral LLDP/CDP snapshot contract with safe link closure. It does not
yet include:

- prevalidated SNMP Exporter generator modules for every switch/router vendor
  or live-lab compatibility claims; the seeded adjacency policy can now be
  activated beside SNMP metrics from one verified web device connection;
- scored service/business impact and AI-inferred causal reasoning (bounded
  deterministic Situation context paths are implemented);
- server-pushed automatic refresh or investigation-driven dynamic view
  generation and save-as-Artifact;
- temporal topology replay, topology-specific rollout health/canaries, or
  automatic rollback. Generic Artifact diff, signed import/export, and
  immutable restore-candidate controls already apply.

Those capabilities require broader collection packs and M4 situation
intelligence rather than embedding protocol-specific discovery in the Studio.
