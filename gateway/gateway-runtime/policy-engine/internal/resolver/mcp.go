/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/wso2/api-platform/common/chainkey"
)

// MCPResolverName is the registered name of the MCP resolver, matching the
// resolver_name the controller emits on an MCP proxy's POST route.
const MCPResolverName = "mcp"

// mcpEnrichOnlyOperation is the operation component every MCP chain key carries today.
//
// It is a constant because this resolver is *enrich-only*: one policy chain per route,
// exactly as MCP ships now, with the resolver contributing facts rather than selecting
// between chains. A composed key is still required — validateResolvedKey rejects a
// protocol resolver that returns the route key — so the key is composed from the
// captured partition with a fixed operation.
//
// Per-operation chains ("tools/call:get_weather") are the natural next step and are the
// only thing that changes here when they are taken up.
const mcpEnrichOnlyOperation = "mcp"

// Attribute keys this resolver publishes. Every key is prefixed mcp.body. because MCP
// 2026-07-28 carries the same facts in both headers and the body, and the two
// disagreeing is a security-relevant condition (JSON-RPC -32020) rather than a detail.
// A consumer comparing the two sides must never be in doubt which side it holds.
//
// There is deliberately no mcp.header.* group: headers already reach every policy
// through RequestHeaderContext, and copying them here would create a second source of
// truth for a value that already has one.
const (
	AttrMCPBodyMethod           = "mcp.body.method"
	AttrMCPBodyCapabilityType   = "mcp.body.capability.type"
	AttrMCPBodyCapabilityAction = "mcp.body.capability.action"
	AttrMCPBodyCapabilityName   = "mcp.body.capability.name"
	AttrMCPBodyProtocolVersion  = "mcp.body.protocol.version"
	// AttrMCPBodyJSONRPCID carries the id as a JSON *token*, not a display string: 7 for a
	// number and "7" with its quotes for a string. A consumer echoes it into an error
	// envelope verbatim; unwrapping it would lose the type a client correlates on.
	AttrMCPBodyJSONRPCID = "mcp.body.jsonrpc.id"

	// The client that sent the request, which MCP states in a different place in each era:
	// params.clientInfo on a legacy initialize, params._meta on every modern request. Both
	// publish here, so a consumer never branches on era to learn who is calling.
	//
	// Telemetry only. The spec is explicit that clientInfo is self-reported, unverified, and
	// "intended for display, logging, and debugging" — implementations SHOULD NOT use it to
	// change behaviour or rely on it for security decisions. No policy may govern on these.
	AttrMCPBodyClientName    = "mcp.body.client.name"
	AttrMCPBodyClientVersion = "mcp.body.client.version"

	// AttrMCPBodyRequestStateHash fingerprints the opaque requestState a client echoes back
	// when it retries a request the server answered with input_required. It correlates the
	// retry with that answer, which nothing else can: the spec requires the JSON-RPC id to
	// DIFFER between the two, since they are independent requests.
	//
	// Hashed, not published raw, for two reasons. The value is a capability a log reader
	// could replay, and the spec has servers encode a principal, a TTL and a request digest
	// into it. And a realistic AEAD blob exceeds the kernel's 256-character attribute limit,
	// so the raw value would be dropped for length and the fact lost without a trace.
	AttrMCPBodyRequestStateHash = "mcp.body.request.state.hash"

	// AttrMCPBodyPresent reports that a request body was there — nothing more. Its value is
	// always "true": the key's presence is the fact.
	//
	// It exists because the facts alone cannot distinguish two states that both publish
	// nothing. A client-posted JSON-RPC *response* carrying neither an id nor a _meta
	// version is read perfectly and names no operation; a request that arrived with no body
	// was never read at all. Without this key both are the empty set, and a consumer cannot
	// tell "the body says there is no operation" — authoritative, and the same answer a
	// resolver-less gateway reaches by parsing — from "there is nothing to go on", where it
	// has to fail closed.
	//
	// It is published on every path where bytes arrived, AttrMCPBodyUnusable included.
	// Whether a body was there and whether it could be read are different questions, and
	// only the second is what "instead of the facts" governs: publishing a *method* taken
	// from a body that reads two ways is the confused-deputy vector, while publishing that
	// bytes existed reveals nothing about what they said. Keeping them orthogonal means a
	// consumer testing "was there anything to go on" never has to check the reason first.
	//
	//	absent                     no body
	//	present                    a body, read fine — facts follow if it named any
	//	present + unusable         a body, and this resolver could not read it
	AttrMCPBodyPresent = "mcp.body.present"

	// AttrMCPBodyUnusable reports that the resolver could not extract a JSON-RPC envelope
	// from the body, and why. Its values are the MCPBodyUnusable* constants below.
	//
	// The rule it encodes: the resolver reports when it could not READ the body, not when
	// the body had little in it. A bodyless request, or an object naming no method, is
	// read successfully and simply names no operation — no reason is published for those.
	// Such a body may still publish the facts that do not depend on the method, and an
	// object always publishes AttrMCPBodyPresent, which is what separates it from a
	// request that carried no body — see attributes.
	//
	// It exists because "published nothing" is otherwise indistinguishable from "never
	// read the body", which cost the released behaviour: mcp-auth, mcp-authz and
	// mcp-ratelimit all rejected an unreadable body outright, and after the parse moved
	// here nothing did.
	//
	// It is a fact *about reading* the body rather than a value read *from* it, and it is
	// published INSTEAD of the facts, never alongside them: reporting a method taken from a
	// body that reads two ways is the whole problem. "Instead of the facts" does not
	// extend to AttrMCPBodyPresent, which is also about the body rather than from it and is
	// published here too — see its doc.
	AttrMCPBodyUnusable = "mcp.body.unusable"
)

// Reasons for AttrMCPBodyUnusable. A closed set, so the attribute stays span-safe.
//
// They are split along the same line the released MCP policies split their JSON-RPC error
// codes: broken syntax was a parse error (-32700), everything else an invalid request
// (-32600). Reporting one undifferentiated "malformed" would force a consumer to answer
// -32700 for a request that merely used the wrong type, which is not what clients saw
// before.
const (
	// MCPBodySyntaxError is a body whose JSON does not parse — almost always truncation,
	// e.g. `{"id":1,"method":"tools/call"` with no closing brace, or a trailing comma.
	// Maps to JSON-RPC -32700.
	MCPBodySyntaxError = "syntax-error"

	// MCPBodyInvalidMemberType is well-formed JSON in which a member this resolver reads
	// carries the wrong type: `{"method":42}`, `{"method":["a"]}`, or a non-object
	// `_meta`. The document is fine; one of its values is not what it must be.
	//
	// Only members that are modelled can cause this. `params` and `id` are held raw
	// precisely so their shape cannot fail the envelope — JSON-RPC permits `"params":[]`,
	// and rejecting it would discard a perfectly readable method over an unrelated field.
	// Maps to JSON-RPC -32600.
	MCPBodyInvalidMemberType = "invalid-member-type"

	// MCPBodyNotAnObject is valid JSON that is not a request object at all — a JSON-RPC
	// batch, which names several operations and therefore identifies none, or a bare
	// scalar. Maps to JSON-RPC -32600.
	MCPBodyNotAnObject = "not-an-object"

	// MCPBodyAmbiguous is an object naming a member this resolver reads in more than one
	// way. Unlike the others, a backend may not reject it — it may simply resolve a
	// different value than the gateway did, which is the confused-deputy vector. Maps to
	// JSON-RPC -32600.
	MCPBodyAmbiguous = "ambiguous"
)

// spanSafeAttributes is the subset of published attributes that may be stamped on a
// trace span. The rule is closed sets only: a span attribute is indexed by the tracing
// backend, so a caller-chosen value mints one index entry per distinct value.
//
// mcp.body.capability.name is excluded because a tool name is an open set, and
// mcp.body.jsonrpc.id because it is unique per request — the worst possible span
// attribute. Both remain available to policies, which can bound them for their own use.
//
// A future resolver publishing attributes adds its own span-safe keys here.
var spanSafeAttributes = map[string]bool{
	AttrMCPBodyMethod:           true,
	AttrMCPBodyCapabilityType:   true,
	AttrMCPBodyCapabilityAction: true,
	AttrMCPBodyProtocolVersion:  true,
	// A closed set of three reasons, and the attribute an operator would most want to
	// alert on: a rising count means someone is probing the parser.
	AttrMCPBodyUnusable: true,

	// AttrMCPBodyPresent is deliberately absent. It is a closed set and so would pass the
	// rule above, but its value is always "true" — a span attribute with one possible
	// value carries no information and only costs an index entry.
	//
	// AttrMCPBodyRequestStateHash is absent: one value per exchange is unbounded cardinality,
	// and a correlation token is not a span facet.
	//
	// AttrMCPBodyClientName and AttrMCPBodyClientVersion are absent on the spec's own terms:
	// clientInfo is self-reported and unverified, so indexing it would invite exactly the
	// reliance the spec warns against. Unbounded cardinality is the second reason, not the
	// first, and is why AttrMCPBodyCapabilityName is absent too.
}

// IsSpanSafeAttribute reports whether an attribute key may be recorded on a span.
// Unknown keys are not span-safe: a new attribute must be reasoned about before it is
// indexed, rather than inheriting permission by default.
func IsSpanSafeAttribute(key string) bool { return spanSafeAttributes[key] }

// mcpMetaProtocolVersionKey is where a modern request states its protocol version
// inside _meta. MCP namespaces its reserved _meta members, so the slash is part of the
// key rather than a path separator.
const mcpMetaProtocolVersionKey = "io.modelcontextprotocol/protocolVersion"

// mcpMetaClientInfoKey is the same for the client's identity, which 2026-07-28 moved out of
// the initialize handshake and into per-request _meta.
const mcpMetaClientInfoKey = "io.modelcontextprotocol/clientInfo"

// mcpCapabilityTypes maps a method's family segment to the singular capability type.
//
// Singular is chosen deliberately: two of the five MCP policies already write a plural
// form into SharedContext.Metadata and two write singular, and this canonical set has to
// pick one rather than inherit the split.
// mcpCapabilityTypeResource is called out because it is the one family MCP identifies by uri
// rather than by name — see capabilityName.
const mcpCapabilityTypeResource = "resource"

var mcpCapabilityTypes = map[string]string{
	"tools":         "tool",
	"resources":     mcpCapabilityTypeResource,
	"prompts":       "prompt",
	"completion":    "completion",
	"logging":       "logging",
	"notifications": "notification",
	"subscriptions": "subscription",
	"sampling":      "sampling",
	"elicitation":   "elicitation",
	"roots":         "roots",
	"server":        "server",
}

// MCPResolver is the resolver factory for MCP proxy routes.
//
// It exists to parse the JSON-RPC request body once, before the policy chain runs, so
// that the five MCP policies and the analytics system policy stop unmarshalling the same
// bytes up to six times per request.
//
// One factory serves both MCP eras and prepares them identically: every MCP route reads
// the body. A modern request mirrors its method and capability name into headers, but the
// body remains the side the gateway derives facts from, so that a policy governing on the
// mirrored headers has something to check them against and the two eras are governed the
// same way.
//
// The route carries no resolver configuration. Anything the controller emits under
// resolver_config is ignored here, which keeps a future controller field from failing a
// route on an engine that predates it.
type MCPResolver struct{}

// Name returns the wire value the controller emits for MCP routes.
func (*MCPResolver) Name() string { return MCPResolverName }

// Prepare builds one MCP route's resolver.
//
// Everything that can be decided at ingest is decided here: the chain key is composed
// once, and the body requirement is fixed for the life of the route. A request then costs
// a parse and a map build.
func (*MCPResolver) Prepare(cfg ResolverRouteConfig) (PreparedResolver, error) {
	if !chainkey.ValidComponent(cfg.APIID) {
		// Composing a key from an empty or separator-bearing API id would produce a key
		// that either fails partition validation or, worse, reaches another partition.
		// Reject the route at ingest instead of per request.
		return nil, fmt.Errorf("mcp resolver requires a valid API id, got %q", cfg.APIID)
	}

	return &preparedMCP{chainKey: ChainKeyFor(cfg.APIID, cfg.Vhost, mcpEnrichOnlyOperation)}, nil
}

// preparedMCP is an MCP route whose request body is parsed once, before the chain runs,
// and whose findings are published for policies to read.
//
// Every MCP route prepares this way, legacy or modern. A modern request also carries its
// method and capability name in headers, but those are not what this resolver reads:
// publishing header-derived facts would give a consumer two sources for one value with no
// way to tell them apart, and the disagreement between them is a security condition
// (JSON-RPC -32020) rather than a detail. Headers already reach every policy through
// RequestHeaderContext; the body is what needs reading once on their behalf.
//
// Attributes are therefore published on every MCP route. An empty ResolutionAttributes
// means the route has no MCP resolver on it at all — not that the resolver chose not to
// read. When the body was read and could not be interpreted, that is reported explicitly
// under AttrMCPBodyUnusable.
type preparedMCP struct {
	chainKey string
}

// Requirements asks for the buffered body, which makes the kernel defer chain selection
// to the request-body callback. Header-phase policies then run there too, after the body
// has been read — which is the only way a body-derived fact can reach OnRequestHeaders.
func (*preparedMCP) Requirements() RequestRequirements {
	return RequestRequirements{Body: BodyBuffered}
}

// Resolve inspects the MCP request body and publishes the facts needed by the
// policy chain.
//
// The chain key is fixed for this prepared route; the body is used only to
// extract MCP metadata such as the method, capability name/URI, ID, and _meta.
//
// A body that is empty or contains no relevant MCP fields is valid and produces
// no attributes. A body that cannot be safely interpreted is also not returned
// as a resolver error. Instead, Resolve publishes AttrMCPBodyUnusable with one
// of the following reasons:
//
//   - MCPBodyNotAnObject: the JSON value is not a single request object
//   - MCPBodyAmbiguous: duplicate/case-variant members make interpretation unsafe
//   - MCPBodySyntaxError: the body is malformed JSON
//   - MCPBodyInvalidMemberType: the JSON is valid but a member the resolver reads
//     carries the wrong type
//
// Body problems are reported through attributes rather than errors so the
// selected policy chain still runs and MCP policies can return the appropriate
// JSON-RPC error shape.
//
// Ambiguous members are checked before json.Unmarshal because encoding/json can
// collapse duplicate matching fields and lose the evidence of ambiguity.
//
// A nil or empty body is allowed because a request whose headers are end-of-stream gets no body callback at all,
// so a BodyBuffered resolver is called with Body nil (extproc.go). Handled as "read fine,
// nothing to take" rather than as a fault.
func (p *preparedMCP) Resolve(_ context.Context, view RequestView) (Resolution, error) {
	res := Resolution{ChainKey: p.chainKey}

	body := trimLeadingSpace(view.Body)
	if len(body) == 0 {
		// Nothing to read, which is not the same as failing to read. Legitimate for a
		// bodyless request; consumers fail closed on the missing method.
		return res, nil
	}

	// Bytes arrived. Set once here so every path below reports it, the unusable ones
	// included — see AttrMCPBodyPresent for why presence and readability stay orthogonal.
	res.Attributes = map[string]string{AttrMCPBodyPresent: "true"}

	if body[0] != '{' {
		// Valid JSON, wrong kind. A batch names several operations and so identifies none
		// — picking one to enforce on while the server runs them all would be the same
		// divergence ambiguity creates. A scalar identifies nothing at all.
		res.Attributes[AttrMCPBodyUnusable] = MCPBodyNotAnObject
		return res, nil
	}

	// Before unmarshalling: see the ordering note above. Report it and publish none of the
	// facts — a method taken from a body that reads two ways is precisely what must not
	// reach a policy.
	if hasAmbiguousMembers(body) {
		res.Attributes[AttrMCPBodyUnusable] = MCPBodyAmbiguous
		return res, nil
	}

	var env mcpEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		// Distinguish the two failures the released policies distinguished: broken syntax
		// was a parse error, a wrong type an invalid request. Collapsing them would make a
		// consumer answer -32700 for a request that merely used the wrong type.
		reason := MCPBodyInvalidMemberType
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			reason = MCPBodySyntaxError
		}
		res.Attributes[AttrMCPBodyUnusable] = reason
		return res, nil
	}

	env.addAttributes(res.Attributes)
	return res, nil
}

// mcpEnvelope is the subset of a JSON-RPC request this resolver reads. Everything else
// in the payload is deliberately not modelled: this is a fixed vocabulary, not a
// projection of whatever the caller sent.
type mcpEnvelope struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`

	// Params is held raw and decoded separately. JSON-RPC 2.0 permits params to be an
	// array as well as an object, so declaring it as a struct would make the whole
	// unmarshal fail on a legitimate `"params": []` — discarding a perfectly readable
	// method because an unrelated member has an unexpected shape.
	Params json.RawMessage `json:"params"`
}

// mcpParams is the subset of an object-shaped params this resolver reads.
type mcpParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`

	// Where a legacy initialize states what modern requests put in _meta.
	ClientInfo      *mcpClientInfo `json:"clientInfo"`
	ProtocolVersion string         `json:"protocolVersion"`

	RequestState string `json:"requestState"`

	Meta map[string]json.RawMessage `json:"_meta"`
}

// mcpClientInfo is the client identity, shaped the same in both eras — only its location moves.
type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// params decodes the params member when it is an object. A non-object params is valid
// JSON-RPC and simply names no capability, so it yields the zero value rather than an
// error.
func (e *mcpEnvelope) params() mcpParams {
	var p mcpParams
	if len(e.Params) == 0 || !isJSONObject(e.Params) {
		return p
	}
	// A decode failure here leaves the zero value, which is the same outcome as absent —
	// the method is still readable and still worth publishing.
	_ = json.Unmarshal(e.Params, &p)
	return p
}

// addAttributes adds the envelope's canonical facts to attrs, omitting anything it did not
// find. A key is added only when it was actually read. The caller owns the map and has
// already recorded that a body was there; this adds only what the body said.
//
// The set splits in two, and the split is the whole of the logic here.
//
// Some facts stand on their own: an id and a protocol version mean the same thing whatever
// the body went on to name, so they are read from any body that carried them. The rest
// describe an operation, so they are published only when the body actually named one —
// inventing a capability for a body that invoked nothing is how a policy comes to enforce
// on a fact no request ever asserted.
//
// A body naming no operation is NOT a body that could not be read, which is why no
// unusable reason is published here. The commonest cause is not an error at all: a
// JSON-RPC response, which a client POSTs to answer a server-initiated request and which
// carries an id and a result but never a method.
func (e *mcpEnvelope) addAttributes(attrs map[string]string) {
	params := e.params()

	// ─── Facts that do not depend on the method ──────────────────────────────

	// A JSON-RPC request without an id is a notification: the server sends no response, so
	// several policies must not synthesise a correlated error envelope for it. That is not
	// published as a fact of its own — a consumer reads it off this key's absence, which is
	// the same test the resolver would have applied and cannot disagree with the id a
	// policy actually correlates against.
	//
	if id, ok := renderJSONRPCID(e.ID); ok {
		attrs[AttrMCPBodyJSONRPCID] = id
	}

	// Published even for a body naming no operation: _meta is read the same way either
	// way, and a policy that must know which era it is holding should not be denied the
	// answer because the body turned out to be a response rather than a request.
	if v := mcpProtocolVersion(params); v != "" {
		attrs[AttrMCPBodyProtocolVersion] = v
	}

	if params.RequestState != "" {
		attrs[AttrMCPBodyRequestStateHash] = hashRequestState(params.RequestState)
	}

	// Who is calling describes the client, not the operation, so it belongs here: a modern
	// request states it on every call, a methodless JSON-RPC response included.
	if info := mcpClientInfoOf(params); info.Name != "" || info.Version != "" {
		if info.Name != "" {
			attrs[AttrMCPBodyClientName] = info.Name
		}
		if info.Version != "" {
			attrs[AttrMCPBodyClientVersion] = info.Version
		}
	}

	// ─── Facts that describe the operation ───────────────────────────────────

	if e.Method != "" {
		attrs[AttrMCPBodyMethod] = e.Method

		capType, action, ok := splitMCPMethod(e.Method)
		if ok {
			attrs[AttrMCPBodyCapabilityType] = capType
			attrs[AttrMCPBodyCapabilityAction] = action
		}

		// Guarded by the method, though params is readable regardless: with no operation
		// there is no capability being addressed, and a stray params.name published as one
		// is a value an ACL could match on for a body that invoked nothing.
		if name := capabilityName(capType, params); name != "" {
			attrs[AttrMCPBodyCapabilityName] = name
		}
	}
}

// splitMCPMethod maps "tools/call" to the singular capability type and its action.
// A method with no family segment ("initialize") has neither, and reports false rather
// than inventing one.
// capabilityName picks the member that identifies the capability this operation addresses:
// params.uri for a resource, params.name for everything else.
//
// Keyed on the family, never on whichever member happens to be populated. MCP identifies a
// resource by uri and defines no name for resources/*, so a params.name there is not the
// capability and a client sets it freely. Taking the first non-empty member let a decoy name
// mask the resource the server actually reads: measured, a body naming a protected uri
// alongside an unrelated name escaped a rule written against that uri, while the same body
// parsed on a resolver-less gateway did not. Same class of divergence as the mirrored request
// headers, and the reason mcp-validation exists.
//
// Publishing nothing is the right answer when the family's own member is absent. A
// resources/read without a uri addresses no resource, and naming one from a member the server
// will not read is a value an ACL could match on for a capability never invoked.
func capabilityName(capType string, params mcpParams) string {
	if capType == mcpCapabilityTypeResource {
		return params.URI
	}
	return params.Name
}

func splitMCPMethod(method string) (capType, action string, ok bool) {
	family, action, found := strings.Cut(method, "/")
	if !found || family == "" || action == "" {
		return "", "", false
	}
	capType, known := mcpCapabilityTypes[family]
	if !known {
		// An unknown family is still a real segment; report it as-is rather than
		// dropping the fact. Policies match on the method anyway.
		capType = family
	}
	return capType, action, true
}

// mcpProtocolVersion reads the per-request protocol version out of params._meta, where
// 2026-07-28 places it, then falls back to params.protocolVersion, where a legacy initialize
// states one.
//
// The two are not quite the same thing, and folding them was a deliberate decision taken on
// 2026-09-11 for the simpler key set: modern _meta declares the version this request uses,
// while a legacy initialize proposes the newest version its client supports and lets the
// server pick. A consumer that must tell them apart can, since only initialize carries the
// legacy form. The one reader today, mcp-validation, compares this against the mirrored
// header behind an era gate that a legacy request never passes.
func mcpProtocolVersion(params mcpParams) string {
	if raw, ok := params.Meta[mcpMetaProtocolVersionKey]; ok {
		var v string
		if err := json.Unmarshal(raw, &v); err == nil && v != "" {
			return v
		}
	}
	return params.ProtocolVersion
}

// hashRequestState fingerprints an opaque requestState so two events can be matched without the
// value itself travelling. Plain SHA-256 hex: a consumer hashing the other half of the exchange
// must use exactly this, so the two sides cannot be matched if either changes.
func hashRequestState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// mcpClientInfoOf reads the calling client's identity, with the same precedence:
// params._meta first, then the legacy params.clientInfo.
//
// A member of the wrong shape is left to the zero value rather than failing the parse. It is
// one fact among several, and a body that states it oddly is still readable for the rest.
func mcpClientInfoOf(params mcpParams) mcpClientInfo {
	if raw, ok := params.Meta[mcpMetaClientInfoKey]; ok {
		var info mcpClientInfo
		if err := json.Unmarshal(raw, &info); err == nil && (info.Name != "" || info.Version != "") {
			return info
		}
	}
	if params.ClientInfo != nil {
		return *params.ClientInfo
	}
	return mcpClientInfo{}
}

// renderJSONRPCID renders the id as the JSON token it arrived as — 7 for a number, "7" with
// its quotes for a string. JSON-RPC allows either and a client correlates by matching the
// value, so a consumer echoes the token verbatim rather than re-parsing it.
//
// Reports false only when the member was absent. Null and "" are members that are present, so
// both publish and both are requests: a notification is a method with no id, both halves.
func renderJSONRPCID(raw json.RawMessage) (string, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

// trimLeadingSpace skips leading JSON whitespace so the first meaningful byte can be
// inspected without allocating.
func trimLeadingSpace(b []byte) []byte {
	for i, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b[i:]
		}
	}
	return nil
}

func init() {
	// Registered unconditionally, like route-key. It stays inert until a controller
	// emits resolver_name "mcp" on a route, so registering it cannot change the
	// behaviour of any MCP proxy deployed today.
	RegisterDefault(&MCPResolver{})
}
