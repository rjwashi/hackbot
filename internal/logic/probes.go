// This file defines the logic-bug probe catalog: one micro-scoped agent per
// bug class that a ready-made scanner cannot see (races, limits, workflows,
// object references, role escalation, verb/path tampering, error disclosure,
// integrity, upload policy, mass assignment, GraphQL argument surface).
//
// Every probe is built from fixed curl-shaped steps; the target and any
// operator-provided -path / -token / -header values travel as single argv
// elements, never through a shell. Classifiers are pure functions over the
// observed responses, so they are trivially unit-testable.
package logic // same package as logic.go

import ( // imports for the catalog
	"fmt"     // Sprintf for verdict reasons
	"regexp"  // evidence-marker matching
	"strings" // case-insensitive body checks
)

// Catalog returns the logic probes in display order.
func Catalog() []Probe { // the shipped micro-agents
	return []Probe{
		raceProbe(),
		ratelimitProbe(),
		workflowProbe(),
		idorProbe(),
		privescProbe(),
		authzBypassProbe(),
		errorDisclosureProbe(),
		paymentIntegrityProbe(),
		uploadTypeProbe(),
		massAssignmentProbe(),
		graphqlArgsProbe(),
	}
}

// ByKey looks up a probe by key (case-insensitive).
func ByKey(key string) (Probe, bool) { // used by `logic plan/run`
	for _, p := range Catalog() { // linear scan (small set)
		if strings.EqualFold(p.Key, strings.TrimSpace(key)) { // tolerant match
			return p, true
		}
	}
	return Probe{}, false
}

// raceProbe fires the same state-changing request many times in parallel and
// looks for divergent outcomes — the client-visible signature of a race window
// (double-apply, balance drift, duplicate resource).
func raceProbe() Probe { // WSTG-BUSL-04 Process Timing
	return Probe{
		Key: "race", Name: "Race condition (parallel double-submit)",
		Category: "business-logic", Tests: []string{"WSTG-BUSL-04"},
		DefaultPath: "/api/apply",
		Like:        "N parallel identical requests produce differing responses (duplicate effect / inconsistent state).",
		Note:        "Point -path at a state-changing endpoint (apply, redeem, transfer). Parallel repeats are the delivery: identical is UNVERIFIED, divergent is FOUND.",
		Steps: []Step{{
			Label: "parallel double-submit", Method: "POST", Path: "{path}",
			Body: "{}", Count: 12, Parallel: true,
		}},
		Judge: func(rs []Response) (Verdict, string) { // divergent == race signal
			groups := map[string]int{} // distinct outcomes, keyed by status+body hash
			for _, r := range rs {     // tally each exchange
				if r.Err != "" { // a transport failure is not a race signal
					continue
				}
				key := r.Status + "|" + bodyHash(r.Body) // outcome identity
				groups[key]++                            // count it
			}
			if len(groups) > 1 { // more than one outcome under parallel load
				return VerdictFound, fmt.Sprintf("%d parallel identical requests produced %d distinct responses — possible race window; confirm the business effect", len(rs), len(groups))
			}
			return VerdictUnverified, "all parallel responses were identical; no race window is visible from the client side"
		},
	}
}

// ratelimitProbe repeats one request and looks for a lockout/rate-limit signal
// (429 or a throttle message). Its absence across many tries is a finding.
func ratelimitProbe() Probe { // WSTG-BUSL-05, WSTG-ATHN-03
	return Probe{
		Key: "ratelimit", Name: "Function/rate limits (no lockout)",
		Category: "business-logic", Tests: []string{"WSTG-BUSL-05", "WSTG-ATHN-03"},
		DefaultPath: "/login",
		Like:        "Repeated attempts all succeed with neither 429 nor a block message.",
		Note:        "Point -path at anything rate-limited (login, OTP, promo code). Endpoints that need a body accept one via a future -body flag.",
		Steps: []Step{{
			Label: "rapid retries", Method: "POST", Path: "{path}", Count: 8,
		}},
		Judge: func(rs []Response) (Verdict, string) { // throttle present => CLEAN
			if bodyMatch(rs, `(?i)too many|rate limit|locked|temporarily blocked|try again later|throttl`) != "" { // a protection signal
				return VerdictClean, "a lockout/rate-limit signal was observed in the responses"
			}
			for _, r := range rs { // a bare 429 also proves protection
				if r.Status == "429" {
					return VerdictClean, "HTTP 429 observed — server enforces a rate limit"
				}
			}
			if n := countByPrefix(rs, "2", "3"); n == len(rs) && n > 0 { // every try succeeded
				return VerdictFound, fmt.Sprintf("%d consecutive attempts all succeeded without a lockout/rate-limit response", n)
			}
			return VerdictUnverified, "attempts returned mixed statuses; confirm the app's lockout behavior manually"
		},
	}
}

// workflowProbe calls a later workflow step directly and checks whether the
// application still serves it without the prerequisite step having run.
func workflowProbe() Probe { // WSTG-BUSL-06 Circumvention of Work Flows
	return Probe{
		Key: "workflow", Name: "Workflow circumvention (skip prerequisite)",
		Category: "business-logic", Tests: []string{"WSTG-BUSL-06"},
		DefaultPath: "/checkout",
		Like:        "The later workflow step answers 2xx when called directly.",
		Note:        "Point -path at a step that should require an earlier one (checkout before cart, confirm before draft). A 2xx means the gate is missing or client-side.",
		Steps: []Step{{
			Label: "call later step directly", Method: "GET", Path: "{path}",
		}},
		Judge: func(rs []Response) (Verdict, string) { // 2xx == step reachable
			if len(rs) == 0 { // nothing observed
				return VerdictUnverified, "no response observed"
			}
			switch s := rs[0].Status; { // judge by the status class
			case httpStatusPrefix(s, "2"):
				return VerdictFound, "the later workflow step answered 2xx when called without its prerequisite — verify the gate is server-side"
			case httpStatusPrefix(s, "3"):
				return VerdictUnverified, "the step redirected (3xx); follow the redirect to see whether the gate holds"
			case httpStatusPrefix(s, "4"), httpStatusPrefix(s, "5"):
				return VerdictClean, "the later step was refused (HTTP " + s + ") without the prerequisite"
			default:
				return VerdictUnverified, "no usable status for the direct call"
			}
		},
	}
}

// idorProbe walks sequential object ids with the same credentials and looks for
// cross-object data — the signature of an insecure direct object reference.
func idorProbe() Probe { // WSTG-ATHZ-04 Insecure Direct Object References
	return Probe{
		Key: "idor", Name: "IDOR (sequential object reference)",
		Category: "authorization", Tests: []string{"WSTG-ATHZ-04"},
		DefaultPath: "/api/object",
		Like:        "Multiple sequential ids return different objects (no per-object access check).",
		Note:        "The step appends /{id} for 1..5; -path sets the collection (e.g. /api/orders). Add -token for authenticated apps.",
		Steps: []Step{{
			Label: "object fetch", Method: "GET", Path: "{path}/{id}",
			IDs: []string{"1", "2", "3", "4", "5"},
		}},
		Judge: func(rs []Response) (Verdict, string) { // varied 2xx == IDOR
			ok := make([]Response, 0, len(rs)) // all successful fetches
			for _, r := range rs {             // collect 2xx responses
				if r.Err == "" && httpStatusPrefix(r.Status, "2") { // successful
					ok = append(ok, r)
				}
			}
			if n := countByPrefix(rs, "4"); n > 0 { // any refusal means a check exists
				return VerdictClean, "at least one requested id was refused (4xx) — a per-object access check is present"
			}
			if len(ok) >= 2 { // several ids answered...
				if bodyHash(ok[0].Body) != bodyHash(ok[len(ok)-1].Body) { // ...with different data
					return VerdictFound, fmt.Sprintf("%d sequential object ids returned different data — cross-object reference is not restricted", len(ok))
				}
				return VerdictUnverified, "every id returned the same object; no per-object distinction is visible"
			}
			return VerdictUnverified, "responses were inconclusive (no clear 4xx check, no varied 2xx)"
		},
	}
}

// privescProbe compares an anonymous baseline against requests carrying forged
// privilege/forwarding signals, flagging any that flip closed into open.
func privescProbe() Probe { // WSTG-ATHZ-03 Privilege Escalation
	return Probe{
		Key: "privesc", Name: "Privilege escalation (forged signals)",
		Category: "authorization", Tests: []string{"WSTG-ATHZ-03"},
		DefaultPath: "/admin",
		Like:        "A 4xx baseline becomes 2xx when a privilege/forwarding signal is added.",
		Note:        "Point -path at an admin/privileged endpoint. The probe adds X-Forwarded-For and X-Original-URL; a role-in-body variant is covered by mass-assignment.",
		Steps: []Step{
			{Label: "baseline", Method: "GET", Path: "{path}"},
			{Label: "forwarded-for signal", Method: "GET", Path: "{path}", Headers: []string{"X-Forwarded-For: 127.0.0.1"}},
			{Label: "original-url override", Method: "GET", Path: "{path}", Headers: []string{"X-Original-URL: {path}"}},
		},
		Judge: func(rs []Response) (Verdict, string) { // closed->open flip == finding
			if len(rs) == 0 { // nothing to compare
				return VerdictUnverified, "no response observed"
			}
			base, rest := rs[0], rs[1:]                                 // the anonymous baseline is always first
			bs := base.Status                                           // its status class decides the branch
			if httpStatusPrefix(bs, "4") || httpStatusPrefix(bs, "5") { // baseline closed
				for _, r := range rest { // any variant that opens it is a finding
					if r.Err == "" && (httpStatusPrefix(r.Status, "2") || httpStatusPrefix(r.Status, "3")) {
						return VerdictFound, "the endpoint (baseline HTTP " + bs + ") returned " + r.Status + " when a forged privilege/forwarding signal was added"
					}
				}
				return VerdictClean, "the endpoint stayed closed (HTTP " + bs + ") under privilege/forwarding signals"
			}
			return VerdictUnverified, "the endpoint is reachable with no privilege signal (HTTP " + bs + "); a public page does not prove escalation works"
		},
	}
}

// authzBypassProbe tries to slip past an authorization gate with verb and path
// tampering: HTTP method override headers and path normalizations that servers
// route differently than the gate.
func authzBypassProbe() Probe { // WSTG-ATHZ-02, WSTG-ATHN-04
	return Probe{
		Key: "authz-bypass", Name: "Authorization schema bypass (verb/path tampering)",
		Category: "authorization", Tests: []string{"WSTG-ATHZ-02", "WSTG-ATHN-04"},
		DefaultPath: "/api/admin",
		Like:        "A 4xx baseline answers 2xx after a method-override header or path normalization.",
		Note:        "Point -path at a protected route. Probes X-HTTP-Method-Override and common path confusion (/ / ..; / %2e).",
		Steps: []Step{
			{Label: "baseline", Method: "GET", Path: "{path}"},
			{Label: "method-override", Method: "POST", Path: "{path}", Headers: []string{"X-HTTP-Method-Override: DELETE"}},
			{Label: "slash confusion", Method: "GET", Path: "{path}//"},
			{Label: "semicolon confusion", Method: "GET", Path: "{path}/..;/"},
			{Label: "encoded dot", Method: "GET", Path: "{path}/%2e/"},
		},
		Judge: func(rs []Response) (Verdict, string) { // closed->open flip == finding
			if len(rs) == 0 { // nothing observed
				return VerdictUnverified, "no response observed"
			}
			base, rest := rs[0], rs[1:] // the untouched baseline is first
			bs := base.Status
			if httpStatusPrefix(bs, "4") || httpStatusPrefix(bs, "5") { // gate closed...
				for _, r := range rest { // ...does any tampering open it?
					if r.Err == "" && (httpStatusPrefix(r.Status, "2") || httpStatusPrefix(r.Status, "3")) {
						return VerdictFound, "the endpoint (baseline HTTP " + bs + ") answered " + r.Status + " for " + r.Step + " — gate bypass may be possible"
					}
				}
				return VerdictClean, "the endpoint stayed closed (HTTP " + bs + ") for every tampered variant"
			}
			return VerdictUnverified, "the endpoint is reachable with no tampering (HTTP " + bs + "); bypass cannot be distinguished from an open endpoint"
		},
	}
}

// errorDisclosureProbe feeds malformed input and looks for stack traces,
// framework banners, or verbose database errors in the response.
func errorDisclosureProbe() Probe { // WSTG-ERRH-01, WSTG-ERRH-02
	return Probe{
		Key: "error-disclosure", Name: "Verbose error disclosure",
		Category: "error-handling", Tests: []string{"WSTG-ERRH-01", "WSTG-ERRH-02"},
		DefaultPath: "/items",
		Like:        "Malformed input triggers a response containing a stack trace or framework/database error.",
		Note:        "Adjust -path to a query-driven endpoint. The probe sends a quote, a NUL byte, and an overflow value.",
		Steps: []Step{
			{Label: "baseline", Method: "GET", Path: "{path}"},
			{Label: "quote injection", Method: "GET", Path: "{path}?id='"},
			{Label: "nul byte", Method: "GET", Path: "{path}?id=%00"},
			{Label: "numeric overflow", Method: "GET", Path: "{path}?id=1e999999"},
		},
		Judge: func(rs []Response) (Verdict, string) { // disclosure marker == finding
			if m := bodyMatch(rs, `(?i)(stack trace|traceback|exception in |\.java:[0-9]+|at [a-z_][a-z0-9_]*\.[a-z_]+\(|php (warning|fatal)|ora-[0-9]{5}|sqlstate|syntax error near|sqlite3\.|javax\.)`); m != "" { // internals leaked
				return VerdictFound, "a response disclosed application internals: " + m
			}
			if n := countByPrefix(rs, "5"); n > 0 { // 5xx without a trace
				return VerdictUnverified, "the server errored (5xx) but disclosed no internals; confirm the error page by hand"
			}
			if n := countByPrefix(rs, "4"); n > 0 { // clean rejections
				return VerdictClean, "malformed input was rejected (4xx) without verbose disclosure"
			}
			return VerdictUnverified, "malformed input produced no error at all; the endpoint may fail open"
		},
	}
}

// paymentIntegrityProbe submits a tampered price/quantity and checks whether the
// server revalidates it or simply accepts what it receives.
func paymentIntegrityProbe() Probe { // WSTG-BUSL-01, WSTG-BUSL-10
	return Probe{
		Key: "payment-integrity", Name: "Payment/cart integrity (tampered values)",
		Category: "business-logic", Tests: []string{"WSTG-BUSL-01", "WSTG-BUSL-10"},
		DefaultPath: "/api/cart",
		Like:        "A request carrying a tampered price/quantity is accepted without server-side rejection.",
		Note:        "Point -path at the cart/checkout endpoint this app actually uses; the default JSON body is a placeholder showing the tampering shape.",
		Steps: []Step{{
			Label: "tampered price/qty", Method: "POST", Path: "{path}",
			Headers: []string{"Content-Type: application/json"},
			Body:    `{"items":[{"id":1,"price":-1,"quantity":-1}],"discount":99}`,
		}},
		Judge: func(rs []Response) (Verdict, string) { // acceptance == integrity gap
			if len(rs) == 0 { // nothing observed
				return VerdictUnverified, "no response observed"
			}
			s := rs[0].Status // the tampered request's outcome
			switch {          // classify by status class
			case httpStatusPrefix(s, "2"):
				return VerdictFound, "the server accepted a tampered price/quantity without rejection — verify server-side recalculation"
			case httpStatusPrefix(s, "4"):
				return VerdictClean, "the server rejected the tampered values (HTTP " + s + ")"
			case httpStatusPrefix(s, "5"):
				return VerdictUnverified, "the server errored (HTTP " + s + "); confirm whether validation is present but broken"
			default:
				return VerdictUnverified, "no usable status for the tampered request"
			}
		},
	}
}

// uploadTypeProbe tries to upload a JSP file via multipart — twice, once with a
// plain .jsp name and once with a double extension (the classic filter bypass.
func uploadTypeProbe() Probe { // WSTG-BUSL-08, WSTG-BUSL-09
	return Probe{
		Key: "upload-type", Name: "Upload file-type validation",
		Category: "business-logic", Tests: []string{"WSTG-BUSL-08", "WSTG-BUSL-09"},
		DefaultPath: "/upload",
		Like:        "The upload endpoint accepts a .jsp / double-extension file.",
		Note:        "Point -path at the upload form endpoint. The probe sends a small multipart body; servers that validate extensions reject it.",
		Steps: []Step{
			{
				Label: "jsp upload", Method: "POST", Path: "{path}",
				Headers: []string{"Content-Type: multipart/form-data; boundary=hackbot-boundary"},
				Body:    "--hackbot-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.jsp\"\r\nContent-Type: text/html\r\n\r\n<h1>hackbot-probe</h1>\r\n--hackbot-boundary--\r\n",
			},
			{
				Label: "double-extension upload", Method: "POST", Path: "{path}",
				Headers: []string{"Content-Type: multipart/form-data; boundary=hackbot-boundary"},
				Body:    "--hackbot-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.png.jsp\"\r\nContent-Type: text/html\r\n\r\n<h1>hackbot-probe</h1>\r\n--hackbot-boundary--\r\n",
			},
		},
		Judge: func(rs []Response) (Verdict, string) { // acceptance == policy gap
			for _, r := range rs { // any accepted upload is a finding
				if r.Err == "" && httpStatusPrefix(r.Status, "2") {
					return VerdictFound, "the upload endpoint accepted " + r.Step + " (HTTP " + r.Status + ") — file-type validation is absent or bypassable"
				}
			}
			if n := countByPrefix(rs, "4"); n > 0 { // rejected everywhere
				return VerdictClean, "the upload endpoint rejected the tampered file(s)"
			}
			return VerdictUnverified, "uploads were not clearly accepted or rejected; confirm the endpoint's behavior by hand"
		},
	}
}

// massAssignmentProbe adds unexpected privilege fields to an object create/update
// and checks whether the response echoes them (meaning the server binds them).
func massAssignmentProbe() Probe { // WSTG-APIT-02, WSTG-ATHZ-03
	return Probe{
		Key: "mass-assignment", Name: "Mass assignment (privilege fields)",
		Category: "api-testing", Tests: []string{"WSTG-APIT-02", "WSTG-ATHZ-03"},
		DefaultPath: "/api/users",
		Like:        "A create/update with an extra role or isAdmin field answers 2xx and echoes the field.",
		Note:        "Point -path at an object create/update endpoint. The default body adds role and isAdmin; a 4xx means unknown fields are rejected.",
		Steps: []Step{{
			Label: "privilege-field create", Method: "POST", Path: "{path}",
			Headers: []string{"Content-Type: application/json"},
			Body:    `{"name":"hackbot-probe","role":"admin","isAdmin":true}`,
		}},
		Judge: func(rs []Response) (Verdict, string) { // echoed field == binding
			if len(rs) == 0 { // nothing observed
				return VerdictUnverified, "no response observed"
			}
			r := rs[0] // the create/update response
			switch {   // classify by what came back
			case httpStatusPrefix(r.Status, "2") && strings.Contains(strings.ToLower(r.Body), "admin"):
				return VerdictFound, "the server accepted and echoed an injected privilege field (role/isAdmin observed in the response)"
			case httpStatusPrefix(r.Status, "2"):
				return VerdictUnverified, "the request was accepted (2xx) but the injected field was not echoed; check whether it was silently bound"
			case httpStatusPrefix(r.Status, "4"):
				return VerdictClean, "the server rejected the unknown privilege field (HTTP " + r.Status + ")"
			default:
				return VerdictUnverified, "no usable response for the tampered create/update"
			}
		},
	}
}

// graphqlArgsProbe checks whether GraphQL introspection is enabled and whether
// the argument surface (mutations) is exposed for tampering.
func graphqlArgsProbe() Probe { // WSTG-APIT-99 GraphQL
	return Probe{
		Key: "graphql-args", Name: "GraphQL introspection + argument surface",
		Category: "api-testing", Tests: []string{"WSTG-APIT-99"},
		DefaultPath: "/graphql",
		Like:        "Introspection answers with __schema (schema + mutation arguments exposed).",
		Note:        "Point -path at the GraphQL endpoint. A 200 with __schema means introspection is on: every mutation argument becomes a tampering target.",
		Steps: []Step{
			{
				Label: "introspection", Method: "POST", Path: "{path}",
				Headers: []string{"Content-Type: application/json"},
				Body:    `{"query":"{__schema{types{name fields{name}}}}"}`,
			},
			{
				Label: "argument tamper", Method: "POST", Path: "{path}",
				Headers: []string{"Content-Type: application/json"},
				Body:    `{"query":"mutation($r:String!){__typename}","variables":{"r":"admin"}}`,
			},
		},
		Judge: func(rs []Response) (Verdict, string) { // schema echo == exposure
			if len(rs) == 0 { // nothing observed
				return VerdictUnverified, "no response observed"
			}
			body := strings.ToLower(rs[0].Body) // the introspection response
			switch {                            // classify by what came back
			case strings.Contains(body, "__schema"):
				return VerdictFound, "GraphQL introspection is enabled — the schema (including mutation arguments) is exposed for tampering"
			case httpStatusPrefix(rs[0].Status, "4"):
				return VerdictClean, "introspection was refused (HTTP " + rs[0].Status + ")"
			default:
				return VerdictUnverified, "introspection returned no schema; confirm whether the endpoint is GraphQL and whether depth limiting hides it"
			}
		},
	}
}

// bodyMatch joins every response body and searches it for a pattern, returning
// the first matched snippet (empty string when nothing matched).
func bodyMatch(rs []Response, pattern string) string { // evidence-marker search
	re, err := regexp.Compile(pattern) // the marker pattern
	if err != nil {                    // a malformed pattern is a programming error
		return ""
	}
	for _, r := range rs { // search each exchange's body
		if m := re.FindString(r.Body); m != "" { // a hit...
			return m // ...return the snippet
		}
	}
	return "" // no marker found
}

// countByPrefix counts responses whose status starts with any given prefix.
func countByPrefix(rs []Response, prefixes ...string) int { // tally helper
	n := 0 // the tally
	for _, r := range rs {
		for _, p := range prefixes { // any of the given status classes
			if httpStatusPrefix(r.Status, p) { // a match...
				n++ // ...count it once
				break
			}
		}
	}
	return n
}
