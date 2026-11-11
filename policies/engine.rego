package capstone

import rego.v1

engine_version := "2.0.0"

# A small declarative policy interpreter. Policy data comes only from the server.
levels := {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

rhs(c) := object.get(input.attributes, c.other, null) if c.other

else := c.value

passes(c) if {
	c.op == "eq"
	object.get(input.attributes, c.path, null) == rhs(c)
}

passes(c) if {
	c.op == "neq"
	object.get(input.attributes, c.path, null) != rhs(c)
}

passes(c) if {
	c.op == "in"
	object.get(input.attributes, c.path, null) in rhs(c)
}

passes(c) if {
	c.op == "gte"
	object.get(input.attributes, c.path, null) >= rhs(c)
}

passes(c) if {
	c.op == "lt"
	object.get(input.attributes, c.path, null) < rhs(c)
}

passes(c) if {
	c.op == "rank_lt"
	levels[object.get(input.attributes, c.path, null)] < levels[rhs(c)]
}

condition_result(c) := {"condition": c, "passed": true} if passes(c)

else := {"condition": c, "passed": false}

target_matches(p) if every c in p.target { passes(c) }
target_value(p) if target_matches(p)

else := false

missing(p) if {
	some c in array.concat(p.target, p.conditions)
	object.get(input.attributes, c.path, null) == null
}

missing(p) if {
	some c in array.concat(p.target, p.conditions)
	c.other
	object.get(input.attributes, c.other, null) == null
}

outcome(p) := "Indeterminate" if missing(p)

else := p.effect if {
	target_matches(p)
	every c in p.conditions { passes(c) }
}

else := "NotApplicable"

catalogue := input.policies if input.policies

else := data.capstone_catalogues[input.catalogue_digest]

# Same evaluation semantics; omit repeated static metadata on the wire.
compact_outcomes := [result |
	some p in catalogue
	input.baseline in p.baselines
	result := {
		"id": p.id,
		"target_match": target_value(p),
		"passed": [condition_result(c).passed | some c in p.conditions],
		"outcome": outcome(p),
	}
] if {
	is_array(catalogue)
}

outcomes := [result |
	some p in catalogue
	input.baseline in p.baselines
	result := {
		"id": p.id, "description": p.description, "priority": p.priority,
		"version": p.version, "reason_code": p.reason_code,
		"target_match": target_value(p),
		"conditions": [condition_result(c) | some c in p.conditions],
		"outcome": outcome(p),
	}
] if {
	is_array(catalogue)
}
