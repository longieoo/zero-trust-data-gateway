# Benchmark policy catalogues

Generate a catalogue with `python -m benchmark.generate_policies --count 5000 --output policies/benchmark/generated.json`.

The runner saves each exact catalogue alongside its raw measurements under `benchmark/results/<run>/policies-<count>.json`. The normal demo always uses `policies/policies.json`; set `POLICY_FILE` only for controlled experiments. Clients cannot submit policy source to the API.

These rules vary targets, condition values/operators, effects, and priorities using a fixed seed. They are an artificial sparse-match workload, not a model of a production organization's complete access policy.
