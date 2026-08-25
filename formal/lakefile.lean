import Lake
open Lake DSL

package «frontier_formal»

@[default_target]
lean_lib «Formal»

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.22.0"
