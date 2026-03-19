# Points-To Analysis

How `iamspy` determines which GCP SDK class a variable holds at each call site.

Implementation: `src/iamspy/type_inference.py`
Tests: `tests/test_type_inference.py`

---

## How the Analysis Works

At every method call like `client.list_buckets()`, the scanner needs to know
what `client` points to — is it a `storage.Client`, a `compute_v1.InstancesClient`,
or something else? The answer determines which IAM permissions are required.

We solve this with **Andersen's inclusion-based points-to analysis** [Andersen 1994],
scoped down for our use case. The analysis runs in three steps:

**Step 1 — Walk the syntax tree once.** We parse the Python file with tree-sitter
and do a single recursive traversal. During this walk, we simultaneously:

- Build a **scope tree** (one scope per function, class, lambda, comprehension),
  following Python's LEGB scoping rules.
- **Generate constraints** from every assignment we see:
  - `client = storage.Client()` → "client may point to Client"
  - `backup = client` → "backup points to everything client points to"
  - `self.gcs = storage.Client()` → "the gcs field of this class may point to Client"
  - `x = get_client()` where `get_client` has `-> Client` annotation → "x may point to Client"
- **Harvest return-type annotations** from function definitions (`-> ClassName`).

**Step 2 — Solve to a fixed point.** We process the constraints using a worklist
algorithm. Allocation constraints (`client = Client()`) are seeded directly. Copy
constraints (`backup = client`) are propagated: when client's set grows, backup's
set grows too. The worklist drains when no set can grow further — this is the
**fixed point**, and it's guaranteed to terminate because sets only grow and the
domain is finite.

**Step 3 — Query at each call site.** When the scanner encounters
`client.list_buckets()`, it asks the analysis: "what classes can `client` hold
at this program point?" The answer is a set:

- **1 class** → `EXACT` — resolve permissions against that class.
- **Multiple classes** → `AMBIGUOUS` — resolve each, union the permissions.
- **Empty** → `UNRESOLVED` — fall back to method-name matching across imported services.

For `self.attr.method()`, the analysis looks up the field in the enclosing class.
For `app.client.method()`, it does a two-step lookup: resolve `app`'s type first,
then look up the field on that type.

**What it handles:** direct constructors, aliasing (`y = x`), `self.attr` fields,
cross-object field access (`app.client`), annotated factories (`-> Client`),
branch merging (if/else), walrus operator (`:=`), tuple unpacking, and proper
scope isolation (same variable name in different functions).

**What it does not handle:** dynamic dispatch (`getattr`), dict-stored clients
(`d["key"].method()`), cross-file analysis, unannotated factories, or loop
iteration variables. These are documented in the Known Limitations section below.

---

## Formal Model

### Abstract domain

```
AbstractObj = ClassName         -- e.g. "InstancesClient", "Client"

Loc =
  | Var(scope_id, name)         -- a variable in a specific LEGB scope
  | Field(class_name, attr)     -- self.attr on instances of a class
  | Ret(func_name)              -- return value of a function

pt : Loc -> P(AbstractObj)      -- the points-to map
```

The lattice is `(P(AbstractObj), subset)`. Bottom = empty set. Join = union.
Transfer functions are monotone. The domain is finite. The analysis terminates.

---

## Constraint Language

Constraint generation walks the tree-sitter CST once and produces a set of
inclusion constraints. The solver then propagates them to a fixed point.

There are two constraint forms:

```
alloc(C)  ⊆  pt(loc)          -- loc definitely points to C
pt(loc_a) ⊆  pt(loc_b)        -- everything loc_a points to, loc_b may also point to
```

### Generation rules

| Python statement | Generated constraint |
|---|---|
| `x = C(...)` where C ∈ method_db | `alloc(C) ⊆ pt(Var(σ, x))` |
| `x = y` where y might be a GCP var | `pt(Var(σ_y, y)) ⊆ pt(Var(σ, x))` |
| `self.a = C(...)` in class K | `alloc(C) ⊆ pt(Field(K, a))` |
| `self.a = y` in class K | `pt(Var(σ, y)) ⊆ pt(Field(K, a))` |
| `x = self.a` in method of class K | `pt(Field(K, a)) ⊆ pt(Var(σ, x))` |
| `def f() -> C` where C ∈ method_db | `alloc(C) ⊆ pt(Ret(f))` |
| `x = f()` | `pt(Ret(f)) ⊆ pt(Var(σ, x))` |

**Domain restriction.** Constraint generation tracks ALL uppercase constructors
(`Foo()`, `Config()`, `App()`), not just classes in `known_classes`. This is
necessary for cross-object field access (S12): `app = App()` must generate an
alloc constraint even though `App` is not a GCP class, so that `app.instances`
can resolve to `InstancesClient` via a two-step field load. The `known_classes`
filter is applied only to return-type harvesting (annotated factory functions).
The scanner applies its own domain filter at query time — it intersects the
final pt-set with `method_db` class names to determine which classes are GCP
clients. This is the "scoped down" part — we generate constraints broadly but
interpret results narrowly.

**LEGB at generation time.** The σ in `Var(σ, y)` is determined at constraint
generation by LEGB lookup: find the innermost enclosing scope that contains a
binding for `y`. LEGB is resolved during the CST walk, not during solving. The
solver only shuffles abstract objects between pre-computed locations.

**Flow-insensitivity within scope.** All assignment constraints for a given scope
are collected without regard to program order. This means both branches of an
`if/else` contribute to `pt(Var(σ, x))`. This is a sound over-approximation: the
analysis may report `AMBIGUOUS` where a flow-sensitive analysis would report `EXACT`,
but it will never miss a permission. For GCP code, where client variables are rarely
reassigned, the precision cost is negligible.

### Additional statement forms (same rules, different syntax)

| Python syntax | Treated as |
|---|---|
| `x: Type = C()` (annotated assign) | Same as `x = C()` |
| `(x := C())` (walrus) | Same as `x = C()` |
| `a, b = C1(), C2()` (tuple, same length) | Two allocations: `alloc(C1) ⊆ pt(Var(σ,a))`, etc. |
| `a, *b, c = ...` (starred, variable length) | Skip — shapes don't match statically |
| `from google.cloud.storage import *` | Marks service as imported; calls remain UNRESOLVED until receiver resolved |

---

## Constraint Solver

The solver is a standard worklist propagation over inclusion constraints.

```
Input:  alloc_constraints: list[(AbstractObj, Loc)]
        copy_constraints:  list[(Loc, Loc)]         -- (src, dst)
Output: pt: dict[Loc, set[AbstractObj]]

# Step 1: seed allocations
for (obj, loc) in alloc_constraints:
    pt[loc].add(obj)

# Step 2: propagate copies
worklist = deque(copy_constraints)

while worklist:
    (src, dst) = worklist.popleft()
    new = pt[src] - pt[dst]
    if new:
        pt[dst] |= new
        # anything that depends on dst may now get new entries
        for (dst, downstream) in copy_constraints_from[dst]:
            worklist.append((dst, downstream))
```

The worklist terminates because:
1. `pt[loc]` is monotonically non-decreasing (sets only grow).
2. `pt[loc] ⊆ AbstractObj`, which is finite.
3. Each iteration adds at least one element to some `pt[loc]`.
4. Total additions bounded by `|Loc| × |AbstractObj|`.

**Why no dynamic edge addition.** Full Andersen's generates new copy constraints
during solving when `pt(x)` grows and there are outstanding field load/store
constraints (`y = x.f`). We avoid this because we only model fields on `self` — a
single, statically-known receiver. Field constraints `pt(Field(K,a)) ⊆ pt(Var(σ,x))`
are pre-compiled during constraint generation, not added dynamically. This is what
makes our version simpler than full Andersen's.

---

## Scope Model

### Scope tree

Each scope-introducing node in the CST spawns a `Scope`:

```python
@dataclass
class Scope:
    id:     int                             # unique, assigned in tree-walk order
    kind:   Literal["module", "class", "function", "comprehension", "lambda"]
    parent: Scope | None
    class_name: str | None                  # set for class scopes only
    func_name:  str | None                  # set for function/lambda scopes only
```

Scope-introducing tree-sitter node types: `module`, `class_definition`,
`function_definition`, `lambda`, `list_comprehension`, `set_comprehension`,
`dictionary_comprehension`, `generator_expression`.

### LEGB lookup

```
def legb_scope(name: str, from_scope: Scope) -> Scope | None:
    s = from_scope
    while s is not None:
        if name in s.bindings:
            return s
        if s.kind == "class":
            s = s.parent   # Python LEGB skips class scope during method body lookup
            continue
        s = s.parent
    return None             # unresolved — not a local, enclosing, or global binding
```

The call site `obj.method()` uses `legb_scope(obj, call_site_scope)` to determine
which `Var(σ, obj)` to query. If no scope has a binding, the variable is `UNRESOLVED`.

### Class scope and field access

`self.attr.method()` bypasses LEGB entirely. The receiver is resolved via the class
scope of the enclosing `class_definition`:

```
def field_scope(attr: str, from_scope: Scope) -> Scope | None:
    s = from_scope
    while s is not None:
        if s.kind == "class" and attr in s.field_bindings:
            return s
        s = s.parent
    return None
```

`pt(Field(K, attr))` is the points-to set for `self.attr` in instances of class K.

---

## Canonical Scenarios

Each scenario is the **exit criterion** for the corresponding fix. A scenario passes
when `scan_source(source)` produces findings that match the expected permission set
and resolution class exactly.

All examples use real GCP SDK calls with their actual IAM permissions:
- `compute_v1.InstancesClient.insert` → `compute.instances.create` (+ conditional `iam.serviceAccounts.actAs`)
- `compute_v1.InstancesClient.start` → `compute.instances.start`
- `compute_v1.InstancesClient.stop` → `compute.instances.stop`
- `compute_v1.InstancesClient.aggregated_list` → `compute.instances.list`
- `storage.Client.list_buckets` → `storage.buckets.list`
- `storage.Client.create_bucket` → `storage.buckets.create`
- `storage.Blob.upload_from_filename` → `storage.objects.create`

---

### S1 — Direct constructor (baseline, must not regress)

```python
from google.cloud import compute_v1

instances = compute_v1.InstancesClient()
instances.insert(project="my-proj", zone="us-central1-a", instance_resource=body)
```

**Constraints generated:**
```
alloc(InstancesClient) ⊆ pt(Var(module, "instances"))
```

**Solved:** `pt(Var(module, "instances")) = {InstancesClient}`

**Query at call site:** `legb_scope("instances", call_scope)` → module scope.
Single-element pt-set → **EXACT**.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert len(result.findings) == 1
assert result.findings[0].method_name == "insert"
assert result.findings[0].resolution == Resolution.EXACT
assert "compute.instances.create" in result.findings[0].permissions
```

---

### S2 — Instance attribute (`self.x`) — most common missed pattern

```python
from google.cloud import compute_v1, storage

class VMProvisioner:
    def __init__(self, project: str):
        self.instances = compute_v1.InstancesClient()   # store: Field(VMProvisioner, instances)
        self.gcs = storage.Client()                     # store: Field(VMProvisioner, gcs)
        self.project = project

    def provision(self, zone: str, body: compute_v1.Instance):
        self.instances.insert(                          # query: Field(VMProvisioner, instances)
            project=self.project,
            zone=zone,
            instance_resource=body,
        )

    def archive_logs(self, bucket: str):
        self.gcs.create_bucket(bucket)                  # query: Field(VMProvisioner, gcs)
```

**Constraints generated:**
```
alloc(InstancesClient) ⊆ pt(Field("VMProvisioner", "instances"))
alloc(StorageClient)   ⊆ pt(Field("VMProvisioner", "gcs"))
```

**Solved:**
```
pt(Field("VMProvisioner", "instances")) = {InstancesClient}
pt(Field("VMProvisioner", "gcs"))       = {StorageClient}
```

**Query at `self.instances.insert(...)`:**
`field_scope("instances", provision_scope)` → VMProvisioner class scope.
`pt(Field("VMProvisioner", "instances")) = {InstancesClient}` → **EXACT**.

**Query at `self.gcs.create_bucket(...)`:**
`pt(Field("VMProvisioner", "gcs")) = {StorageClient}` → **EXACT**.

**Current failure mode:** `_extract_receiver_name` returns `None` for `self.instances`
(the receiver is an `attribute` node, not a bare `identifier`). Both calls fall
through to first-match-wins across all imported services. `insert` is unambiguous,
but `create_bucket` could match multiple services if method names collide.

**Fix:** `_extract_receiver_name` must detect the `self.<attr>` pattern and return
`("self", attr_name)`. At the call site, query `Field(enclosing_class, attr_name)`
instead of `Var(σ, attr_name)`.

**Exit criterion:**
```python
result = scanner.scan_source(source)
findings = {f.method_name: f for f in result.findings}

assert findings["insert"].resolution == Resolution.EXACT
assert "compute.instances.create" in findings["insert"].permissions

assert findings["create_bucket"].resolution == Resolution.EXACT
assert "storage.buckets.create" in findings["create_bucket"].permissions
```

---

### S3 — Branch-conditional assignment (phi-node)

```python
from google.cloud import compute_v1, storage

def get_resource_client(use_compute: bool):
    if use_compute:
        client = compute_v1.InstancesClient()   # alloc(InstancesClient) → Var(fn, client)
    else:
        client = storage.Client()               # alloc(StorageClient)   → Var(fn, client)
    # call after merge point — client is ambiguous
    client.aggregated_list(project="my-proj")   # exists on InstancesClient only
```

**Constraints generated (flow-insensitive — both branches fire unconditionally):**
```
alloc(InstancesClient) ⊆ pt(Var(fn, "client"))
alloc(StorageClient)   ⊆ pt(Var(fn, "client"))
```

**Solved:** `pt(Var(fn, "client")) = {InstancesClient, StorageClient}`

**Query at call site:** `|pt(...)| = 2` → **AMBIGUOUS**. The scanner resolves
each class in the pt-set independently, then unions all permission results via
`_merge_permission_results`. This function deduplicates permissions while
preserving first-appearance order, unions conditional permissions, and combines
notes from all contributors. `aggregated_list` has no mapping on `StorageClient`
— only `compute.instances.list` is returned (the union contains one result).

**Current failure mode:** `_collect_assignments` is a plain tree walk; whichever
branch's assignment node appears later in the CST wins. The `else` branch appears
last, so `client → "Client"` (StorageClient). The call to `aggregated_list` is
then attributed to StorageClient with no permissions — a **wrong EXACT** at zero
confidence that silently drops the compute finding.

**Note on flow-insensitivity:** A flow-sensitive analysis would produce EXACT on
each branch and AMBIGUOUS only at the merge point. That requires a control-flow
graph and SSA construction. Flow-insensitivity gets the same soundness — both types
enter the pt-set — without any of that machinery. For GCP code (client variables
almost never reassigned), the precision cost is negligible.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert len(result.findings) == 1
f = result.findings[0]
assert f.method_name == "aggregated_list"
assert f.resolution == Resolution.AMBIGUOUS
assert "compute.instances.list" in f.permissions
```

---

### S4 — Scope collision: same name, different clients

This is the scenario where `client` means `storage.Client` at module scope and
`compute_v1.InstancesClient` inside a function. The flat dict cannot distinguish
them — the inner assignment overwrites the outer.

```python
from google.cloud import compute_v1, storage

# Module scope: client → StorageClient
client = storage.Client()

def provision_vm(project: str, zone: str, body: compute_v1.Instance):
    # Function scope: client → InstancesClient (different Var, different scope)
    client = compute_v1.InstancesClient()
    client.insert(project=project, zone=zone, instance_resource=body)
    # Expected: compute.instances.create — EXACT

# Back in module scope: client is still StorageClient
buckets = client.list_buckets()
# Expected: storage.buckets.list — EXACT
```

**Constraints generated:**
```
alloc(StorageClient)   ⊆ pt(Var(module,       "client"))
alloc(InstancesClient) ⊆ pt(Var(fn_provision, "client"))
```

Two distinct abstract locations. The solver populates them independently.

**Query at `client.insert(...)` inside `provision_vm`:**
`legb_scope("client", provision_scope)` → `fn_provision` (local binding found first).
`pt(Var(fn_provision, "client")) = {InstancesClient}` → **EXACT**.

**Query at `client.list_buckets()` at module scope:**
`legb_scope("client", module_scope)` → module scope (no inner scope in play).
`pt(Var(module, "client")) = {StorageClient}` → **EXACT**.

**Current failure mode:** The flat `var_type_map` has one entry keyed by `"client"`.
The tree walk visits the inner assignment later (it appears after the outer one in
the CST), so `var_type_map["client"] = "InstancesClient"`. The module-scope call
`client.list_buckets()` is then resolved against `InstancesClient` — no permissions,
wrong service, wrong resolution.

**Exit criterion:**
```python
result = scanner.scan_source(source)
findings = {f.method_name: f for f in result.findings}

assert findings["insert"].resolution == Resolution.EXACT
assert "compute.instances.create" in findings["insert"].permissions

assert findings["list_buckets"].resolution == Resolution.EXACT
assert "storage.buckets.list" in findings["list_buckets"].permissions
```

---

### S5 — Annotated factory function

```python
from google.cloud import compute_v1

def get_instances_client(project: str) -> compute_v1.InstancesClient:
    return compute_v1.InstancesClient()

instances = get_instances_client("my-proj")
instances.start(project="my-proj", zone="us-central1-a", instance="vm-1")
```

**Constraints generated:**
```
alloc(InstancesClient) ⊆ pt(Ret("get_instances_client"))       # from -> annotation
pt(Ret("get_instances_client")) ⊆ pt(Var(module, "instances")) # from x = f()
```

**Solved via worklist:**
```
Seed:        pt(Ret("get_instances_client")) = {InstancesClient}
Copy fires:  pt(Var(module, "instances"))   |= {InstancesClient}
```

**Query:** `pt(Var(module, "instances")) = {InstancesClient}` → **EXACT**.

**Current failure mode:** `_try_extract_constructor_assignment` rejects the RHS
because `get_instances_client` does not start with an uppercase letter. No constraint
is generated. `receiver_class = None`. Resolution falls to first-match-wins across
all imported services.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert result.findings[0].resolution == Resolution.EXACT
assert "compute.instances.start" in result.findings[0].permissions
```

---

### S6 — Unannotated factory (deferred — UNRESOLVED is acceptable)

```python
from google.cloud import compute_v1

def get_client():
    return compute_v1.InstancesClient()

instances = get_client()
instances.stop(project="my-proj", zone="us-central1-a", instance="vm-1")
```

**Constraints generated:**
```
pt(Ret("get_client")) ⊆ pt(Var(module, "instances"))   # from x = f()
```

`pt(Ret("get_client")) = ∅` — no annotation, no allocation constraint for `Ret`.
Copy constraint propagates nothing.

**Query:** `pt(Var(module, "instances")) = ∅` → **UNRESOLVED**. Falls back to
service-filter matching: `stop` matched against imported services → finds
`compute.instances.stop` via method_db, but confidence is lower.

To resolve this, we would walk `get_client`'s body, find the `return` statement,
apply the allocation rule to the returned constructor, and add
`alloc(InstancesClient) ⊆ pt(Ret("get_client"))`. Deferred: annotated factories
(S5) cover the common typed-codebase case.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert result.findings[0].resolution == Resolution.UNRESOLVED
# permissions may still be present via fallback, but confidence is flagged
```

---

### S7 — Chained SDK call (deferred)

```python
from google.cloud import compute_v1

images = compute_v1.ImagesClient()
op = compute_v1.ZoneOperationsClient().wait(
    project="my-proj", zone="us-central1-a", operation=op_name
)
```

The receiver of `wait(...)` is `compute_v1.ZoneOperationsClient()` — a call node,
not an identifier. `_extract_receiver_name` requires the receiver to be an
`identifier` node. No `Var` is created; the call site has no receiver location to
query.

To fix, we would need to recognize inline constructor calls as temporary allocation
sites: `alloc(ZoneOperationsClient) ⊆ pt(tmp_N)` and use `tmp_N` as the receiver.
Deferred — rare pattern, method_db fallback still finds it as UNRESOLVED.

**Exit criterion (current acceptable behavior):**
```python
result = scanner.scan_source(source)
assert result.findings[0].resolution == Resolution.UNRESOLVED
```

---

### S8 — Explicit copy / alias

```python
from google.cloud import compute_v1

primary = compute_v1.InstancesClient()
backup = primary                              # copy constraint
backup.aggregated_list(project="my-proj")
```

**Constraints generated:**
```
alloc(InstancesClient) ⊆ pt(Var(σ, "primary"))
pt(Var(σ, "primary"))  ⊆ pt(Var(σ, "backup"))   # copy
```

**Solved via worklist:**
```
Seed:       pt(Var(σ, "primary")) = {InstancesClient}
Copy fires: pt(Var(σ, "backup")) |= {InstancesClient}
```

**Query:** `pt(Var(σ, "backup")) = {InstancesClient}` → **EXACT**.

**Current failure mode:** `_try_extract_constructor_assignment` requires the RHS to
be a `call` node. `backup = primary` has an `identifier` RHS → rejected. No
constraint generated. Receiver of `backup.aggregated_list(...)` is unresolved.

The copy constraint rule fixes this as a natural consequence of Andersen's. No
special case needed.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert result.findings[0].resolution == Resolution.EXACT
assert "compute.instances.list" in result.findings[0].permissions
```

---

### S9 — Star import (independent fix, not a points-to issue)

```python
from google.cloud.compute_v1 import *

instances = InstancesClient()
instances.insert(project="my-proj", zone="us-central1-a", instance_resource=body)
```

**Import detection failure:** `_handle_import_from` scans child nodes for
`dotted_name` to find imported names. A star import produces a `wildcard_import`
node (`*`) — not a `dotted_name`. The import is silently dropped.
`imported_services = ∅` → no findings at all, regardless of calls.

This is a **pre-condition failure**: the constraint generator never runs because
`imported_services` is empty. The fix lives in `_handle_import_from`: detect the
`wildcard_import` child and resolve the module path itself to a service_id.

After the fix, `InstancesClient()` is an unqualified constructor. The allocation
rule fires: `alloc(InstancesClient) ⊆ pt(Var(σ, "instances"))`. Resolution is
EXACT since InstancesClient is unambiguous.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert len(result.findings) == 1
assert result.findings[0].method_name == "insert"
assert "compute.instances.create" in result.findings[0].permissions
```

---

### S10 — Walrus operator

```python
from google.cloud import compute_v1

if instances := compute_v1.InstancesClient():
    instances.start(project="my-proj", zone="us-central1-a", instance="vm-1")
```

The tree-sitter node type is `named_expression`. The named expression binds
`instances` in the enclosing scope (not just inside the `if` body). The constraint
rule is identical to a regular assignment.

**Constraints generated:**
```
alloc(InstancesClient) ⊆ pt(Var(σ, "instances"))
```

The constraint generator must handle `named_expression` nodes in addition to
`assignment` nodes.

**Exit criterion:**
```python
result = scanner.scan_source(source)
assert result.findings[0].resolution == Resolution.EXACT
assert "compute.instances.start" in result.findings[0].permissions
```

---

### S11 — Tuple unpacking

```python
from google.cloud import compute_v1, storage

instances, gcs = compute_v1.InstancesClient(), storage.Client()
instances.insert(project="my-proj", zone="us-central1-a", instance_resource=body)
gcs.list_buckets()
```

LHS is a `pattern_list` node containing two `identifier` nodes. RHS is an
`expression_list` with two `call` nodes. Zip positionally when lengths match:

```
alloc(InstancesClient) ⊆ pt(Var(σ, "instances"))
alloc(StorageClient)   ⊆ pt(Var(σ, "gcs"))
```

**Exit criterion:**
```python
result = scanner.scan_source(source)
findings = {f.method_name: f for f in result.findings}

assert findings["insert"].resolution == Resolution.EXACT
assert "compute.instances.create" in findings["insert"].permissions

assert findings["list_buckets"].resolution == Resolution.EXACT
assert "storage.buckets.list" in findings["list_buckets"].permissions
```

---

### S12 — Cross-object field access (`obj.attr.method()`)

```python
from google.cloud import compute_v1, storage

class App:
    def __init__(self):
        self.instances = compute_v1.InstancesClient()
        self.gcs = storage.Client()

app = App()
app.instances.insert(project="p", zone="z", instance_resource=body)
app.gcs.list_buckets()
```

This is Andersen's field load constraint: `y = x.f`. The full version adds
dynamic copy edges: `forall o in pt(x): pt(o.f) <= pt(y)`. We implement it
as a two-step query-time lookup — no new constraints needed:

1. `pt(Var(module, "app"))` -> `{App}` (standard LEGB lookup)
2. `pt(Field("App", "instances"))` -> `{InstancesClient}` (field lookup on each class in pt-set)

The constraint system already tracks both sides:
- `app = App()` generates `alloc(App) <= pt(Var(module, "app"))` (standard alloc)
- `self.instances = InstancesClient()` generates `alloc(InstancesClient) <= pt(Field("App", "instances"))` (field_alloc)

The key enabler is the **domain restriction change** (see below): constraint
generation tracks ALL uppercase constructors, not just `known_classes`. This
means `App()` generates an alloc constraint even though `App` is not a GCP class.
The `known_classes` filter is applied only to return-type harvesting. The scanner
applies its own domain filter at query time (intersection with method_db class
names) to interpret the final pt-set.

No new constraint forms are needed. The `query_obj_attr(obj, attr, node)` method
on `PointsToAnalysis` implements the two-step lookup at query time.

**Constraints generated:**
```
alloc(App)              <= pt(Var(module, "app"))
alloc(InstancesClient)  <= pt(Field("App", "instances"))
alloc(StorageClient)    <= pt(Field("App", "gcs"))
```

**Solved:**
```
pt(Var(module, "app"))            = {App}
pt(Field("App", "instances"))     = {InstancesClient}
pt(Field("App", "gcs"))           = {StorageClient}
```

**Query at `app.instances.insert(...)`:**
`query_obj_attr("app", "instances", node)`:
  Step 1: `pt(Var(module, "app"))` -> `{App}`
  Step 2: `pt(Field("App", "instances"))` -> `{InstancesClient}` -> **EXACT**.

**Query at `app.gcs.list_buckets()`:**
`query_obj_attr("app", "gcs", node)`:
  Step 1: `pt(Var(module, "app"))` -> `{App}`
  Step 2: `pt(Field("App", "gcs"))` -> `{StorageClient}` -> **EXACT**.

**Exit criterion:**
```python
result = scanner.scan_source(source)
findings = {f.method_name: f for f in result.findings}

assert findings["insert"].resolution == Resolution.EXACT
assert "compute.instances.create" in findings["insert"].permissions

assert findings["list_buckets"].resolution == Resolution.EXACT
assert "storage.buckets.list" in findings["list_buckets"].permissions
```

---

## Complexity

| Quantity | Symbol | Bound |
|---|---|---|
| Lines of source | n | — |
| Abstract locations (variables + fields) | V | O(n) |
| Copy constraints | E | O(n) |
| Domain size (tracked GCP classes) | D | ~1,000, constant |
| Allocation constraints | A | O(n) |

**Constraint generation:** O(n) — single CST walk.

**Solver:** Each copy constraint is processed at most D times (each propagation adds
at least one element; each pt-set grows at most D elements). Total work: O(E·D).
Since D is a small constant, this is O(n) in practice.

**Total:** O(n). The worklist terminates in linear time. No fixed-point iteration
over the constraint graph is needed because there are no dynamic edges — field
constraints on `self` are pre-compiled during generation.

**Comparison to full Andersen's:** Full Andersen's is O(n³) in the worst case due to
field store/load constraints generating new copy edges during solving. We avoid this
by restricting field tracking to `self`. The tradeoff: we cannot analyze
`clients_dict["storage"].method()` or arbitrary heap-stored clients.

---

## What We Are Not Building

These patterns require capabilities outside the scoped-down model. They are
documented here to avoid revisiting the decision.

| Pattern | Reason not in scope |
|---|---|
| `getattr(client, name)()` | Dynamic dispatch. Unsolvable by any static analysis. |
| `clients["storage"].method()` | Requires container content tracking (full Andersen's). |
| Cross-file analysis (Phase 2) | Requires a module resolver and cross-file constraint graph. The analysis is single-file only — if `Config` is defined in `config.py` and used in `main.py`, the field access is invisible. |
| Unannotated factory return inference (S6) | Deferred — low ROI, annotated factories cover typed codebases. |
| Chained SDK calls (S7) | Requires SDK type stubs or SDK-level return inference. |
| Loop iteration variables | `for x in container:` requires container content tracking. |

### Known limitations (correctness and code quality)

| Issue | Category | Notes |
|---|---|---|
| `_scope_for_byte` is O(n) linear scan | Performance | Should be binary search over sorted intervals. Not a correctness issue — just slow on very large files. |
| `_text` and `_flatten_attribute` are duplicated | Code quality | Identical implementations exist in both `scanner.py` and `type_inference.py`. Should be extracted to a shared CST helper module. |
| `Constraint = tuple` is untyped | Code quality | Tagged tuples are fragile. Should be `NamedTuple` or `@dataclass` per constraint type (e.g. `AllocConstraint`, `CopyConstraint`). |

---

## Implementation Plan

### Module Layering

Compiler passes should be separate modules with clear data flow between them.
The current `scanner.py` mixes CST traversal, type inference, and call resolution
into one file. The upgrade separates the type inference into its own pass.

```
                      scanner.py                         type_inference.py
                   (orchestration)                        (analysis pass)
                                                      ┌─────────────────────┐
  source ──► parse ──► detect_gcp_imports              │  Scope tree (LEGB)  │
                │                                      │  Constraint gen     │
                │      ┌───────────────────┐           │  Worklist solver    │
                └─────►│ PointsToAnalysis  │◄──────────│  Query interface    │
                       │ (known_classes)   │           └─────────────────────┘
                       └────────┬──────────┘
                                │ query_var(name, node) → PointsToSet
                                │ query_field(attr, node) → PointsToSet
                                ▼
                   _walk calls ──► _check_call ──► _resolve
                                                       │
                                                       ▼
                                                   Finding(resolution=...)
```

**Key boundary:** `type_inference.py` knows nothing about GCP, permissions, or
findings. It takes a tree-sitter CST, a set of "interesting" class names (the
domain restriction), and returns a query interface over solved points-to sets.
The scanner feeds it `known_classes` from method_db and queries it at each call
site.

### New module: `src/iamspy/type_inference.py`

This module implements a single compiler pass: scoped-down Andersen's points-to
analysis over a tree-sitter CST. It is self-contained — the only imports from
iamspy are none (it depends only on tree-sitter).

**Types:**

```python
PointsToSet = frozenset[str]    # e.g. frozenset({"InstancesClient", "StorageClient"})

# Constraint representation — tagged union via tuples for simplicity.
# Alloc: ("alloc", class_name, scope_id, var_name)
# Copy:  ("copy", src_scope_id, src_name, dst_scope_id, dst_name)
# FieldStore: ("field_store", class_name, attr, scope_id, rhs_name_or_class)
```

**Data structures (layered bottom-up):**

```python
@dataclass
class Scope:
    """A single scope node in the LEGB scope tree.

    Scopes form a tree rooted at the module scope. Each scope contains
    variable bindings (populated by constraint solving) and, for class
    scopes, field bindings for self.X attributes.
    """
    id:         int
    kind:       Literal["module", "class", "function", "comprehension", "lambda"]
    parent:     Scope | None
    node:       Node                         # tree-sitter node that opened this scope
    bindings:   dict[str, set[str]]          # var_name → mutable set of class names
    fields:     dict[str, set[str]]          # attr → class names (class scopes only)
    class_name: str | None = None            # set for class scopes
    children:   list[Scope] = field(...)     # child scopes (for tree traversal)
```

**Core abstraction — `PointsToAnalysis`:**

```python
class PointsToAnalysis:
    """Scoped-down Andersen's points-to analysis.

    Construction runs the full analysis: scope tree → constraints → solve.
    After construction, the instance is a read-only query interface.
    """
    def __init__(self, root: Node, src: bytes, known_classes: set[str]):
        # 1. Build scope tree
        # 2. Harvest return-type annotations
        # 3. Generate constraints (alloc + copy + field)
        # 4. Solve to fixed point
        ...

    def query_var(self, name: str, at_node: Node) -> PointsToSet:
        """LEGB lookup: return the solved pt-set for `name` at `at_node`."""

    def query_field(self, attr: str, at_node: Node) -> PointsToSet:
        """Return the solved pt-set for `self.attr` in the enclosing class."""

    def scope_for(self, node: Node) -> Scope:
        """Return the innermost scope containing `node`."""
```

**Internal functions (private, one per compiler sub-pass):**

| Function | Responsibility | Lines |
|---|---|---|
| `_build_scope_tree(root, src)` | Walk CST, push/pop scopes at scope-introducing nodes | ~30 |
| `_harvest_return_types(scopes, src, known)` | Extract `-> RetType` annotations from function defs | ~15 |
| `_generate_constraints(root, src, scopes, known)` | Walk assignments, emit alloc/copy/field constraints | ~50 |
| `_solve(scopes, constraints)` | Worklist propagation to fixed point | ~25 |
| `_legb_lookup(name, scope)` | Walk scope chain per Python's LEGB rule | ~15 |
| `_find_enclosing_class(scope)` | Walk up scope chain to find the nearest class scope | ~8 |
| `_extract_constructor_class(rhs_node, src, known)` | From a call RHS node, return class name if it's a known constructor | ~12 |

**Separation of constraint generation from solving.** Constraints are generated as
a list of tuples in one pass, then solved in a separate function. This is standard
compiler practice — it allows the constraint language to be tested independently
from the solver, and makes it easy to dump constraints for debugging.

### Modified module: `src/iamspy/scanner.py`

**Deleted functions** (replaced by `type_inference.py`):

- `_build_var_type_map` — replaced by `PointsToAnalysis.__init__`
- `_collect_assignments` — replaced by `_generate_constraints`
- `_try_extract_constructor_assignment` — replaced by `_extract_constructor_class`

**Modified functions:**

| Function | Change |
|---|---|
| `_extract_receiver_name` | Renamed to `_extract_receiver`. Returns `ReceiverInfo` (see below) instead of `str \| None`. Handles `self.attr` patterns. |
| `scan_source` | Creates `PointsToAnalysis(root, src, known_classes)` instead of `_build_var_type_map`. Passes the analysis into `_walk`. |
| `_walk` | Replaces `var_type_map: dict` arg with `pta: PointsToAnalysis`. |
| `_check_call` | Queries `pta.query_var` / `pta.query_field`. Classifies result into `Resolution`. Attaches to `Finding`. |
| `_resolve` | Accepts `receiver_classes: PointsToSet` instead of `receiver_class: str \| None`. When `AMBIGUOUS`, resolves each class independently via `_resolve_classes`, then unions results via `_merge_permission_results` (deduplicates permissions, preserves first-appearance order, unions conditional permissions). Falls back to first-match-wins across matched sigs when `UNRESOLVED`. |

**New type in `scanner.py`:**

```python
@dataclass(frozen=True)
class ReceiverInfo:
    """Parsed receiver of a method call."""
    kind: Literal["var", "self_attr", "obj_attr", "none"]
    name: str | None = None      # variable name or attribute name
    obj_name: str | None = None  # for obj_attr: the object variable name
```

This replaces the bare `str | None` return of `_extract_receiver_name`. The `kind`
field tells `_check_call` which query method to call:
- `"var"` -> `pta.query_var(name, node)` — standard LEGB lookup
- `"self_attr"` -> `pta.query_field(name, node)` — `self.attr` in enclosing class
- `"obj_attr"` -> `pta.query_obj_attr(obj_name, name, node)` — two-step field load (S12)
- `"none"` -> no receiver to resolve, fall through to UNRESOLVED

### Already done: `models.py`

`Resolution` enum and `Finding.resolution` field are already implemented.
`PermissionResult.status` bug is already fixed.

### Data flow summary

```
scan_source(source):
  1. parse → tree-sitter CST
  2. detect_gcp_imports(tree) → imported_services
  3. known_classes = {sig.class_name for sigs in db.values() for sig in sigs}
  4. pta = PointsToAnalysis(root, src, known_classes)       ← NEW
  5. _walk(root, src, result, imported_services, pta)       ← CHANGED
       └─ _check_call(node, src, result, imported_services, pta)
            ├─ receiver = _extract_receiver(node, src)      ← CHANGED
            ├─ if receiver.kind == "var":
            │    pt_set = pta.query_var(receiver.name, node)
            ├─ elif receiver.kind == "self_attr":
            │    pt_set = pta.query_field(receiver.name, node)
            ├─ elif receiver.kind == "obj_attr":
            │    pt_set = pta.query_obj_attr(receiver.obj_name, receiver.name, node)
            ├─ resolution = classify(pt_set)
            └─ _resolve(method_name, matched, pt_set) → PermissionResult
```

### Rollout order

Each step is a self-contained change that leaves all existing tests passing.

1. **Create `type_inference.py`** with `Scope`, `_build_scope_tree`,
   `_generate_constraints`, `_solve`, `PointsToAnalysis`. Unit-test the analysis
   in isolation with `test_type_inference.py`.

2. **Wire into `scanner.py`**: replace `_build_var_type_map` call in `scan_source`
   with `PointsToAnalysis`. Replace `_extract_receiver_name` with
   `_extract_receiver`. Update `_check_call` and `_resolve`. Delete old functions.
   All existing scanner tests must pass (behavioral equivalence on S1 patterns).

3. **Add exit-criterion tests** for S2–S5, S8, S10–S11 in `test_scanner.py`.
   These tests initially validate the new capabilities (scope isolation, self.attr,
   branch merge, copy constraints, annotated factories).
