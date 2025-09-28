# Clustering / Crew-to-Vehicle Allocation — Logic Overview

This README explains the allocation logic implemented in **`calculations.py`**, which assigns crews of different sizes to available vehicles (cars, vans, buses) subject to simple capacity rules and an ordering strategy that aims to maximize feasible placements.

> **Scope:** The descriptions below are based on the current contents of `calculations.py` contained in the uploaded archive. The file implements four main functions focused on counting/allocating crews into vehicles, rather than running geometric clustering (e.g., k-means/DBSCAN).

---

## File & Functions

- **`calculations.py`**
  - `singlevans(vans, singlecrews) -> tuple[int, int]`
  - `triplevans(vans, triplecrews) -> tuple[int, int]`
  - `triplesingle(vans, triple, single) -> list[int] | tuple[...]`
  - `cluster(singlesites, doublesites, triplesites, carclusters, vanclusters, buscapacities) -> list`

There are no classes and no external dependencies besides the Python standard library (`math`).

---

## Core Concepts & Assumptions

- **Crew sizes:** Three “crew” types are considered via counters:
  - `singlesites` (size‑1 crews)
  - `doublesites` (size‑2 crews)
  - `triplesites` (size‑3 crews)

- **Vehicles:** Three vehicle types are represented via **counts of available slots/clusters**, not physical capacities in seats:
  - `carclusters` — each car can carry **one cluster** (modeled as a single placement unit).
  - `vanclusters` — each van is treated as **two half‑slots**, allowing either:
    - two singles (1+1), or
    - one double (2), or
    - part of a mixed triple/single split depending on the helper function `triplesingle`.
  - `buscapacities` — total number of **double clusters** that can be absorbed by buses. (From the code pattern, buses are used to soak up groups of size‑2 first where possible.)

- **Ordering Strategy (as implemented in `cluster`)**:
  1. **Place doubles in vans** up to the number of available van half‑slots.
  2. **Place triples in cars** (cars handle them one cluster at a time).
  3. **Place doubles in cars** with any remaining car capacity.
  4. **Use van–car combinations** to resolve remaining doubles/triples in the most space‑efficient way (variable name `vanCarCombo` appears in code).
  5. **Place singles in cars first**, then **fill remaining van capacity with singles** (two singles per van).
  6. Compute a **breakdown of vans** across triples/singles via `triplesingle(...)`.
  7. Return a compact **summary list** with the placements and the leftover capacity.

This ordering tries to keep cars from being underutilized by singles, pushes multi‑crews into vehicles that can “absorb” them efficiently, and uses vans flexibly due to their “two half‑slots” nature.

---

## Function–by–Function

### `singlevans(vans, singlecrews)`
Determines how many single crews can **own a van** outright vs. how many must be **paired** together (two singles per van).

**Logic outline:**  
- If `vans >= singlecrews`, every single can get its **own** van (`paired = 0`).  
- If `2*vans < singlecrews`, all van slots are filled by **paired** singles (`paired = 2*vans`, `own = 0`).  
- Otherwise, some singles get individual vans and the remainder are paired so that total singles assigned equals the available van capacity.

**Returns:** `(own, paired)` where:
- `own` = number of singles who ride alone in a van,
- `paired` = number of singles that are paired (this count equals **the number of single riders**, not the number of vans used; two paired singles consume one van).

---

### `triplevans(vans, triplecrews)`
Allocates triple crews into vans, presumably using **two half‑slots per van** and a pairing rule similar in spirit to `singlevans`.  
(Portions of the source lines are redacted in the provided file, but the signature and variables imply an **allocation of 3‑person crews into available van capacity** with an own/pairing trade‑off.)

**Returns:** a small tuple of counts describing how many triple crews are placed using van capacity.

---

### `triplesingle(vans, triple, single)`
Computes a detailed **van breakdown** when vans must accommodate a **mixture** of triple and single crews. This is called by `cluster(...)` after preliminary placements to finalize how many vans end up as:
- triple‑only,
- single‑only (one or two singles),
- mixed (if such a configuration is supported by the internal logic).

**Returns:** A structure (list/tuple of ints) representing the van composition after mixing triples and singles given the remaining `vans` and remaining `triple`/`single` counts.

---

### `cluster(singlesites, doublesites, triplesites, carclusters, vanclusters, buscapacities)`

This is the **main orchestration function**. It consumes counts of crews and vehicle slots and returns a **summary** of the final allocation + leftovers.

**High‑level flow (inferred from visible code):**

1. **Initialize working copies** of `carclusters` (cars), `vanclusters` (vans), and save `initialVans = vanclusters` for later accounting.
2. **Doubles into vans**: Fill as many doubles as possible into vans (each double consumes one full van, i.e., two half‑slots). Update counters.
3. **Triples into cars**: Allocate triples to car slots first (`triplesInCars`). Update counters.
4. **Doubles into cars**: Allocate remaining doubles into car slots (`doublesInCars`). Update counters.
5. **Van–Car Combo**: A variable named `vanCarCombo` suggests a **joint strategy** to absorb remaining doubles/triples using a combination of any leftover van half‑slots and car slots.
6. **Singles into cars**: Place singles into the remaining car slots (`singlesInCars`), then update counters.
7. **Singles into vans**: Place remaining singles into vans (`singlesInVans = min(singlesites, int(vanclusters*2))`), two singles per van, then update `vanclusters` accordingly.
8. **Finalize vans with `triplesingle`**: Call `VanList = triplesingle(initialVans - doublesInVans - vanCarCombo, triplesInVans, singlesInVans)` to compute the **van composition** after all above steps.
9. **Collect leftovers**: `remain = [carclusters, 2*int(vanclusters)]` — cars left and van half‑slots left.
10. **Return a compact result list**:
    ```python
    finalList = [
        int(singlesInCars),
        int(doublesInVans),
        int(doublesInCars),
        int(vanCarCombo),
        int(triplesInCars),
        VanList,
        remain,
    ]
    ```

> **Note on return format:** The positions encode a fixed schema:
> 1. singles placed in cars  
> 2. doubles placed in vans  
> 3. doubles placed in cars  
> 4. van–car combo used  
> 5. triples placed in cars  
> 6. detailed van composition list (from `triplesingle`)  
> 7. remaining capacity: `[remaining_car_slots, remaining_van_half_slots]`

