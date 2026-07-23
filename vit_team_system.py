#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 VIT OPEN-PROJECT ALLOCATION SYSTEM
 Teams (2 SCOPE + 3 other schools) | Duplicate detection | FFCS-style faculty
================================================================================

WHY THIS SCRIPT EXISTS
----------------------
Freshers are put into open-project teams of 5. The rule:
    * exactly 2 members must be from SCOPE (Computer Science school), and
    * the other 3 must each come from a DIFFERENT school.
Teams then connect to a project coordinator and pick a project faculty
(a teacher) the way VIT's FFCS course registration works: you have a ranked
wishlist of faculty, seats are limited, and it is first-come-first-served.

This runs entirely on its own - it does NOT read anything from VTOP. You feed
it a plain list of registration numbers, and it does everything in memory. It is
built to handle a full batch of 10,000 students in one shot.

--------------------------------------------------------------------------------
THE DSA / DAA CHOICES  (this is the "explain whatever you generated" part)
--------------------------------------------------------------------------------
Every heavy operation is chosen so the whole pipeline stays O(n) on average.
For n = 10,000 that is the difference between "instant" and "hangs".

1. ROSTER LOOKUP  ->  hash map  (Python dict)   :  O(1) average per lookup
   reg number -> Student object. We look people up thousands of times while
   forming teams and allocating faculty; a dict makes each lookup O(1).

2. DUPLICATE DETECTION  ->  hash set  (Python set)   :  O(n) total
   The obvious way - compare every pair of students - is O(n^2). For 10,000
   students that is 100,000,000 comparisons. Sorting first would be O(n log n).
   A hash set gives us O(1) "have I seen this reg before?", so scanning the
   entire list for duplicates is O(n). At n=10,000 this is the single biggest
   speed win in the program.

3. GROUP-BY-SCHOOL  ->  hash map of queues  (dict of collections.deque) : O(n)
   To build a team we need "give me one student from school X". Bucketing every
   student into their school's queue once (O(n)) turns each pick into an O(1)
   popleft().

4. TEAM FORMATION  ->  greedy algorithm over the buckets   :  O(n)
   Each team consumes 2 SCOPE + 3 distinct-school students. We greedily draw the
   3 "other" members from the schools that currently have the MOST students left.
   Pulling from the largest buckets keeps the buckets balanced, which lets us
   build the maximum number of complete teams (a classic greedy-balancing idea).
   There are only ~15 schools, so choosing the top-3 buckets each round is a
   constant-time step; total work stays linear.

5. FFCS FACULTY ALLOCATION  ->  hash map of seat counters  :  O(1) per team
   Each faculty has a seat limit (capacity). A dict faculty -> seats_left lets
   us check-and-book a seat in O(1). Teams are processed in registration order,
   and each team is given the highest-ranked faculty on its wishlist that still
   has a free seat - exactly how FFCS fills slots first-come-first-served.

OVERALL COMPLEXITY:  Time O(n), Space O(n).  Proven fast for 10,000 below.
================================================================================
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import time
import random


# =============================================================================
# 1. BRANCH-CODE  ->  SCHOOL  reference table
# -----------------------------------------------------------------------------
# A VIT registration number looks like:  24 BCE 2312
#     24   = batch/admission year
#     BCE  = 3-letter BRANCH code  -> tells us the SCHOOL   <-- the important bit
#     2312 = roll number
#
# NOTE: only BCE (core CSE) is certain. The rest are common guesses - correct
# them for your own batch. Any CSE program (all specializations) is SCOPE.
# =============================================================================
BRANCH_TABLE = {
    # code : (school label, is_scope)
    "BCE": ("SCOPE - Computer Science & Engineering",        True),
    "BAI": ("SCOPE - CSE (AI & Machine Learning)",           True),
    "BCI": ("SCOPE - CSE (AI & Robotics)",                   True),
    "BPS": ("SCOPE - CSE (specialization)",                  True),
    "BDS": ("SCOPE - CSE (Data Science)",                    True),
    "BKT": ("SCOPE - CSE (specialization)",                  True),
    "BEC": ("SENSE - Electronics & Communication",           False),
    "BEE": ("SELECT - Electrical & Electronics",             False),
    "BME": ("SMEC - Mechanical Engineering",                 False),
    "BMD": ("SMEC - Mechatronics",                           False),
    "BCH": ("SCHEME - Chemical Engineering",                 False),
    "BCV": ("SCE - Civil Engineering",                       False),
    "BBT": ("SBST - Biotechnology",                          False),
}

TEAM_SIZE = 5
SCOPE_REQUIRED = 2          # exactly this many SCOPE members
OTHER_REQUIRED = 3          # exactly this many non-SCOPE members
REQUIRE_DISTINCT_SCHOOLS = True   # the 3 "other" members must be from 3 schools


# =============================================================================
# 2. THE STUDENT RECORD
# =============================================================================
@dataclass
class Student:
    reg: str            # e.g. "24BCE2312"
    name: str = ""
    code: str = ""      # e.g. "BCE"
    school: str = "Unknown code"
    is_scope: bool = False
    known: bool = False # True if the branch code was found in BRANCH_TABLE


def parse_registration(raw: str) -> Student | None:
    """
    Validate + decode a single registration number.  O(1).
    Returns a Student, or None if the string is not a valid reg number.
    Format enforced:  2 digits, 3 letters, 4 digits.
    """
    reg = "".join(str(raw).strip().upper().split())   # strip spaces, upper-case
    if len(reg) != 9:
        return None
    year, code, roll = reg[:2], reg[2:5], reg[5:]
    if not (year.isdigit() and code.isalpha() and roll.isdigit()):
        return None
    school, is_scope = BRANCH_TABLE.get(code, ("Unknown code", False))
    return Student(
        reg=reg, code=code, school=school,
        is_scope=is_scope, known=code in BRANCH_TABLE,
    )


# =============================================================================
# 3. DUPLICATE DETECTION  (hash set  ->  O(n))
# =============================================================================
def build_roster(raw_rows: list[str]):
    """
    Turn raw input lines into a clean, DE-DUPLICATED roster.

    Data structures:
        seen     : set   -> O(1) "have I already got this reg number?"
        roster   : dict  -> reg -> Student, O(1) lookups later on

    Returns (roster_dict, report_dict).  Total cost: O(n).
    """
    seen = set()
    roster = {}
    duplicates, invalid, unknown_codes = [], [], set()

    for row in raw_rows:                          # O(n) - one pass over input
        parts = [p.strip() for p in row.replace(";", ",").split(",")]
        student = parse_registration(parts[0]) if parts and parts[0] else None
        if student is None:
            if row.strip():
                invalid.append(row.strip())
            continue
        if len(parts) > 1:
            student.name = parts[1]
        if student.reg in seen:                   # O(1) duplicate check
            duplicates.append(student.reg)
            continue
        seen.add(student.reg)                     # O(1) insert
        roster[student.reg] = student             # O(1) insert
        if not student.known:
            unknown_codes.add(student.code)

    report = {
        "total_valid": len(roster),
        "duplicates": duplicates,
        "invalid": invalid,
        "unknown_codes": sorted(unknown_codes),
    }
    return roster, report


def find_cross_team_duplicates(teams: list[list[Student]]) -> dict:
    """
    Safety check: is any single student placed in MORE THAN ONE team?
    A hash map reg -> team_index catches it in one O(n) pass instead of
    comparing every team against every other team (which would be O(teams^2)).
    """
    where = {}                    # reg -> first team index seen
    clashes = []
    for t_idx, members in enumerate(teams):
        for m in members:
            if m.reg in where:    # O(1)
                clashes.append((m.reg, where[m.reg], t_idx))
            else:
                where[m.reg] = t_idx
    return {"clashes": clashes, "ok": not clashes}


# =============================================================================
# 4. TEAM FORMATION  (greedy over school buckets  ->  O(n))
# =============================================================================
def form_teams(roster: dict):
    """
    Build as many valid teams as possible.
    Each team = 2 SCOPE + 3 members from 3 DIFFERENT other schools.

    Data structures:
        scope_pool : deque             -> the SCOPE students, O(1) popleft
        buckets    : dict[school,deque]-> non-SCOPE students grouped by school

    Greedy rule: for the 3 "other" seats, always draw from the 3 schools that
    currently have the most students waiting. Keeping the biggest buckets
    drained keeps every bucket roughly balanced, which maximizes how many
    complete teams we can form. Runs in O(n).
    """
    scope_pool = deque(s for s in roster.values() if s.is_scope)
    buckets = defaultdict(deque)
    for s in roster.values():                     # O(n) bucketing
        if not s.is_scope and s.known:
            buckets[s.school].append(s)

    teams = []
    while len(scope_pool) >= SCOPE_REQUIRED:
        # non-empty other-school buckets, largest first  (~15 schools => O(1))
        live = sorted((sch for sch, dq in buckets.items() if dq),
                      key=lambda sch: len(buckets[sch]), reverse=True)
        if len(live) < OTHER_REQUIRED:
            break                                 # not enough distinct schools

        chosen = live[:OTHER_REQUIRED]
        members = [scope_pool.popleft() for _ in range(SCOPE_REQUIRED)]
        members += [buckets[sch].popleft() for sch in chosen]
        teams.append(members)

    # Whoever could not be placed into a complete valid team:
    leftover = list(scope_pool) + [s for dq in buckets.values() for s in dq]
    return teams, leftover


def validate_team(members: list[Student]) -> tuple[bool, list[str]]:
    """Independently re-check a team against the rule. Useful for audits."""
    problems = []
    scope = [m for m in members if m.is_scope]
    other = [m for m in members if not m.is_scope and m.known]
    unknown = [m for m in members if not m.known]
    if len(members) != TEAM_SIZE:
        problems.append(f"team has {len(members)}/{TEAM_SIZE} members")
    if len(scope) != SCOPE_REQUIRED:
        problems.append(f"needs {SCOPE_REQUIRED} SCOPE, has {len(scope)}")
    if len(other) != OTHER_REQUIRED:
        problems.append(f"needs {OTHER_REQUIRED} other-school, has {len(other)}")
    if unknown:
        problems.append(f"{len(unknown)} member(s) with unknown branch code")
    if REQUIRE_DISTINCT_SCHOOLS:
        schools = [m.school for m in other]
        if len(set(schools)) != len(schools):
            problems.append("the 3 other-school members repeat a school")
    return (not problems), problems


# =============================================================================
# 5. COORDINATOR  (teams connect / register here)
# =============================================================================
@dataclass
class Coordinator:
    name: str
    email: str
    teams: list = field(default_factory=list)

    def register_team(self, team_id: str, members: list[Student]):
        """A team 'connects to the coordinator' by registering. O(1)."""
        self.teams.append({"team_id": team_id, "members": members})


# =============================================================================
# 6. FFCS-STYLE FACULTY ALLOCATION  (seat counters in a hash map -> O(1)/team)
# =============================================================================
@dataclass
class FacultyAllocator:
    """
    Mimics FFCS: each faculty has a limited number of project seats. Teams
    register in order and get the highest-ranked faculty on their wishlist
    that still has a free seat. First-come-first-served, hard seat cap, no
    double-booking - all in O(1) per team using a dict of seat counters.
    """
    capacity: dict                      # faculty name -> total project seats
    seats_left: dict = field(init=False)
    assignment: dict = field(default_factory=dict)   # team_id -> faculty
    faculty_teams: dict = field(default_factory=lambda: defaultdict(list))
    waitlist: list = field(default_factory=list)      # teams that got nothing

    def __post_init__(self):
        self.seats_left = dict(self.capacity)         # O(F) one-time copy

    def allocate(self, team_id: str, wishlist: list[str]):
        """Give team_id its best available faculty. O(len(wishlist))."""
        for faculty in wishlist:                      # ranked preferences
            if self.seats_left.get(faculty, 0) > 0:   # O(1) seat check
                self.seats_left[faculty] -= 1          # O(1) book the seat
                self.assignment[team_id] = faculty
                self.faculty_teams[faculty].append(team_id)
                return faculty
        self.waitlist.append(team_id)                 # every choice was full
        return None


# =============================================================================
# 7. DEMO / SELF-TEST  -  proves it handles 10,000 students at once
# =============================================================================
def _synthetic_rows(n: int, seed: int = 7) -> list[str]:
    """Generate n fake-but-valid registration numbers for a stress test."""
    rng = random.Random(seed)
    codes = list(BRANCH_TABLE.keys())
    # ~40% SCOPE so realistic 2-per-team supply; rest spread over other schools
    scope_codes = [c for c in codes if BRANCH_TABLE[c][1]]
    other_codes = [c for c in codes if not BRANCH_TABLE[c][1]]
    rows, used = [], set()
    while len(rows) < n:
        code = rng.choice(scope_codes if rng.random() < 0.40 else other_codes)
        reg = f"24{code}{rng.randint(1000, 9999)}"
        if reg in used:                 # avoid accidental dup in the generator
            continue
        used.add(reg)
        rows.append(f"{reg}, Student{len(rows)+1}")
    # deliberately inject a few duplicates to show detection works
    rows += rows[:5]
    return rows


def run_demo(n: int = 10_000):
    print("=" * 70)
    print(f" VIT OPEN-PROJECT ALLOCATION  -  stress test with {n:,} students")
    print("=" * 70)

    rows = _synthetic_rows(n)
    t0 = time.perf_counter()

    # --- Step 1: build roster + detect duplicates (hash set, O(n)) -----------
    roster, report = build_roster(rows)
    t1 = time.perf_counter()
    print(f"\n[1] Roster built + duplicates removed")
    print(f"    valid unique students : {report['total_valid']:,}")
    print(f"    duplicate regs dropped : {len(report['duplicates'])}"
          f"  e.g. {report['duplicates'][:3]}")
    print(f"    invalid rows           : {len(report['invalid'])}")
    print(f"    time                   : {(t1-t0)*1000:.1f} ms")

    # --- Step 2: form teams (greedy over buckets, O(n)) ----------------------
    teams, leftover = form_teams(roster)
    t2 = time.perf_counter()
    print(f"\n[2] Teams formed (2 SCOPE + 3 distinct other schools)")
    print(f"    complete teams         : {len(teams):,}")
    print(f"    students placed        : {len(teams)*TEAM_SIZE:,}")
    print(f"    left over (unplaced)   : {len(leftover):,}")
    print(f"    time                   : {(t2-t1)*1000:.1f} ms")

    # audit: every team really satisfies the rule?
    all_valid = all(validate_team(t)[0] for t in teams)
    dup_check = find_cross_team_duplicates(teams)
    print(f"    all teams valid?       : {all_valid}")
    print(f"    no student in 2 teams? : {dup_check['ok']}")

    # --- Step 3: coordinator + FFCS-style faculty allocation -----------------
    coordinator = Coordinator("Dr. Project Coordinator", "coord@vit.ac.in")
    # e.g. 30 faculty, capacity chosen so ~everyone can be seated
    faculty_names = [f"Prof_{i:02d}" for i in range(30)]
    seats_each = max(1, (len(teams) // len(faculty_names)) + 2)
    allocator = FacultyAllocator(capacity={f: seats_each for f in faculty_names})

    rng = random.Random(11)
    for i, members in enumerate(teams):
        team_id = f"T{i+1:04d}"
        coordinator.register_team(team_id, members)          # connect to coord
        wishlist = rng.sample(faculty_names, k=5)             # 5 ranked choices
        allocator.allocate(team_id, wishlist)                # FFCS FCFS booking
    t3 = time.perf_counter()

    seated = len(allocator.assignment)
    print(f"\n[3] Coordinator + FFCS faculty allocation")
    print(f"    faculty available      : {len(faculty_names)} "
          f"({seats_each} seats each)")
    print(f"    teams registered w/coord: {len(coordinator.teams):,}")
    print(f"    teams given a faculty  : {seated:,}")
    print(f"    teams waitlisted       : {len(allocator.waitlist):,}")
    print(f"    time                   : {(t3-t2)*1000:.1f} ms")

    print(f"\n[=] TOTAL end-to-end time  : {(t3-t0)*1000:.1f} ms "
          f"for {n:,} students")

    # --- show one real example team ------------------------------------------
    if teams:
        print("\n" + "-" * 70)
        print(" SAMPLE TEAM (T0001)")
        print("-" * 70)
        for m in teams[0]:
            tag = "SCOPE" if m.is_scope else "other"
            print(f"   {m.reg:12} [{tag:5}] {m.school}")
        print(f"   faculty assigned      : {allocator.assignment.get('T0001')}")
        print(f"   coordinator           : {coordinator.name}")


if __name__ == "__main__":
    run_demo(10_000)
