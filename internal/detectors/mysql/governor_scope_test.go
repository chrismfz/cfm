package mysql

import "testing"

// A tenant sees only its own connections in the lock graph. The graph groups
// waiters by database name alone, so a group whose blocker is the tenant's
// can hold other accounts' connections — most of all the DB-less group every
// connection with no default database falls into.
func TestFilterGovernorStateLockGraphKeepsOnlyOwnWaiters(t *testing.T) {
	st := GovernorState{LockGraph: []LockGroup{
		{ // DB-less group: alice's blocker, waiters from everyone
			Blocker: Process{ID: 1, User: "alice", DB: "", Command: "Query", State: "User sleep", Info: "SELECT SLEEP(3000)"},
			Waiters: []Process{
				{ID: 2, User: "bob", Host: "10.0.0.2:5000", DB: "", State: "Waiting for table metadata lock", Info: "ALTER TABLE bob_wp.t"},
				{ID: 3, User: "event_scheduler", DB: "", State: "Waiting on empty queue"},
				{ID: 4, User: "alice_ro", DB: "", State: "Waiting for table metadata lock", Info: "SELECT 1"},
			},
		},
		{ // alice's DB: alice's blocker, only bob waits
			Blocker: Process{ID: 5, User: "alice", DB: "alice_wp", Command: "Query"},
			Waiters: []Process{{ID: 6, User: "bob", DB: "bob_wp", State: "Waiting for table level lock"}},
		},
		{ // bob's group: never shown
			Blocker: Process{ID: 7, User: "bob", DB: "bob_wp", Command: "Query"},
			Waiters: []Process{{ID: 8, User: "alice", DB: "bob_wp", State: "Waiting for table level lock"}},
		},
	}}
	out := filterGovernorState(st, []string{"alice", "alice_*"}, []string{"alice_*"})
	if len(out.LockGraph) != 1 {
		t.Fatalf("lock groups = %+v, want only the DB-less group with alice's own waiter", out.LockGraph)
	}
	lg := out.LockGraph[0]
	if lg.Blocker.ID != 1 || lg.Blocker.Info != "" {
		t.Errorf("blocker = %+v", lg.Blocker)
	}
	if len(lg.Waiters) != 1 || lg.Waiters[0].ID != 4 || lg.Waiters[0].Info != "" {
		t.Errorf("waiters = %+v, want only id 4 with no query text", lg.Waiters)
	}
}
