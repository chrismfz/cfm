// internal/ipquery/feeds.go
package ipquery

// FeedsBlocking επιστρέφει τα feeds (ονόματα ή IDs) που “πιάνουν” το ipStr.
// Implementation: re-use των δομών/ευρετηρίων που ήδη διαβάζεις για το which().
func FeedsBlocking(ipStr string) ([]string, error) {
    hits, err := Find(ipStr) // υπάρχει ήδη
    if err != nil { return nil, err }
    uniq := map[string]struct{}{}
    var out []string
    for _, h := range hits {
        if h.Feed == "" { continue }
        if _, ok := uniq[h.Feed]; ok { continue }
        uniq[h.Feed] = struct{}{}
        out = append(out, h.Feed)
    }
    return out, nil
}
