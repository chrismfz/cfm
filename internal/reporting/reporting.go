package reporting

type Reporter interface {
    ReportBlock(ip, reason, source, mode string, ttlSec int) error
    // ReportLenient records a per-server, short-lived block centrally for
    // visibility only. The receiver stores it on a list that is never served
    // to the farm, so a softly-blocked known-good origin is not propagated.
    ReportLenient(ip, reason, source, mode string, ttlSec int) error
    ReportUnblock(ip, source, why string) error
}
