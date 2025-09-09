package reporting

type Reporter interface {
    ReportBlock(ip, reason, source, mode string, ttlSec int) error
    ReportUnblock(ip, source, why string) error
}
