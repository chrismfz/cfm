package webdetector

const (
	challengeEventsDefaultLimit = 200
	challengeEventsMaxLimit     = 2000
)

func clampChallengeEventsLimit(limit int) int {
	if limit <= 0 {
		return challengeEventsDefaultLimit
	}
	if limit > challengeEventsMaxLimit {
		return challengeEventsMaxLimit
	}
	return limit
}
