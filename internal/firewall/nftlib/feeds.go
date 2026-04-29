//go:build linux

// Feed management methods delegate to the embedded nft.Backend.
// Native nftlib implementations will replace these in a later phase.
package nftlib

import (
	"context"

	"cfm/internal/blocklists"
)

func (b *Backend) ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error {
	return b.cli.ApplyFeed(ctx, f, res)
}

func (b *Backend) RebuildExternalUnions() error {
	return b.cli.RebuildExternalUnions()
}

func (b *Backend) PruneExternalFeeds(activeKeys []string) error {
	return b.cli.PruneExternalFeeds(activeKeys)
}

func (b *Backend) DropFeedSets(feedName string) {
	b.cli.DropFeedSets(feedName)
}

func (b *Backend) RemoveFeedByKey(feedKey string) error {
	return b.cli.RemoveFeedByKey(feedKey)
}
