//go:build linux

// Inspection methods delegate to the embedded nft.Backend.
// Native nftlib implementations (using conn.GetSetElements) will replace
// these in a later phase.
package nftlib

func (b *Backend) HasElem(setName, elem string) (bool, error) {
	return b.cli.HasElem(setName, elem)
}

func (b *Backend) ListSetElementsRaw(setName string) ([]string, error) {
	return b.cli.ListSetElementsRaw(setName)
}

func (b *Backend) ListTableJSON(family, table string) ([]byte, error) {
	return b.cli.ListTableJSON(family, table)
}

func (b *Backend) ListSetJSON(family, table, set string) ([]byte, error) {
	return b.cli.ListSetJSON(family, table, set)
}

func (b *Backend) ListTableTextNoDNS(family, table string) (string, error) {
	return b.cli.ListTableTextNoDNS(family, table)
}

func (b *Backend) ListChainText(family, table, chain string) (string, error) {
	return b.cli.ListChainText(family, table, chain)
}
