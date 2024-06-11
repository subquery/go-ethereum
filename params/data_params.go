package params

type ChainDataConfig struct {
	DesiredChainDataStart  *uint64 `json:"desiredChainDataStart"`
	DesiredChainDataEnd    *uint64 `json:"desiredChainDataEnd"`
	DesiredChainStateStart *uint64 `json:"desiredChainStateStart"`
}

type ChainDataStatus struct {
	ChainDataStart   *uint64 `json:"chainDataStart"`
	ChainStateStart  *uint64 `json:"chainStateStart"`
	LatestHeight     *uint64 `json:"latestHeight"`
	AncientEndHeight *uint64 `json:"ancientEndHeight"`
}
