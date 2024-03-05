package core

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// BloomIndexer implements a core.ChainIndexer, building up a rotated bloom bits index
// for the Ethereum header bloom filters, permitting blazing fast filtering.
type TransactionBloomIndexer struct {
	size    uint64               // section size to generate bloombits for
	db      ethdb.Database       // database instance to write index data and metadata into
	gen     *bloombits.Generator // generator to rotate the bloom bits crating the bloom index
	section uint64               // Section is the section number being processed currently
	head    common.Hash          // Head is the hash of the last header processed
	config *params.ChainConfig
}

// NewTransactionBloomIndexer returns a chain indexer that generates bloom bits data for the
// canonical chain for transactions filtering.
func NewTransactionBloomIndexer(db ethdb.Database, chainConfig *params.ChainConfig, size, confirms uint64) *ChainIndexer {
	backend := &TransactionBloomIndexer{
		db:   db,
		size: size,
		config: chainConfig,
	}
	table := rawdb.NewTable(db, string(rawdb.BloomBitsTransactionIndexPrefix))

	return NewChainIndexer(db, table, backend, size, confirms, bloomThrottling, "transactionBloombits")
}

// Reset implements core.ChainIndexerBackend, starting a new bloombits index
// section.
func (b *TransactionBloomIndexer) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	gen, err := bloombits.NewGenerator(uint(b.size))
	b.gen, b.section, b.head = gen, section, common.Hash{}
	return err
}

// Process implements core.ChainIndexerBackend, adding a new header's bloom into
// the index.
func (b *TransactionBloomIndexer) Process(ctx context.Context, header *types.Header) error {
	// Get the bloom value from the db
	bloom, err := b.getOrCreateTxBloom(header)
	if err != nil {
		return err;
	}
	// Add the bloom value to the bloombits
	b.gen.AddBloom(uint(header.Number.Uint64()-b.section*b.size), *bloom)
	b.head = header.Hash()
	return nil
}

// Commit implements core.ChainIndexerBackend, finalizing the bloom section and
// writing it out into the database.
func (b *TransactionBloomIndexer) Commit() error {
	batch := b.db.NewBatchWithSize((int(b.size) / 8) * types.BloomBitLength)
	for i := 0; i < types.BloomBitLength; i++ {
		bits, err := b.gen.Bitset(uint(i))
		if err != nil {
			return err
		}
		rawdb.WriteTransactionBloomBits(batch, uint(i), b.section, b.head, bitutil.CompressBytes(bits))
	}
	return batch.Write()
}

// Prune returns an empty error since we don't support pruning here.
func (b *TransactionBloomIndexer) Prune(threshold uint64) error {
	return nil
}

// getOrCreateTxBloom fetches the transactions bloom for the block, if it doesn't exist it will create the transaction bloom and save it
func (b* TransactionBloomIndexer) getOrCreateTxBloom(header *types.Header) (*types.Bloom, error) {
	bloom := rawdb.ReadTxBloom(b.db, header.Hash(), header.Number.Uint64())

	if bloom == nil {
		block := rawdb.ReadBlock(b.db, header.Hash(), header.Number.Uint64())
		if block == nil {
			return nil, fmt.Errorf("Failed to get block to index transactions bloom. number='%v' hash='%v'", header.Number.Uint64(), header.Hash().Hex())
		}
		bloom = rawdb.WriteTxBloomByBlock(b.db, block, b.config)
	}

	bloomBytes := types.BytesToBloom(*bloom)

	return &bloomBytes, nil
}
