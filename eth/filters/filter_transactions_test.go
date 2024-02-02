// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package filters

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// func makeReceipt(addr common.Address) *types.Receipt {
// 	receipt := types.NewReceipt(nil, false, 0)
// 	receipt.Logs = []*types.Log{
// 		{Address: addr},
// 	}
// 	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
// 	return receipt
// }

// func BenchmarkTxFilters(b *testing.B) {
// 	var (
// 		db, _   = rawdb.NewLevelDBDatabase(b.TempDir(), 0, 0, "", false)
// 		_, sys  = newTestFilterSystem(b, db, Config{})
// 		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
// 		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
// 		addr2   = common.BytesToAddress([]byte("jeff"))
// 		addr3   = common.BytesToAddress([]byte("ethereum"))
// 		addr4   = common.BytesToAddress([]byte("random addresses please"))

// 		gspec = &core.Genesis{
// 			Alloc:   core.GenesisAlloc{addr1: {Balance: big.NewInt(1000000)}},
// 			BaseFee: big.NewInt(params.InitialBaseFee),
// 			Config:  params.TestChainConfig,
// 		}
// 	)
// 	defer db.Close()
// 	_, chain, receipts := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 100010, func(i int, gen *core.BlockGen) {
// 		switch i {
// 		case 2403:
// 			receipt := makeReceipt(addr1)
// 			gen.AddUncheckedReceipt(receipt)
// 			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
// 		case 1034:
// 			receipt := makeReceipt(addr2)
// 			gen.AddUncheckedReceipt(receipt)
// 			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
// 		case 34:
// 			receipt := makeReceipt(addr3)
// 			gen.AddUncheckedReceipt(receipt)
// 			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
// 		case 99999:
// 			receipt := makeReceipt(addr4)
// 			gen.AddUncheckedReceipt(receipt)
// 			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
// 		}
// 	})
// 	// The test txs are not properly signed, can't simply create a chain
// 	// and then import blocks. TODO(rjl493456442) try to get rid of the
// 	// manual database writes.
// 	gspec.MustCommit(db, trie.NewDatabase(db, trie.HashDefaults))

// 	for i, block := range chain {
// 		rawdb.WriteBlock(db, block, params.TestChainConfig)
// 		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
// 		rawdb.WriteHeadBlockHash(db, block.Hash())
// 		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
// 	}
// 	b.ResetTimer()

// 	filter := sys.NewRangeFilter(0, -1, []common.Address{addr1, addr2, addr3, addr4}, nil)

// 	for i := 0; i < b.N; i++ {
// 		logs, _ := filter.Logs(context.Background())
// 		if len(logs) != 4 {
// 			b.Fatal("expected 4 logs, got", len(logs))
// 		}
// 	}
// }

func TestTxFilters(t *testing.T) {
	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(t, db, Config{})
		// Sender account
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr    = crypto.PubkeyToAddress(key1.PublicKey)
		signer  = types.NewLondonSigner(big.NewInt(1))
		// Logging contract
		contract  = common.Address{0xfe}
		contract2 = common.Address{0xff}
		abiStr    = `[{"inputs":[],"name":"log0","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"}],"name":"log1","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"},{"internalType":"uint256","name":"t2","type":"uint256"}],"name":"log2","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"},{"internalType":"uint256","name":"t2","type":"uint256"},{"internalType":"uint256","name":"t3","type":"uint256"}],"name":"log3","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"},{"internalType":"uint256","name":"t2","type":"uint256"},{"internalType":"uint256","name":"t3","type":"uint256"},{"internalType":"uint256","name":"t4","type":"uint256"}],"name":"log4","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
		/*
			// SPDX-License-Identifier: GPL-3.0
			pragma solidity >=0.7.0 <0.9.0;

			contract Logger {
				function log0() external {
					assembly {
						log0(0, 0)
					}
				}

				function log1(uint t1) external {
					assembly {
						log1(0, 0, t1)
					}
				}

				function log2(uint t1, uint t2) external {
					assembly {
						log2(0, 0, t1, t2)
					}
				}

				function log3(uint t1, uint t2, uint t3) external {
					assembly {
						log3(0, 0, t1, t2, t3)
					}
				}

				function log4(uint t1, uint t2, uint t3, uint t4) external {
					assembly {
						log4(0, 0, t1, t2, t3, t4)
					}
				}
			}
		*/
		bytecode = common.FromHex("608060405234801561001057600080fd5b50600436106100575760003560e01c80630aa731851461005c5780632a4c08961461006657806378b9a1f314610082578063c670f8641461009e578063c683d6a3146100ba575b600080fd5b6100646100d6565b005b610080600480360381019061007b9190610143565b6100dc565b005b61009c60048036038101906100979190610196565b6100e8565b005b6100b860048036038101906100b391906101d6565b6100f2565b005b6100d460048036038101906100cf9190610203565b6100fa565b005b600080a0565b808284600080a3505050565b8082600080a25050565b80600080a150565b80828486600080a450505050565b600080fd5b6000819050919050565b6101208161010d565b811461012b57600080fd5b50565b60008135905061013d81610117565b92915050565b60008060006060848603121561015c5761015b610108565b5b600061016a8682870161012e565b935050602061017b8682870161012e565b925050604061018c8682870161012e565b9150509250925092565b600080604083850312156101ad576101ac610108565b5b60006101bb8582860161012e565b92505060206101cc8582860161012e565b9150509250929050565b6000602082840312156101ec576101eb610108565b5b60006101fa8482850161012e565b91505092915050565b6000806000806080858703121561021d5761021c610108565b5b600061022b8782880161012e565b945050602061023c8782880161012e565b935050604061024d8782880161012e565b925050606061025e8782880161012e565b9150509295919450925056fea264697066735822122073a4b156f487e59970dc1ef449cc0d51467268f676033a17188edafcee861f9864736f6c63430008110033")

		hash1 = common.BytesToHash([]byte("topic1"))
		hash2 = common.BytesToHash([]byte("topic2"))
		hash3 = common.BytesToHash([]byte("topic3"))
		hash4 = common.BytesToHash([]byte("topic4"))
		hash5 = common.BytesToHash([]byte("topic5"))

		gspec = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc: core.GenesisAlloc{
				addr:      {Balance: big.NewInt(0).Mul(big.NewInt(100), big.NewInt(params.Ether))},
				contract:  {Balance: big.NewInt(0), Code: bytecode},
				contract2: {Balance: big.NewInt(0), Code: bytecode},
			},
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
	)

	contractABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		t.Fatal(err)
	}

	// Hack: GenerateChainWithGenesis creates a new db.
	// Commit the genesis manually and use GenerateChain.
	_, err = gspec.Commit(db, trie.NewDatabase(db, nil))
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := core.GenerateChain(gspec.Config, gspec.ToBlock(), ethash.NewFaker(), db, 1000, func(i int, gen *core.BlockGen) {
		switch i {
		case 1:
			data, err := contractABI.Pack("log1", hash1.Big())
			if err != nil {
				t.Fatal(err)
			}
			tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    0,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &contract,
				Data:     data,
			}), signer, key1)
			gen.AddTx(tx)
			tx2, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    1,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &contract2,
				Data:     data,
			}), signer, key1)
			gen.AddTx(tx2)
		case 2:
			data, err := contractABI.Pack("log2", hash2.Big(), hash1.Big())
			if err != nil {
				t.Fatal(err)
			}
			tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    2,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &contract,
				Data:     data,
			}), signer, key1)
			gen.AddTx(tx)
		case 3:
			tx, _ := types.SignTx(types.NewContractCreation(3, big.NewInt(0), 63152, gen.BaseFee(), bytecode), signer, key1)
			gen.AddTx(tx)
		case 4:
			tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    4,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &addr,
				Value:    big.NewInt(1),
			}), signer, key1)
			gen.AddTx(tx)
		case 998:
			data, err := contractABI.Pack("log1", hash3.Big())
			if err != nil {
				t.Fatal(err)
			}
			tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    5,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &contract2,
				Data:     data,
			}), signer, key1)
			gen.AddTx(tx)
		case 999:
			data, err := contractABI.Pack("log1", hash4.Big())
			if err != nil {
				t.Fatal(err)
			}
			tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    6,
				GasPrice: gen.BaseFee(),
				Gas:      30000,
				To:       &contract,
				Data:     data,
			}), signer, key1)
			gen.AddTx(tx)
		}
	})
	var l uint64
	bc, err := core.NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, &l)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bc.InsertChain(chain)
	if err != nil {
		t.Fatal(err)
	}

	// Set block 998 as Finalized (-3)
	bc.SetFinalized(chain[998].Header())

	// Generate pending block
	pchain, preceipts := core.GenerateChain(gspec.Config, chain[len(chain)-1], ethash.NewFaker(), db, 1, func(i int, gen *core.BlockGen) {
		data, err := contractABI.Pack("log1", hash5.Big())
		if err != nil {
			t.Fatal(err)
		}
		tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    7,
			GasPrice: gen.BaseFee(),
			Gas:      30000,
			To:       &contract,
			Data:     data,
		}), signer, key1)
		gen.AddTx(tx)
	})
	sys.backend.(*testBackend).pendingBlock = pchain[0]
	sys.backend.(*testBackend).pendingReceipts = preceipts[0]

	for i, tc := range []struct {
		f    *TxFilter
		want string
		err  string
	}{
		{
			f:    sys.NewTxBlockFilter(chain[2].Hash(), nil, []common.Address{contract}, nil),
			want: `[{"blockHash":"0x7a7556792ca7d37882882e2b001fe14833eaf81c2c7f865c9c771ec37a024f6b","blockNumber":"0x3","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x280a0d96","hash":"0xdefe471992a07a02acdfbe33edaae22fbb86d7d3cec3f1b8e4e77702fb3acc1d","input":"0x78b9a1f30000000000000000000000000000000000000000000000000000746f706963320000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x2","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x26","r":"0x8aadf3ab0e624f0a44d3a3f0b12d9b846162c0a84d06a898b81c9a81a749fccb","s":"0x1c0fe3b723da1d841448bb8ed05d3f889e2509282129159889a6e0f3729b64cc"}]`,
		},
		{
			f:    sys.NewTxRangeFilter(0, int64(rpc.LatestBlockNumber), 0, nil, []common.Address{contract}, [][]byte{common.Hex2Bytes("c670f864")}),
			want: `[{"blockHash":"0x24417bb49ce44cfad65da68f33b510bf2a129c0d89ccf06acb6958b8585ccf34","blockNumber":"0x2","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x2da282a8","hash":"0xa8028c655b6423204c8edfbc339f57b042d6bec2b6a61145d76b7c08b4cccd42","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x0","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xacd139f95e249a1d60fdb392ba0fa34a4fdc4f062203dc17f35f8e56f29d64d2","s":"0xcd785e8cdee241f414578e569da6ec152f432abeed61a7016dddffffa00c1c7"},{"blockHash":"0xb166569ffd2b8f9865e6333dfaada62d5027749c381ff568493b24d594f711ab","blockNumber":"0x3e8","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0xa919b50798f7ab32f2066b47e63d6225d69cbb9acbc7f3a4935f7c75919f78fc","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696334","nonce":"0x6","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0x2cc28a31219ceb5149bc5c7660d26943ac0d4e0aae7d08d5fc03d272928b08b0","s":"0x5a065f094e9143f6a1ba11cfe781ae3e979b9dc172c069f6edde4c3ad58162bc"}]`,
		},
		{
			f: sys.NewTxRangeFilter(900, 999, 0, nil, []common.Address{contract}, [][]byte{common.Hex2Bytes("2a4c0896")}),
		},
		{
			f:    sys.NewTxRangeFilter(990, int64(rpc.LatestBlockNumber), 0, []common.Address{addr}, nil, nil),
			want: `[{"blockHash":"0x36020790d78fb99953cba029042880e15cfb2c99ccfcc8521e8f3a687a3682e0","blockNumber":"0x3e7","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0x8753150337b296468cb8b177c7efc1380c56c98a4c08b9b9dcf240706fc304cb","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696333","nonce":"0x5","to":"0xff00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xcace86d5a4aa7c523dc21e5c2f5698beecd80a5f7773d39a89196d4d07853868","s":"0x2983ec62939515ac3a2971a88081f7720a95dc9ef18b9ae398b74132bda04308"},{"blockHash":"0xb166569ffd2b8f9865e6333dfaada62d5027749c381ff568493b24d594f711ab","blockNumber":"0x3e8","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0xa919b50798f7ab32f2066b47e63d6225d69cbb9acbc7f3a4935f7c75919f78fc","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696334","nonce":"0x6","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0x2cc28a31219ceb5149bc5c7660d26943ac0d4e0aae7d08d5fc03d272928b08b0","s":"0x5a065f094e9143f6a1ba11cfe781ae3e979b9dc172c069f6edde4c3ad58162bc"}]`,
		},
		{
			f:    sys.NewTxRangeFilter(990, int64(rpc.LatestBlockNumber), 0, []common.Address{addr}, []common.Address{contract2}, nil),
			want: `[{"blockHash":"0x36020790d78fb99953cba029042880e15cfb2c99ccfcc8521e8f3a687a3682e0","blockNumber":"0x3e7","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0x8753150337b296468cb8b177c7efc1380c56c98a4c08b9b9dcf240706fc304cb","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696333","nonce":"0x5","to":"0xff00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xcace86d5a4aa7c523dc21e5c2f5698beecd80a5f7773d39a89196d4d07853868","s":"0x2983ec62939515ac3a2971a88081f7720a95dc9ef18b9ae398b74132bda04308"}]`,
		},
		{
			f:    sys.NewTxRangeFilter(0, int64(rpc.LatestBlockNumber), 0, nil, []common.Address{contract}, [][]byte{common.Hex2Bytes("c670f864"), common.Hex2Bytes("78b9a1f3")}),
			want: `[{"blockHash":"0x24417bb49ce44cfad65da68f33b510bf2a129c0d89ccf06acb6958b8585ccf34","blockNumber":"0x2","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x2da282a8","hash":"0xa8028c655b6423204c8edfbc339f57b042d6bec2b6a61145d76b7c08b4cccd42","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x0","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xacd139f95e249a1d60fdb392ba0fa34a4fdc4f062203dc17f35f8e56f29d64d2","s":"0xcd785e8cdee241f414578e569da6ec152f432abeed61a7016dddffffa00c1c7"},{"blockHash":"0x7a7556792ca7d37882882e2b001fe14833eaf81c2c7f865c9c771ec37a024f6b","blockNumber":"0x3","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x280a0d96","hash":"0xdefe471992a07a02acdfbe33edaae22fbb86d7d3cec3f1b8e4e77702fb3acc1d","input":"0x78b9a1f30000000000000000000000000000000000000000000000000000746f706963320000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x2","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x26","r":"0x8aadf3ab0e624f0a44d3a3f0b12d9b846162c0a84d06a898b81c9a81a749fccb","s":"0x1c0fe3b723da1d841448bb8ed05d3f889e2509282129159889a6e0f3729b64cc"},{"blockHash":"0xb166569ffd2b8f9865e6333dfaada62d5027749c381ff568493b24d594f711ab","blockNumber":"0x3e8","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0xa919b50798f7ab32f2066b47e63d6225d69cbb9acbc7f3a4935f7c75919f78fc","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696334","nonce":"0x6","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0x2cc28a31219ceb5149bc5c7660d26943ac0d4e0aae7d08d5fc03d272928b08b0","s":"0x5a065f094e9143f6a1ba11cfe781ae3e979b9dc172c069f6edde4c3ad58162bc"}]`,
		},
		{
			f:    sys.NewTxRangeFilter(0, int64(rpc.LatestBlockNumber), 1, false, nil, []common.Address{contract}, [][]byte{common.Hex2Bytes("c670f864"), common.Hex2Bytes("78b9a1f3")}),
			want: `[{"blockHash":"0x24417bb49ce44cfad65da68f33b510bf2a129c0d89ccf06acb6958b8585ccf34","blockNumber":"0x2","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x2da282a8","hash":"0xa8028c655b6423204c8edfbc339f57b042d6bec2b6a61145d76b7c08b4cccd42","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x0","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xacd139f95e249a1d60fdb392ba0fa34a4fdc4f062203dc17f35f8e56f29d64d2","s":"0xcd785e8cdee241f414578e569da6ec152f432abeed61a7016dddffffa00c1c7"}]`,
		},
		// TODO test that can find contract creation
		// {
		// 	f:    sys.NewTxRangeFilter(0, int64(rpc.LatestBlockNumber), nil, []common.Address{nil}, nil),
		// 	want: `[{"blockHash":"0x24417bb49ce44cfad65da68f33b510bf2a129c0d89ccf06acb6958b8585ccf34","blockNumber":"0x2","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x2da282a8","hash":"0xa8028c655b6423204c8edfbc339f57b042d6bec2b6a61145d76b7c08b4cccd42","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x0","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0xacd139f95e249a1d60fdb392ba0fa34a4fdc4f062203dc17f35f8e56f29d64d2","s":"0xcd785e8cdee241f414578e569da6ec152f432abeed61a7016dddffffa00c1c7"},{"blockHash":"0x7a7556792ca7d37882882e2b001fe14833eaf81c2c7f865c9c771ec37a024f6b","blockNumber":"0x3","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x280a0d96","hash":"0xdefe471992a07a02acdfbe33edaae22fbb86d7d3cec3f1b8e4e77702fb3acc1d","input":"0x78b9a1f30000000000000000000000000000000000000000000000000000746f706963320000000000000000000000000000000000000000000000000000746f70696331","nonce":"0x2","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x26","r":"0x8aadf3ab0e624f0a44d3a3f0b12d9b846162c0a84d06a898b81c9a81a749fccb","s":"0x1c0fe3b723da1d841448bb8ed05d3f889e2509282129159889a6e0f3729b64cc"},{"blockHash":"0x7a11433433b82333fc2c2c3b75f264aad0539f830b2e17851c1a801a4473cfbd","blockNumber":"0x3e8","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x7","hash":"0x23de4893c396523db3187da311b8abd019171f60e98c5bfa2a093504d097bfef","input":"0xc670f8640000000000000000000000000000000000000000000000000000746f70696334","nonce":"0x5","to":"0xfe00000000000000000000000000000000000000","transactionIndex":"0x0","value":"0x0","type":"0x0","chainId":"0x1","v":"0x25","r":"0x570f5f7f4bebc2fff0a95c3f0c2139f3bdc4f4008181221964ade5d45bc9bb98","s":"0x7d54831ec83c774cce49589412da5851ba79a2373ab0c26595b323940ead70a4"}]`,
		// },
		{
			f:    sys.NewTxRangeFilter(0, int64(rpc.LatestBlockNumber), 0, []common.Address{addr}, []common.Address{addr}, [][]byte{nil}),
			want: `[{"blockHash":"0xf5624ceb3ec3d359bb117ae45202f2306a0c8d0c79208e1c05bfbe0cbb73489f","blockNumber":"0x5","from":"0x71562b71999873db5b286df957af199ec94617f7","gas":"0x7530","gasPrice":"0x1ed0d3c5","hash":"0xfb939950b542fc4c4f9b2bb9ca1b810532ed890ddafdb0603143878da48dbcdb","input":"0x","nonce":"0x4","to":"0x71562b71999873db5b286df957af199ec94617f7","transactionIndex":"0x0","value":"0x1","type":"0x0","chainId":"0x1","v":"0x25","r":"0x306eafff616b2048eec0fc9b1fd2bff77e7a72902686e16996f06521750ae3cf","s":"0xe7baa9f4ae61fd040ab21419abe5a4ca9771abdb9c9efc1e8bfa1e976edf081"}]`,
		},
		{
			f: sys.NewTxRangeFilter(int64(rpc.LatestBlockNumber), int64(rpc.FinalizedBlockNumber), 0, nil, nil, nil),
		},
		{
			f:   sys.NewTxRangeFilter(int64(rpc.SafeBlockNumber), int64(rpc.LatestBlockNumber), 0, nil, nil, nil),
			err: "safe header not found",
		},
		{
			f:   sys.NewTxRangeFilter(int64(rpc.SafeBlockNumber), int64(rpc.SafeBlockNumber), 0, nil, nil, nil),
			err: "safe header not found",
		},
		{
			f:   sys.NewTxRangeFilter(int64(rpc.LatestBlockNumber), int64(rpc.SafeBlockNumber), 0, nil, nil, nil),
			err: "safe header not found",
		},
		{
			f:   sys.NewTxRangeFilter(int64(rpc.PendingBlockNumber), int64(rpc.LatestBlockNumber), 0, nil, nil, nil),
			err: errInvalidBlockRange.Error(),
		},
	} {
		txs, err := tc.f.Transactions(context.Background())
		if err == nil && tc.err != "" {
			t.Fatalf("test %d, expected error %q, got nil", i, tc.err)
		} else if err != nil && err.Error() != tc.err {
			t.Fatalf("test %d, expected error %q, got %q", i, tc.err, err.Error())
		}
		if tc.want == "" && len(txs) == 0 {
			continue
		}
		have, err := json.Marshal(txs)
		if err != nil {
			t.Fatal(err)
		}
		if string(have) != tc.want {
			t.Fatalf("test %d, have:\n%s\nwant:\n%s", i, have, tc.want)
		}
	}

	t.Run("timeout", func(t *testing.T) {
		f := sys.NewTxRangeFilter(0, -1, 0, nil, nil, nil)
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
		defer cancel()
		_, err := f.Transactions(ctx)
		if err == nil {
			t.Fatal("expected error")
		}
		if err != context.DeadlineExceeded {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})
}
