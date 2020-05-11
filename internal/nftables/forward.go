package nftables

import (
	"fmt"

	"github.com/alex60217101990/packets-dump/internal/consts"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/errors"
	nft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func (n *NftablesService) ChangeLocalProxyRule(action enums.NftActionType, table string, fromPort, toPort uint16, trafficType uint8) error {
	if trafficType != unix.IPPROTO_TCP && trafficType != unix.IPPROTO_UDP {
		return errors.ErrInvalidL4ProtoType //types.ErrInvalidL4ProtoType
	}
	rule := &nft.Rule{
		Table: n.tables[table],
		Chain: &nft.Chain{
			Name:     consts.PreroutingChainName,
			Hooknum:  nft.ChainHookPrerouting,
			Priority: nft.ChainPriorityFilter,
			Table:    n.tables[table],
			Type:     nft.ChainTypeNAT,
		},
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{trafficType},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(fromPort),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(toPort),
			},
			//	[ immediate reg 1 0x0000a0c3 ]
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(toPort)},
			// [ redir proto_min reg 1 ]
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	}
	fmt.Printf("%+v", *rule)
	switch action {
	case enums.AddAction:
		n.conn.AddRule(rule)
	case enums.DeleteAction:
		n.conn.DelRule(rule)
	}

	return n.conn.Flush()
}

func (n *NftablesService) ChangeMasqRule(action enums.NftActionType, table string, iface string) error {
	rule := &nft.Rule{
		Table: n.tables[table],
		Chain: &nft.Chain{
			Name:     consts.PostroutingChainName,
			Table:    n.tables[table],
			Type:     nft.ChainTypeNAT,
			Hooknum:  nft.ChainHookPostrouting,
			Priority: nft.ChainPriorityNATSource,
		},
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(fmt.Sprintf("%s\x00", iface)),
			},
			// masq
			&expr.Masq{},
		},
	}
	switch action {
	case enums.AddAction:
		n.conn.AddRule(rule)
	case enums.DeleteAction:
		n.conn.DelRule(rule)
	}

	return n.conn.Flush()
}
