package nftables

import (
	"fmt"

	nft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/alex60217101990/packets-dump/internal/errors"
)

type NftablesService struct {
	conn   *nft.Conn
	tables map[string]*nft.Table
}

func NewNftService() *NftablesService {
	service := &NftablesService{
		conn:   &nft.Conn{},
		tables: make(map[string]*nft.Table),
	}
	// Lets create our tables.
	service.AddTable("proxyIPv4", nft.TableFamilyIPv4)
	// ???
	service.ChangeMasqRule("proxyIPv4", "eth0")
	service.AddTable("proxyIPv6", nft.TableFamilyIPv6)
	// ???
	service.ChangeMasqRule("proxyIPv6", "eth0")
	return service
}

func (n *NftablesService) AddTable(name string, family nft.TableFamily) error {
	n.tables[name] = n.conn.AddTable(&nft.Table{
		Family: family,
		Name:   name,
	})
	return n.conn.Flush()
}

func (n *NftablesService) ChangeLocalProxyRule(table string, fromPort, toPort uint16, trafficType uint8) error {
	if trafficType != unix.IPPROTO_TCP || trafficType != unix.IPPROTO_UDP {
		return errors.ErrInvalidL4ProtoType
	}
	n.conn.AddRule(&nft.Rule{
		Table: n.tables[table],
		Chain: &nft.Chain{
			Name:     "prerouting",
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
	})

	return n.conn.Flush()
}

func (n *NftablesService) ChangeMasqRule(table string, iface string) error {
	n.conn.AddRule(&nft.Rule{
		Table: n.tables[table],
		Chain: &nft.Chain{
			Name:     "postroute_chain",
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
	})

	return n.conn.Flush()
}
