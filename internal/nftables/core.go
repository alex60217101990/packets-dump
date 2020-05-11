package nftables

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	nft "github.com/google/nftables"

	"github.com/alex60217101990/packets-dump/internal/consts"
	"github.com/alex60217101990/types/enums"
	"github.com/alex60217101990/types/errors"
)

type NftablesService struct {
	mx     sync.RWMutex
	conn   *nft.Conn
	tables map[string]*nft.Table
}

// "github.com/alex60217101990/types/enums"
func NewNftService() *NftablesService {
	service := &NftablesService{
		conn:   &nft.Conn{},
		tables: make(map[string]*nft.Table),
	}

	// Lets create our tables.
	err := service.AddTable(consts.NftableIPv4TableName, nft.TableFamilyIPv4)
	if err != nil {
		log.Fatal(err)
	}
	err = service.AddTable(consts.NftableIPv6TableName, nft.TableFamilyIPv6)
	if err != nil {
		log.Fatal(err)
	}
	err = service.InitChains()
	if err != nil {
		log.Fatal(err)
	}

	// ???
	err = service.ChangeMasqRule(enums.AddAction, consts.NftableIPv4TableName, consts.DockerNetInterfaceName)
	if err != nil {
		log.Fatal(err)
	}
	err = service.ChangeMasqRule(enums.AddAction, consts.NftableIPv6TableName, consts.DockerNetInterfaceName)
	if err != nil {
		log.Fatal(err)
	}
	// ???

	return service
}

func (n *NftablesService) AddTable(name string, family nft.TableFamily) error {
	n.tables[name] = n.conn.AddTable(&nft.Table{
		Family: family,
		Name:   name,
	})
	return n.conn.Flush()
}

func (n *NftablesService) DelTable(name string) (err error) {
	if t, ok := n.tables[name]; ok {
		n.conn.DelTable(t)
		if err = n.conn.Flush(); err == nil {
			n.mx.Lock()
			defer n.mx.Unlock()
			delete(n.tables, name)
		}
		return err
	}
	return errors.ErrTableWithNameNotFound(name)
}

func (n *NftablesService) InitChains() (err error) {
	for _, table := range n.tables {
		n.conn.AddChain(&nft.Chain{
			Name:     consts.PreroutingChainName,
			Hooknum:  nft.ChainHookPrerouting,
			Priority: nft.ChainPriorityFilter,
			Table:    table,
			Type:     nft.ChainTypeNAT,
		})
		n.conn.AddChain(&nft.Chain{
			Name:     consts.PostroutingChainName,
			Table:    table,
			Type:     nft.ChainTypeNAT,
			Hooknum:  nft.ChainHookPostrouting,
			Priority: nft.ChainPriorityNATSource,
		})
		err = n.conn.Flush()
	}
	return err
}

func (n *NftablesService) Close() (err error) {
	defer n.conn.FlushRuleset()
	for key, table := range n.tables {
		err = n.AddTable(key, table.Family)
	}
	return err
}

func DumpRulesetList() {
	cmd := exec.Command("nft", "-s", "list", "ruleset")
	// open the out file for writing
	outfile, err := os.Create("./rules.nft")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	io.WriteString(outfile, "# Flush the rule set\nflush ruleset\n")
	cmd.Stdout = outfile

	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	if err != nil {
		log.Fatal(err)
	}
}
