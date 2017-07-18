package main

import (
	"log"

	"github.com/antongulenko/vflow/ipfix"
	"github.com/antongulenko/vflow/netflow/v9"
	"github.com/antongulenko/vflow/sflow"
)

type CliConsumer struct {
}

func (c *CliConsumer) SFlow(msg *sflow.Message) {
	log.Println("sFlow:", msg)
}

func (c *CliConsumer) IPFIX(msg *ipfix.Message) {
	log.Println("IPFIX:", msg)
}

func (c *CliConsumer) NetFlow(msg *netflow9.Message) {
	log.Println("NetFlow:", msg)
}
