package main

import (
	"log"

	"bytes"
	"encoding/json"

	"github.com/VerizonDigital/vflow/ipfix"
	"github.com/VerizonDigital/vflow/netflow/v9"
	"github.com/VerizonDigital/vflow/sflow"
)

type CliConsumer struct {
}

func (c *CliConsumer) SFlow(msg *sflow.Message) {
	c.log("sFlow", msg)
}

func (c *CliConsumer) IPFIX(msg *ipfix.Message) {
	c.log("IPFIX", msg)
}

func (c *CliConsumer) NetFlow(msg *netflow9.Message) {
	c.log("NetFlow", msg)
}

func (c *CliConsumer) log(name string, obj interface{}) {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	err := enc.Encode(obj)
	if err != nil {
		log.Printf("Error encoding %s object of type %T: %v\n", name, obj, err)
	}
	log.Println(name + ": " + data.String())
}
