//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    vflow.go
//: details: TODO
//: author:  Mehrdad Arshad Rad
//: date:    02/01/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

// Package main is the vflow binary
package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/VerizonDigital/vflow/ipfix"
	"github.com/VerizonDigital/vflow/netflow/v9"
	"github.com/VerizonDigital/vflow/sflow"
)

var (
	opts   *Options
	logger *log.Logger
)

type proto interface {
	run()
	shutdown()
}

type Consumer interface {
	SFlow(msg *sflow.Message)
	IPFIX(msg *ipfix.Message)
	NetFlow(msg *netflow9.Message)
}

func main() {
	var (
		wg       sync.WaitGroup
		signalCh = make(chan os.Signal, 1)
	)

	opts = GetOptions()

	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	consumer := &CliConsumer{}
	sFlow := NewSFlow(consumer)
	ipfix := NewIPFIX(consumer)
	netflow9 := NewNetflowV9(consumer)

	protos := []proto{sFlow, ipfix, netflow9}

	for _, p := range protos {
		wg.Add(1)
		go func(p proto) {
			defer wg.Done()
			p.run()
		}(p)
	}

	go statsHTTPServer(ipfix, sFlow, netflow9)

	<-signalCh

	for _, p := range protos {
		wg.Add(1)
		go func(p proto) {
			defer wg.Done()
			p.shutdown()
		}(p)
	}

	wg.Wait()
}
