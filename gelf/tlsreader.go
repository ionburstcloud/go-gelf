package gelf

import (
	"crypto/tls"
	"fmt"
)

type TLSReader struct {
	TCPReader
	tlsConfig tls.Config
}

func newTLSReader(addr string, tlsConfig *tls.Config) (*TLSReader, chan string, chan string, error) {
	var err error
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ListenTCP: %s", err)
	}
	r := new(TLSReader)
	r.listener = listener
	r.messages = make(chan []byte, 100)

	closeSignal := make(chan string, 1)
	doneSignal := make(chan string, 1)

	go r.listenUntilCloseSignal(closeSignal, doneSignal)

	return r, closeSignal, doneSignal, nil
}
