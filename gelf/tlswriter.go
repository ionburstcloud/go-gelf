package gelf

import (
	"crypto/tls"
	"os"
)

type TLSWriter struct {
	TCPWriter
	TlsConfig *tls.Config
}

func NewTLSWriter(addr string, tlsConfig *tls.Config) (Writer, error) {
	w := new(TLSWriter)
	w.MaxReconnect = DefaultMaxReconnect
	w.ReconnectDelay = DefaultReconnectDelay
	w.proto = "tls"
	w.addr = addr
	w.TlsConfig = tlsConfig

	var err error
	if w.conn, err = tls.Dial("tcp", addr, w.TlsConfig); err != nil {
		return nil, err
	}
	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	return w, nil
}
