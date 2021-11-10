package localdns

import (
	"fmt"
	"sync"
)

type LocalDns struct {
	mx      sync.Mutex
	records map[string]string
}

var defaultLocalDns = New()

func New() *LocalDns {
	return &LocalDns{
		records: map[string]string{},
	}
}

func (l *LocalDns) Resolve(addr string) (string, error) {
	l.mx.Lock()
	if ip, exist := l.records[addr]; exist {
		l.mx.Unlock()
		return ip, nil
	}
	l.mx.Unlock()

	return "", fmt.Errorf("not exist")
}

func (l *LocalDns) Update(addr, ip string) {
	l.mx.Lock()
	l.records[addr] = ip
	l.mx.Unlock()
}

func Resolve(addr string) (string, error) {
	return defaultLocalDns.Resolve(addr)
}

func Update(addr, ip string) {
	defaultLocalDns.Update(addr, ip)
}
