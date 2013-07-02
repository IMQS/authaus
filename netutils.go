package authaus

/*
import (
	"errors"
	//"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

type ListenerCancellable struct {
	Target     net.Listener
	StopSignal *uint32
}

func (x *ListenerCancellable) Accept() (c net.Conn, err error) {
	//fmt.Printf("A chance...\n")
	if atomic.LoadUint32(x.StopSignal) == 1 {
		return nil, errors.New("stop signalled")
	}
	return x.Target.Accept()
}

func (x *ListenerCancellable) Close() error {
	return x.Target.Close()
}

func (x *ListenerCancellable) Addr() net.Addr {
	return x.Target.Addr()
}

func (x *ListenerCancellable) Stop() {
	atomic.StoreUint32(x.StopSignal, 1)
}

// Cancellable HTTP server
// In order to stop:
//   Set *stopSignal = 1
//   Send any new communication to the server
func ListenAndServe(srv *http.Server, stopSignal *uint32) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	return srv.Serve(&ListenerCancellable{Target: l, StopSignal: stopSignal})
}
*/
