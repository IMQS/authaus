package authaus

import (
	"code.google.com/p/winsvc/svc"
	"log"
)

type myservice struct {
	handler func()
}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	go m.handler()
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			default:
				//elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

// Returns true if we detected that we are not running in a non-interactive session, and so
// launched the service. This function will not return until the service exits.
func RunAsService(handler func()) bool {
	interactive, err := svc.IsAnIinteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
		return false
	}
	if interactive {
		return false
	}

	serviceName := "" // this doesn't matter when we are a "single-process" service
	service := &myservice{
		handler: handler,
	}
	svc.Run(serviceName, service)
	return true
}
