package authaus

import (
	"code.google.com/p/winsvc/svc"
	"log"
	"os"
)

type myservice struct {
	configFile string
}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	go startServer(m.configFile)
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

func startServer(configFile string) {
	// ignoring error here, but at this stage these things should probably be logged anyway
	RunHttpFromConfigFile(configFile)
}

// Returns true if we tried to run as a service (regardless of success or not)
func RunAsService() bool {
	interactive, err := svc.IsAnIinteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
		return false
	}
	if interactive {
		return false
	}

	serviceName := "" // this doesn't matter when we are a "single-process" service
	configFile := ""
	for i, v := range os.Args {
		if i < len(os.Args)-1 {
			switch v {
			case "-c":
				configFile = os.Args[i+1]
			}
		}
	}

	if configFile == "" {
		log.Fatalf("Must specify a config file with '-c <full path to config>'")
		return true
	}

	service := &myservice{
		configFile: configFile,
	}
	svc.Run(serviceName, service)
	return true
}
