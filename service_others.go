// +build !windows

package authaus

func RunAsService(handler func()) bool {
	return false
}
