package security

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerIdentity represents the verified Linux process credentials of a connected socket peer.
type PeerIdentity struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	PID  int32  `json:"pid"`
	Role Role   `json:"role"`
}

func (p *PeerIdentity) String() string {
	return fmt.Sprintf("UID=%d GID=%d PID=%d Role=%s", p.UID, p.GID, p.PID, p.Role)
}

// GetPeerCredentials extracts the Linux socket peer credentials (UID, GID, PID) using SO_PEERCRED.
func GetPeerCredentials(conn net.Conn) (*PeerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a Unix domain socket")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain syscall connection: %w", err)
	}

	var ucred *unix.Ucred
	var errCred error

	controlErr := rawConn.Control(func(fd uintptr) {
		ucred, errCred = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if controlErr != nil {
		return nil, fmt.Errorf("control syscall failed: %w", controlErr)
	}
	if errCred != nil {
		return nil, fmt.Errorf("failed to read SO_PEERCRED socket options: %w", errCred)
	}

	return &PeerIdentity{
		UID:  ucred.Uid,
		GID:  ucred.Gid,
		PID:  ucred.Pid,
		Role: RoleViewer,
	}, nil
}
