package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	nls, err := NewNlSock()
	if err != nil {
		panic(err)
	}

	if err := nls.SetFeature(); err != nil {
		panic(err)
	}

	native := nativeEndian()
	for {

		nlMsgs, err := nls.receive()
		if err != nil {
			panic(err)
		}

		for i := range nlMsgs {
			m := NlMsg(nlMsgs[i])

			if m.Header.Type == unix.NLMSG_DONE {
				continue
			}

			if m.Header.Type == unix.NLMSG_ERROR {
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					continue
				}
				panic(syscall.Errno(-error))
			}

			hdr := DeserializeGenlmsgHdr(m.Data)
			buf := m.Data[4:]

			nlAttrs := map[uint16]NlAttr{}
			for len(buf) >= unix.SizeofNlAttr {
				nla := DeserializeNlAttr(buf)
				nlAttrs[nla.Type] = nla
				buf = buf[nlaAlignOf(int(nla.Len)):]
			}

			switch hdr.Command {
			case TCMU_CMD_ADDED_DEVICE:
				replyCmd := TCMU_CMD_ADDED_DEVICE_DONE

				if err := nls.ReplyStatus(replyCmd, 0, nlAttrs[TCMU_ATTR_DEVICE_ID].Uint32()); err != nil {
					panic(err)
				}
			default:
				// TODO
			}
		}

	}

}

type NlSock struct {
	fd       int
	seq      uint32
	pid      uint32
	addr     syscall.SockaddrNetlink
	familyID uint16
}

func NewNlSock() (*NlSock, error) {
	family, err := netlink.GenlFamilyGet("TCM-USER")
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, int(family.Groups[0].ID))
	if err != nil {
		return nil, err
	}

	return &NlSock{
		fd:  fd,
		seq: rand.Uint32(),
		pid: uint32(os.Getpid()),
		addr: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
		},
		familyID: family.ID,
	}, nil
}

func (nls *NlSock) SetFeature() error {
	nlMsg := NewNlMsg(nls.pid, nls.newSequence(), nls.familyID,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,
		GenlMsgHdr{
			Command: TCMU_CMD_SET_FEATURES,
			Version: 2,
		},
		NewNlAttrUint8(TCMU_ATTR_SUPP_KERN_CMD_REPLY, 1),
	)

	if err := syscall.Sendto(nls.fd, nlMsg.Serialize(), 0, &nls.addr); err != nil {
		return err
	}

done:
	for {
		nlMsgs, err := nls.receive()
		if err != nil {
			return err
		}

		// verify the message
		for _, m := range nlMsgs {
			if m.Header.Seq != nlMsg.Header.Seq {
				return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, nlMsg.Header.Seq)
			}

			if m.Header.Pid != nls.pid {
				continue
			}

			if m.Header.Type == unix.NLMSG_DONE {
				continue
			}

			if m.Header.Type == unix.NLMSG_ERROR {
				native := nativeEndian()
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				return syscall.Errno(-error)
			}

			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return nil
}

func (nls *NlSock) ReplyStatus(replyCmd uint8, status int, deviceID uint32) error {
	nlMsg := NewNlMsg(nls.pid, nls.newSequence(), nls.familyID,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,

		GenlMsgHdr{
			Command: replyCmd,
			Version: 2,
		},

		NewNlAttrUint32(TCMU_ATTR_CMD_STATUS, uint32(status)),
		NewNlAttrUint32(TCMU_ATTR_DEVICE_ID, deviceID),
	)

	if err := syscall.Sendto(nls.fd, nlMsg.Serialize(), 0, &nls.addr); err != nil {
		return err
	}

done:
	for {
		nlMsgs, err := nls.receive()
		if err != nil {
			return err
		}

		for _, m := range nlMsgs {
			if m.Header.Seq != nlMsg.Header.Seq {
				return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, nlMsg.Header.Seq)
			}

			if m.Header.Pid != nls.pid {
				continue
			}
			if m.Header.Type == unix.NLMSG_DONE {
				break done
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				native := nativeEndian()
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				return syscall.Errno(-error)
			}
			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return nil
}

func (nls *NlSock) receive() ([]syscall.NetlinkMessage, error) {
	defaultBufferSize := 4096

	b := make([]byte, defaultBufferSize)
	for {
		n, _, _, _, err := syscall.Recvmsg(nls.fd, b, nil, syscall.MSG_PEEK)
		if err != nil {
			return nil, err
		}

		// need more bytes to do align if equal
		if n < len(b) {
			break
		}
		b = make([]byte, len(b)+defaultBufferSize)
	}

	n, _, _, _, err := syscall.Recvmsg(nls.fd, b, nil, 0)
	if err != nil {
		return nil, err
	}

	return syscall.ParseNetlinkMessage(b[:nlMsgAlign(n)])
}

func (nls *NlSock) newSequence() uint32 {
	return atomic.AddUint32(&nls.seq, 1)
}

type NlMsg syscall.NetlinkMessage

const (
	TCMU_CMD_UNSPEC uint8 = iota
	TCMU_CMD_ADDED_DEVICE
	TCMU_CMD_REMOVED_DEVICE
	TCMU_CMD_RECONFIG_DEVICE
	TCMU_CMD_ADDED_DEVICE_DONE
	TCMU_CMD_REMOVED_DEVICE_DONE
	TCMU_CMD_RECONFIG_DEVICE_DONE
	TCMU_CMD_SET_FEATURES
	__TCMU_CMD_MAX
)

const (
	TCMU_ATTR_UNSPEC uint16 = iota
	TCMU_ATTR_DEVICE
	TCMU_ATTR_MINOR
	TCMU_ATTR_PAD
	TCMU_ATTR_DEV_CFG
	TCMU_ATTR_DEV_SIZE
	TCMU_ATTR_WRITECACHE
	TCMU_ATTR_CMD_STATUS
	TCMU_ATTR_DEVICE_ID
	TCMU_ATTR_SUPP_KERN_CMD_REPLY
	__TCMU_ATTR_MAX
)

func NewNlMsg(port uint32, seq uint32, family uint16, flags int, hdr GenlMsgHdr, nlAttrs ...NlAttr) NlMsg {
	nlMsg := NlMsg{}

	nlMsg.Header.Pid = port
	nlMsg.Header.Seq = seq
	nlMsg.Header.Type = uint16(family)
	nlMsg.Header.Flags = uint16(flags)
	nlMsg.Data = hdr.Serialize()

	for _, nlAttr := range nlAttrs {
		nlMsg.Data = append(nlMsg.Data, nlAttr.Serialize()...)
	}

	nlMsg.Header.Len = uint32(unix.SizeofNlMsghdr + len(nlMsg.Data))
	return nlMsg
}

func (nlMsg NlMsg) Serialize() []byte {
	l := nlMsgAlign(int(nlMsg.Header.Len))
	buf := make([]byte, l)

	native := nativeEndian()
	native.PutUint32(buf[:4], nlMsg.Header.Len)
	native.PutUint16(buf[4:6], nlMsg.Header.Type)
	native.PutUint16(buf[6:8], nlMsg.Header.Flags)
	native.PutUint32(buf[8:12], nlMsg.Header.Seq)
	native.PutUint32(buf[12:16], nlMsg.Header.Pid)
	copy(buf[unix.SizeofNlMsghdr:], nlMsg.Data)
	return buf
}

type GenlMsgHdr struct {
	Command uint8
	Version uint8
}

func (hdr GenlMsgHdr) Serialize() []byte {
	buf := make([]byte, 4)
	buf[0] = byte(hdr.Command)
	buf[1] = byte(hdr.Version)
	return buf
}

func DeserializeGenlmsgHdr(b []byte) GenlMsgHdr {
	_ = b[3]

	return GenlMsgHdr{
		Command: b[0],
		Version: b[1],
	}
}

// NlAttr is Netlink Attribute.
type NlAttr struct {
	Len  uint16
	Type uint16
	Data []byte
}

func NewNlAttrUint8(typ uint16, val uint8) NlAttr {
	buf := [1]byte{byte(val)}
	return NlAttr{
		Len:  uint16(unix.SizeofNlAttr + len(buf)),
		Type: typ,
		Data: buf[:],
	}
}

func NewNlAttrUint32(typ uint16, val uint32) NlAttr {
	native := nativeEndian()

	buf := [4]byte{}
	native.PutUint32(buf[:], val)
	return NlAttr{
		Len:  uint16(unix.SizeofNlAttr + len(buf)),
		Type: typ,
		Data: buf[:],
	}
}

func (nla NlAttr) Uint8() uint8 {
	if nla.Len != 1+unix.SizeofNlAttr {
		panic("netlink attribute data is not in valid uint8 format")
	}
	return uint8(nla.Data[0])
}

func (nla NlAttr) Uint32() uint32 {
	if nla.Len != 4+unix.SizeofNlAttr {
		panic("netlink attribute data is not in valid uint32 format")
	}

	native := nativeEndian()
	return native.Uint32(nla.Data[:nla.Len])
}

func (nla NlAttr) Uint64() uint64 {
	if nla.Len != 8+unix.SizeofNlAttr {
		panic("netlink attribute data is not in valid uint64 format")
	}

	native := nativeEndian()
	return native.Uint64(nla.Data[:nla.Len])
}

func (nla NlAttr) String() string {
	return string(nla.Data)
}

func (nla NlAttr) Serialize() []byte {
	l := nlaAlignOf(int(nla.Len))
	buf := make([]byte, l)

	native := nativeEndian()
	native.PutUint16(buf[0:2], uint16(nla.Len))
	native.PutUint16(buf[2:4], nla.Type)
	copy(buf[4:], nla.Data)
	return buf
}

func DeserializeNlAttr(b []byte) NlAttr {
	native := nativeEndian()

	l := native.Uint16(b[:2])
	typ := native.Uint16(b[2:4])
	return NlAttr{
		Len:  l,
		Type: typ,
		Data: b[4:l],
	}
}

func nlaAlignOf(attrlen int) int {
	return (attrlen + unix.NLA_ALIGNTO - 1) & ^(unix.NLA_ALIGNTO - 1)
}

func nlMsgAlign(nlMsgLen int) int {
	return (nlMsgLen + unix.NLMSG_ALIGNTO - 1) & ^(unix.NLMSG_ALIGNTO - 1)
}

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
