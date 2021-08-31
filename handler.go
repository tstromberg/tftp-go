/*
Copyright (c) 2015 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tftp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	minBlockSize = 8    // as per RFC 2348
	maxBlockSize = 1400 // fit within a standard MTU of 1500, even if encapsulated
)

// ReadCloser is what the Handler needs to implement to serve TFTP read requests.
type ReadCloser interface {
	io.ReadCloser
}

// WriteCloser is what the Handler needs to implement to serve TFTP write requests.
type WriteCloser interface {
	io.WriteCloser
}

// Conn provides context about the current "connection".
type Conn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// Handler is the interface a consumer of this library needs to implement to be
// able to serve TFTP requests.
type Handler interface {
	ReadFile(c Conn, filename string) (ReadCloser, error)
	WriteFile(c Conn, filename string) (WriteCloser, error)
}

// ErrTimeout is returned by the packetReader when it times out reading a packet.
var ErrTimeout = errors.New("timeout")

// packetReader is the interface that describes the function used for reading
// packets. The read function returns an error when it times out (ErrTimeout)
// or cannot deserialize a packet. In the latter case, the error is propagates
// from the routines responsible for deserialization.
type packetReader interface {
	read(time.Duration) (x packet, err error)
}

// packetWriter is the interface that describes the function used for writing packets.
type packetWriter interface {
	write(x packet) error
}

// packetValidator is type of the function that gets called from the function
// that writes a packet and waits for an acknowledgement from its peer.
type packetValidator func(p packet) bool

// session records the state for an exchange of UDP packets concerning a single
// TFTP request.
type session struct {
	packetReader
	packetWriter

	h       Handler
	c       Conn
	blksize int // The payload size per data packet.
	timeout int // The number of seconds before a retransmit takes place.
	totsize int // The total size of the file.
}

func serve(c Conn, r packetReader, w packetWriter, h Handler) {
	s := &session{
		packetReader: r,
		packetWriter: w,

		h:       h,
		c:       c,
		blksize: 512,
		timeout: 3,
	}

	s.serve()
}

func (s *session) writeError(err tftpError, message string) {
	s.write(&packetERROR{errorCode: err.Code, errorMessage: message}) //nolint:errcheck // no one cares about errors when sending errors
}

// writeAndWaitForPacket sends the packet p to our peer and waits for it to
// reply with a packet that can be validated by the packet validator v.
//
// If no valid reply if received before the configured timeout expires, packet
// p will be sent again. The packet will be sent for a maximum of 3 times.
//
// When a non-timeout error occurs when reading a reply, this function sends an
// error packet with the error message back to the peer.
func (s *session) writeAndWaitForPacket(p packet, v packetValidator) error {
	var err error

	for i := 0; i < 3; i++ {
		err = s.write(p)
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}

		now := time.Now()
		end := now.Add(time.Duration(s.timeout) * time.Second)
		for ; now.Before(end); now = time.Now() {
			timeout := end.Sub(now)

			p, err := s.read(timeout)
			if err != nil {
				if errors.Is(err, ErrTimeout) {
					break
				}

				s.writeError(tftpErrNotDefined, err.Error())
				return fmt.Errorf("read failed: %w", err)
			}

			// Check validity of packet
			if v(p) {
				return nil
			}
		}
	}

	return ErrTimeout
}

func (s *session) serve() {
	p, err := s.read(0)
	if err != nil {
		s.writeError(tftpErrNotDefined, err.Error())
		return
	}

	switch px := p.(type) {
	case *packetRRQ:
		s.serveRRQ(px)
	case *packetWRQ:
		s.serveWRQ(px)
	default:
		s.writeError(tftpErrIllegalOperation, "")
	}
}

func (s *session) negotiate(o map[string]string) (map[string]string, error) {
	oack := make(map[string]string)

	blksize, ok := o["blksize"]
	if ok {
		i, err := strconv.Atoi(blksize)
		if err != nil {
			return nil, err
		}

		switch {
		case i > maxBlockSize:
			s.blksize = maxBlockSize
		case i < minBlockSize:
			s.blksize = minBlockSize
		default:
			s.blksize = i
		}

		oack["blksize"] = strconv.Itoa(s.blksize)
	}

	timeout, ok := o["timeout"]
	if ok {
		i, err := strconv.Atoi(timeout)
		if err != nil {
			return nil, err
		}

		// Lower and upper bound from RFC 2349.
		switch {
		case i < 1:
			s.timeout = 1
		case i > 255:
			s.timeout = 255
		default:
			s.timeout = i
		}

		oack["timeout"] = strconv.Itoa(s.timeout)
	}

	// HACK! For TianoCore
	if _, ok := o["tsize"]; ok && s.totsize > 0 {
		oack["tsize"] = strconv.Itoa(s.totsize)
	}

	return oack, nil
}

func ackValidator(blockNr uint16) packetValidator {
	return func(p packet) bool {
		ack, ok := p.(*packetACK)
		return ok && ack.blockNr == blockNr
	}
}

func (s *session) serveRRQ(p *packetRRQ) {
	rc, err := s.h.ReadFile(s.c, p.filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.writeError(tftpErrNotFound, err.Error())
			return
		}
		if errors.Is(err, os.ErrPermission) {
			s.writeError(tftpErrAccessViolation, err.Error())
			return
		}
		s.writeError(tftpErrNotDefined, err.Error())
		return
	}

	defer func() {
		// This is called from an anonymous function to make errcheck happy.
		_ = rc.Close()
	}()

	type sizer interface {
		Size() int
	}
	if sz, ok := rc.(sizer); ok {
		s.totsize = sz.Size()
	}

	if len(p.options) > 0 {
		options, err := s.negotiate(p.options)
		if err != nil {
			s.writeError(tftpErrOptionNegotiation, err.Error())
			return
		}

		p := &packetOACK{options: options}
		if err = s.writeAndWaitForPacket(p, ackValidator(0)); err != nil {
			return
		}
	}

	// Proceed to send the file
	buf := make([]byte, s.blksize)
	var n int
	var rErr error
	for blockNr := uint16(1); rErr == nil; blockNr++ {
		// The semantics of ReadAtLeast are as follows:
		//
		// If == "blksize" bytes are read into buf, it will return with err == nil.
		// If < "blksize" bytes are read into buf and an error occurs reading new
		// bytes, it will return the number of bytes read and this error. If this
		// error is io.EOF, it is rewritten to io.ErrUnexpectedEOF if > 0 bytes
		// were already read.
		n, rErr = io.ReadAtLeast(rc, buf, s.blksize)
		if rErr != nil {
			if errors.Is(rErr, io.EOF) || errors.Is(rErr, io.ErrUnexpectedEOF) {
				// Treat errors as equivalent
				rErr = io.EOF
			} else {
				s.writeError(tftpErrNotDefined, rErr.Error())
				return
			}
		}

		p := &packetDATA{
			blockNr: blockNr,
			data:    buf[:n],
		}

		if err := s.writeAndWaitForPacket(p, ackValidator(blockNr)); err != nil {
			// This seems very very suspicious
			return
		}
	}
}

func (s *session) serveWRQ(_ *packetWRQ) {
	s.writeError(tftpErrNotDefined, "not supported")
}
