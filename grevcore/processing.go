package grevcore
import ( 
	"io"
	"encoding/binary"
	"fmt"
)

func ReceivePacket(r io.Reader, key []byte) (Packet, error) {
	recvSize := make([]byte, 4)	

	_, err := io.ReadFull(r, recvSize)

	if err != nil {
		return PacketNil, err
	}

	size := binary.LittleEndian.Uint32(recvSize)

	if size > MaxPacketSize {
		return PacketNil, fmt.Errorf("Packet too large. (%d > %d)", size, MaxPacketSize)
	}

	received := make([]byte, size)

	_, err = io.ReadFull(r, received)

	if err != nil {
		return PacketNil, err
	}

	if len(received) == 0 {
		return PacketNil, fmt.Errorf("Received packet is empty.")
	}

	packet := Disassemble(AesDecrypt(received, key))

	return packet, nil
}

func SendPacket(w io.Writer, p Packet, key []byte) error {
	sendSize := make([]byte, 4)		

	encryptedData := AesEncrypt(p.Assemble(), key)
	binary.LittleEndian.PutUint32(sendSize, uint32(len(encryptedData)))

	_, err := w.Write(sendSize)
	if err != nil {
		return err
	}

	_, err = w.Write(encryptedData)

	if err != nil {
		return err
	}

	return nil
}

func (p *Packet) Assemble() []byte {
	packet := make([]byte, HeaderSize + FileNameHeaderSize + len(p.FileName) + len(p.Data))
	
	copy(packet[:HeaderSize], []byte(p.Header))
	binary.LittleEndian.PutUint16(packet[HeaderSize:HeaderSize + FileNameHeaderSize], uint16(len(p.FileName)))
	copy(packet[HeaderSize + FileNameHeaderSize:HeaderSize + FileNameHeaderSize + len(p.FileName)], []byte(p.FileName))
	copy(packet[HeaderSize + FileNameHeaderSize + len(p.FileName):], p.Data)

	return packet
}

func Disassemble(b []byte) Packet {
	var p Packet

	p.Header = string(b[:HeaderSize])
	n := int(binary.LittleEndian.Uint16(b[HeaderSize : HeaderSize+FileNameHeaderSize]))
	p.FileName = string(b[HeaderSize + FileNameHeaderSize:HeaderSize + FileNameHeaderSize + n])
	p.Data = b[HeaderSize + FileNameHeaderSize + n:]

	return p
}
