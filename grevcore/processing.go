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
		return PacketNil, fmt.Errorf("an error occured while trying to read the packet size, err=%w", err)
	}

	size := binary.LittleEndian.Uint32(recvSize)
	
	if size > MaxPacketSize {
		return PacketNil, fmt.Errorf("packet too large. (%d > %d)", size, MaxPacketSize)
	}

	received := make([]byte, size)

	_, err = io.ReadFull(r, received)

	if err != nil {
		return PacketNil, fmt.Errorf("an error occured while trying to receive the packet, err=%w", err)
	}

	if len(received) == 0 {
		return PacketNil, fmt.Errorf("received packet is empty.")
	}

	packet, err := AesDecrypt(received, key)

	if err != nil {
		return PacketNil, fmt.Errorf("an error occured while trying to decrypt the packet, err=%w", err)
	}

	p, err := Disassemble(packet)

	if err != nil {
		return PacketNil, fmt.Errorf("an error occured while trying to disassemble the packet size, err=%w", err)
	}

	return p, nil
}

func SendPacket(w io.Writer, p Packet, key []byte) error {
	sendSize := make([]byte, 4)		

	encryptedData, err := AesEncrypt(p.Assemble(), key)
	if err != nil {
		return fmt.Errorf("an error occured while trying to encrypt the packet, err=%w", err)
	}

	if len(encryptedData) > MaxPacketSize {
		return fmt.Errorf("Packet too large. (%d > %d)", len(encryptedData), MaxPacketSize)
	}

	binary.LittleEndian.PutUint32(sendSize, uint32(len(encryptedData)))

	_, err = w.Write(sendSize)
	if err != nil {
		return fmt.Errorf("an error occured while trying to send the packet size, err=%w", err)
	}

	_, err = w.Write(encryptedData)

	if err != nil {
		return fmt.Errorf("an error occured while trying to read the encrypted packet, err=%w", err)
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

func Disassemble(b []byte) (Packet, error) {
	if len(b) < HeaderSize + FileNameHeaderSize {
		return PacketNil, fmt.Errorf("invalid packet size of %d.", len(b))
	}

	var p Packet
	p.Header = string(b[:HeaderSize])

	n := int(binary.LittleEndian.Uint16(b[HeaderSize : HeaderSize+FileNameHeaderSize]))
	if n > len(b) - HeaderSize - FileNameHeaderSize {
		return PacketNil, fmt.Errorf("invalid header size of %d.", n)
	}

	p.FileName = string(b[HeaderSize + FileNameHeaderSize:HeaderSize + FileNameHeaderSize + n])
	p.Data = b[HeaderSize + FileNameHeaderSize + n:]

	return p, nil
}
