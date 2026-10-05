package grevcore
import ( 
	"io"
	"encoding/binary"
	"log/slog"
)

func ReceivePacket(r io.Reader, key []byte) Packet {
	recvSize := make([]byte, 4)	

	io.ReadFull(r, recvSize)
	size := binary.LittleEndian.Uint32(recvSize)

	if size > MaxPacketSize {
		slog.Error("Packet too large.")
		return PacketNil
	}

	received := make([]byte, size)

	_, err := io.ReadFull(r, received)

	if err != nil {
		slog.Error("An error occured while reading the sent packet.", slog.Any("ERROR", err))
		return PacketNil
	}

	if len(received) == 0 {
		return PacketNil
	}

	packet := Disassemble(AesDecrypt(received, key))

	return packet
}

func SendPacket(w io.Writer, p Packet, key []byte) {
	sendSize := make([]byte, 4)		

	encryptedData := AesEncrypt(p.Assemble(), key)
	binary.LittleEndian.PutUint32(sendSize, uint32(len(encryptedData)))

	w.Write(sendSize)
	w.Write(encryptedData)
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
