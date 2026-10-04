package grevcore

import (
	"net"
	"io"
	"encoding/binary"
	"log/slog"
)

func ReceivePacket(c net.Conn, key *[]byte) []byte {
	recvSize := make([]byte, 4)	

	io.ReadFull(c, recvSize)
	size := binary.LittleEndian.Uint32(recvSize)

	received := make([]byte, size)

	_, err := io.ReadFull(c, received)

	if err != nil {
		slog.Error("An error occured while reading the sent packet.", slog.Any("ERROR", err))
		return nil
	}

	if len(received) == 0 {
		return nil
	}

	return AesDecrypt(&received, key)
}

func SendPacket(c net.Conn, data, key *[]byte) {
	sendSize := make([]byte, 4)		

	encryptedData := AesEncrypt(data, key)
	binary.LittleEndian.PutUint32(sendSize, uint32(len(encryptedData)))

	c.Write(sendSize)
	c.Write(encryptedData)
}
