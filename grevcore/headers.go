package grevcore 

type Packet struct {
	Header		string
	FileName	string 	// Leave Empty for ShellExec
	Data		[]byte
}

var (
	PacketNil	= Packet{"", "", nil}
)

const (
	FileReceiveHeader	= "GREVRCVF"
	FileSendHeader		= "GREVSNDF"
	ShellExecHeader		= "GREVEXEC"
	HeaderSize		= 8
	FileNameHeaderSize	= 2
	MaxPacketSize		= 0xFFFF
)
