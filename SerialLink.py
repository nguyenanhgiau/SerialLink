
import sys
import time
import serial
import logging
import struct
import threading
import queue
import sqlite3

# /* ZHA Commands */
E_SL_MSG_PDM_HOST_AVAILABLE_RESPONSE    = 0x8300

class cPDMFunctionality(threading.Thread):
    """Class implementing the binary serial protocol to the control bridge node"""
    def __init__(self, port):
        threading.Thread.__init__(self, name="PDM")

        # Message queue used to pass message between reader thread and waitMessage()
        self.dMessageQueue = {}
        self.logger = logging.getLogger(str(port))
        # Start reader thread
        self.daemon=True
        self.start()

class cSerialLink(threading.Thread):
    """Class implementing the binary serial protocol to the control bridge node"""
    def __init__(self, port, baudrate=115200):
        threading.Thread.__init__(self, name="SL")
        self.logger = logging.getLogger(str(port))
        self.commslogger = logging.getLogger("Comms("+str(port)+")")

        # Turn this up to see traffic between node and host
        self.commslogger.setLevel(logging.WARNING)

        self.oPort = serial.Serial(port, baudrate)

        # Message queue used to the pass message between reader thread and waitMessage()
        self.dMessageQueue = {}

        # Start reader thread
        self.daemon=True
        self.start()



    def _WriteByte(self, oByte, bSpecial=False, bAscii=False):
        """ Internal function
            Send a single byte to the serial port. Takes care of byte stuffing
        """
        if bAscii:
            if not bSpecial and oByte < 0x10:
                self.commslogger.info("Ascii Host->Node: 0x02 ESC")
                oByte = struct.pack("B", oByte ^ 0x10)
                self.oPort.write(struct.pack("B", 0x20))
            else:
                oByte = struct.pack("B", oByte)
            self.commslogger.info("Ascii Host->Node: 0x%02x", ord(oByte))
            self.oPort.write(oByte)
        else:
            if not bSpecial and ord(oByte) < 0x10:
                self.commslogger.info("non Ascii Host->Node: 0x02 ESC")
                oByte = struct.pack("B", ord(oByte) ^ 0x10)
                self.oPort.write(struct.pack("B", 0x02))
            self.commslogger.info("non Ascii Host->Node: 0x%02x", ord(oByte))
            self.oPort.write(oByte)

    def _WriteMessage(self, eMessageType, sData):
        """ Internal function
            Send a complete message to the serial port. Takes care of byte stuffing
            and checksum generation. eMessageType should be a 16bit message number
            sData is a string containing the packed message data
        """
        self.commslogger.info("Host->Node: Message Type 0x%04x, length %d %s", eMessageType, len(sData), sData)
        
        u8Checksum = ((eMessageType >> 8) & 0xFF) ^ ((eMessageType >> 0) & 0xFF)
        u8Checksum = u8Checksum ^ (((len(sData)//2) >> 8) & 0xFF) ^ (((len(sData)//2) >> 0) & 0xFF)
        bIn=True
        for byte in sData:
            if bIn:
                u8Byte = int(byte,16)<<4 & 0xFF
                bIn=False
            else:
                u8Byte |= int(byte,16)>>0 & 0xFF
                u8Checksum = u8Checksum ^ u8Byte
                bIn=True

        u16Length = len(sData)//2

        self._WriteByte(struct.pack("B", 0x01), True)
        self._WriteByte(struct.pack("B", (eMessageType >> 8) & 0xFF))
        self._WriteByte(struct.pack("B", (eMessageType >> 0) & 0xFF))
        self._WriteByte(struct.pack("B", (u16Length >> 8) & 0xFF))
        self._WriteByte(struct.pack("B", (u16Length >> 0) & 0xFF))
        self._WriteByte(struct.pack("B", (u8Checksum) & 0xFF))
        bIn=True

        for byte in sData:
            if bIn:
                u8Byte = int(byte,16)<<4 & 0xFF
                bIn=False
            else:
                u8Byte |= int(byte,16)>>0 & 0xFF
                self._WriteByte(u8Byte, False, True)
                bIn=True

        self._WriteByte(struct.pack("B", 0x03), True)


    def _ReadMessage(self):
        """ Internal function
            Read a complete message from the serial port. Takes care of byte stuffing
            Length and checksum message integrity checks.
            Return tuple of message type and buffer of data.
        """
        bInEsc=False

        u8Checksum = 0
        eMessageType = 0
        u16Length = 0
        sData = ""
        state = 0
        while (bRunning):
            byte = self.oPort.read(1)
            #sys.stdout.write(byte)
            if True: #len(byte) > 0:
                self.commslogger.info("Node->Host: 0x%02x", ord(byte))

                if (ord(byte) == 0x01):
                    self.commslogger.debug("Start Message")
                    u8Checksum = 0
                    eMessageType = 0
                    u16Length = 0
                    sData = ""
                    state = 0
                elif (ord(byte) == 0x02):
                    self.commslogger.debug("ESC")
                    bInEsc = True
                elif (ord(byte) == 0x03):
                    self.commslogger.debug("End Message")

                    if not len(sData) == u16Length:
                        self.commslogger.warning("Length mismatch (Expected %d, got %d)", u16Length, len(sData))
                        continue

                    u8MyChecksum = ((eMessageType >> 8) & 0xFF) ^ ((eMessageType >> 0) & 0xFF)
                    u8MyChecksum = u8MyChecksum ^ ((u16Length >> 8) & 0xFF) ^ ((u16Length >> 0) & 0xFF)
                    for byte in sData:
                        u8MyChecksum = (u8MyChecksum ^ ord(byte)) & 0xFF

                    if not u8Checksum == u8MyChecksum:
                        self.commslogger.warning("Checksum mismatch (Expected 0x%02x, got 0x%02x)", u8Checksum, u8MyChecksum)
                        continue
                    self.commslogger.debug("Checksum ok")
                    return (eMessageType, sData)
                else:
                    if bInEsc:
                        bInEsc = False
                        byte = struct.pack("B", ord(byte) ^ 0x10)

                    if state == 0:
                        # TYpe MSB
                        eMessageTYpe = ord(byte) << 8
                        state = state + 1
                    elif state == 1:
                        eMessageType = eMessageType + ord(byte)
                        self.commslogger.debug("Message Type: 0x%04x", eMessageType)
                        state = state + 1
                    elif state == 2:
                        # Type MSB
                        u16Length = ord(byte) << 8
                        state = state + 1
                    elif state == 3:
                        u16Length = u16Length + ord(byte)
                        self.commslogger.debug("Message Length: 0x%04x", u16Length)
                        state = state + 1
                    elif state == 4:
                        u8Checksum = ord(byte)
                        self.commslogger.debug("Message Checksum: 0x%02x", u8Checksum)
                        state = state + 1
                    else:
                        self.commslogger.debug("Message Add Data: 0x%02x", ord(byte))
                        sData = sData + byte
        return (0, "")

    def run(self):
        """ Reader thread function.
            Keep reading message from the port.
            Log message are sent straight to the logger.
            Everything else is queued for listers that are waiting for message types via WaitMessage().
        """
        self.logger.debug("Read thread starting")


class cControlBridge():
    """Class implementing commands to the control bridge node"""
    def __init__(self, port, baudrate=115200):
        self.oSL = cSerialLink(port, baudrate)
        self.oPdm = cPDMFunctionality(port)


if __name__ == "__main__":
    from optparse import OptionParser
    parser = OptionParser()

    parser.add_option("-p", "--port", dest="port",
            help="Serial port device name to use", default=None)

    parser.add_option("-b", "--baudrate", dest="baudrate",
            help="Baudrate", default=1000000)

    (options, args) = parser.parse_args()

    logging.basicConfig(format="%(asctime)-15s %(levelname)s:%(name)s:%message)s")
    logging.getLogger().setLevel(logging.INFO)

    if options.port is None:
        parser.print_help()
        sys.exit(1)

    conn = sqlite3.connect('pdm.db')
    c = conn.cursor()
    conn.text_factory = str
    c.execute("""CREATE TABLE IF NOT EXISTS PdmData
                (PdmRecId text, PdmRecSize text, PersistedData text)""")

    conn.commit()
    conn.close()

    oCB = cControlBridge(options.port, options.baudrate)
    continueToRun = True
    oCB.oSL._WriteMessage(E_SL_MSG_PDM_HOST_AVAILABLE_RESPONSE,"00")
    useString = str(options.port)+ ""
    while continueToRun:
        commandd = input(useString+'$ ')
        if (command == ""):
            continueToRun = True
        else:
            continueToRun = oCB.parseCommand(command.strip())
    print ("Terminating current session...")
    sys.exit(1)

