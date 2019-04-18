
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

bRunning = True

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
        # calculate checksum value
        u8Checksum = ((eMessageType >> 8) & 0xFF) ^ ((eMessageType >> 0) & 0xFF)
        u8Checksum = u8Checksum ^ (((len(sData)) >> 8) & 0xFF) ^ (((len(sData)) >> 0) & 0xFF)
        bIn=True
        for byte in sData:
            if bIn:
                u8Byte = int(byte,16)<<4 & 0xFF
                bIn=False
            else:
                u8Byte |= int(byte,16)>>0 & 0xFF
                u8Checksum = u8Checksum ^ u8Byte
                bIn=True

        u16Length = len(sData)

        # send data
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
                        sData = sData + ord(byte)
        return (0, "")

    def run(self):
        """ Read thread function.
            Keep reading messages from the port.
            Log messages are sent straight to the logger.
            Eveything else is queued for listers that are waiting for message types via WaitMessage().
        """
        self.logger.debug("Read thread starting")
        try:
            while (bRunning):
                (eMessageType, sData) = self._ReadMessage()
                self.logger.info("Node->Host: Response 0x%04x, length %d", eMessageType, len(sData))

                if ((eMessageType == E_SL_MSG_LOG) or
                    (eMessageType == E_SL_MSG_NODE_CLUSTER_LIST) or
                    (eMessageType == E_SL_MSG_NODE_ATTRIBUTE_LIST) or
                    (eMessageType == E_SL_MSG_NODE_COMMAND_ID_LIST) or
                    (eMessageType == E_SL_MSG_NETWORK_JOINED_FORMED) or
                    (eMessageType == E_SL_MSG_MATCH_DESCRIPTOR_RESPONSE) or
                    (eMessageType == E_SL_MSG_DEVICE_ANNOUNCE) or
                    (eMessageType == E_SL_MSG_READ_ATTRIBUTE_RESPONSE) or
                    (eMessageType == E_SL_MSG_GET_GROUP_MEMBERSHIP_RESPONSE) or
                    (eMessageType == E_SL_MSG_MANAGEMENT_LQI_RESPONSE)):
                    if (eMessageType == E_SL_MSG_LOG):
                        logLevel = struct.unpack("B", sData[0])[0]
                        logLevel = ["EMERG", "ALERT", "CRIT ", "ERROR", "WARN ", "NOT  ", "INFO ", "DEBUG"][logLevel]
                        logMessage = sData[1:]
                        self.logger.info("Module: %s: %s", logLevel, logMessage)
                        self.logger.info("Module: %s", logMessage)

                    if (eMessageType == E_SL_MSG_NODE_CLUSTER_LIST):
                        stringme = (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Node->Host: Cluster List Received %s", stringme)
                    if (eMessageType == E_SL_MSG_NODE_ATTRIBUTE_LIST):
                        self.logger.info("Node->Host: Attribute List ")

                    if (eMessageType == E_SL_MSG_NODE_COMMAND_ID_LIST):
                        self.logger.info("Node->Host: Command List ")

                    if (eMessageType == E_SL_MSG_NETWORK_JOINED_FORMED):
                        stringme= (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Network joined/formed event received %s", stringme)

                    if (eMessageType == E_SL_MSG_MATCH_DESCRIPTOR_RESPONSE):
                        stringme = (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Match Descriptor response %s", stringme)

                    if (eMessageType == E_SL_MSG_DEVICE_ANNOINCE):
                        stringme= (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Device Announce response %s", stringme)

                    if (eMessageType == E_SL_MSG_READ_ATTRIBUTE_RESPONSE):
                        stringme= (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Read Attribute response %s", stringme)

                    if (eMessageType == E_SL_MSG_GET_MEMBERSHIP_RESPONSE):
                        stringme= (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("GetMembership response %s", stringme)

                    if (eMessageType == E_SL_MSG_MANAGEMENT_LQI_RESPONSE):
                        stringme= (':'.join(x.encode('hex') for x in sData))
                        self.logger.info("LQI response %s", stringme)
                else:
                    try:

                        # Yield control to other thread to allow it to set up the listener
                        if ((eMessageType == E_SL_MSG_SAVE_PDM_RECORD) or
                            (eMessageType == E_SL_MSG_LOAD_PDM_RECORD_REQUEST) or
                            (eMessageType == E_SL_MSG_DELETE_PDM_RECORD) or
                            (eMessageType == E_SL_MSG_PDM_HOST_AVAILABLE)):
                            self.dMessageQueue[eMessageType] = Queue.Queue(30)

                        time.sleep(0)
                        self.dMessageQueu[eMessageType].put(sData)
                    except KeyError:
                        self.logger.warning("Unhandleed message 0x%04x", eMessageType)
        finally:
            self.logger.debug("Read thread terminated")

    def SendMessage(self, eMessageType, sData=""):
        """ Send a message to the node and wait for its synchronous response
            Raise cSerialLinkError or cModuleError on failure
        """
        self.logger.info("Host->Node: Command 0x%04x, length %d", eMessageType, len(sData))
        self._WriteMessage(eMessageType, sData)
        try:
            status = self.WaitMessage(E_SL_MSG_STATUS, 1)
        except cSerialLinkError:
            raise cSerialLinkeError("Module did not acknowledge command 0x%04x" % eMessageType)

        status = struct.unpack("B", status[0])[0]
        message = "" if len(sData) == 0 else sData

        if status == 0:
            stringme = (':'.join(x.encode('hex') for x in sData))
            self.logger.info("Command success. %s " % message)
        else:
            # Error status code
            raise cModuleError(status, message)

    def WaitMessage(self, eMessageType, fTimeout):
        """ Wait for a message of type eMessageType for fTimeout seconds
            Raise cSerialLinkError on failure
            Many different threads can all block on this function as long
            as they are waiting on different message types.
        """
        sData = None
        try:
            # Get the message from the receiver thread and delete the queue entry
            sData = self.dMessageQueue[eMessageType].get(True, fTimeout)
            del self.dMessageQueue[eMessageType]
        except KeyError:
            self.dMessageQueue[eMessageType] = Queue.Queue()
            try:
                # Get the message from the receiver thread and delete the queue entry
                sData = self.dMessageQueue[eMessageType].get(True, fTimeout)
                del self.dMessageQueue[eMessageType]
            except Queue.Empty:
                # Raise exceptin no data received
                raise cSerialLinkError("Message 0x%04x not received with %fs" % (eMessageType, fTimerout))
        self.logger.debug("Pulled message type 0x%04x from queue", eMessageType)
        return sData



class cControlBridge():
    """Class implementing commands to the control bridge node"""
    def __init__(self, port, baudrate=115200):
        self.oSL = cSerialLink(port, baudrate)
        self.oPdm = cPDMFunctionality(port)

    def parseCommand(self, IncCommand):
        """parse commands"""
        command=str.split(IncCommand, ",")
        if command[0] == 'EXIT':
            return False

        if command[0] == 'EXP':
            self.SetExtendedPANID(command[1])


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
        command = input(useString+'$ ')
        if (command == ""):
            continueToRun = True
        else:
            continueToRun = oCB.parseCommand(command.strip())
    print ("Terminating current session...")
    sys.exit(1)

