
import sys
import time
import serial
import logging
import struct
import threading
import queue
import sqlite3

# Message types

# /* Common Commands */
E_SL_MSG_STATUS                         = 0x8000
E_SL_MSG_LOG                            = 0x8001

E_SL_MSG_DATA_INDICATION                = 0x8002

E_SL_MSG_NODE_CLUSTER_LIST              = 0x8003
E_SL_MSG_NODE_ATTRIBUTE_LIST            = 0x8004
E_SL_MSG_NODE_COMMAND_ID_LIST           = 0x8005

E_SL_MSG_GET_VERSION                    = 0x0010
E_SL_MSG_VERSION_LIST                   = 0x8010

E_SL_MSG_SET_EXT_PANID                  = 0x0020
E_SL_MSG_SET_CHANNELMASK                = 0x0021
E_SL_MSG_SET_SECURITY                   = 0x0022
E_SL_MSG_SET_DEVICETYPE                 = 0x0023
E_SL_MSG_START_NETWORK                  = 0x0024
E_SL_MSG_START_SCAN                     = 0x0025
E_SL_MSG_NETWORK_JOINED_FORMED          = 0x8024

E_SL_MSG_RESET                          = 0x0011
E_SL_MSG_ERASE_PERSISTENT_DATA          = 0x0012
E_SL_MSG_ZLL_FACTORY_NEW                = 0x0013
E_SL_MSG_BIND                           = 0x0030
E_SL_MSG_UNBIND                         = 0x0031

E_SL_MSG_NETWORK_ADDRESS_REQUEST        = 0x0040
E_SL_MSG_IEEE_ADDRESS_REQUEST           = 0x0041
E_SL_MSG_NODE_DESCRIPTOR_REQUEST        = 0x0042
E_SL_MSG_SIMPLE_DESCRIPTOR_REQUEST      = 0x0043
E_SL_MSG_SIMPLE_DESCRIPTOR_RESPONSE     = 0x8043
E_SL_MSG_POWER_DESCRIPTOR_REQUEST       = 0x0044
E_SL_MSG_ACTIVE_ENDPOINT_REQUEST        = 0x0045
E_SL_MSG_MATCH_DESCRIPTOR_REQUEST       = 0x0046
E_SL_MSG_MATCH_DESCRIPTOR_RESPONSE      = 0x8046
E_SL_MSG_MANGEMENT_LEAVE_REQUEST        = 0x0047
E_SL_MSG_LEAVE_CONFIRMATION             = 0x8047
E_SL_MSG_LEAVE_INDICATION               = 0x8048
E_SL_MSG_PERMIT_JOINING_REQUEST         = 0x0049
E_SL_MSG_MANAGEMENT_NETWPRK_UPDATE_REQUEST =0x004A
E_SL_MSG_SYSTEM_SERVER_DISCOVERY        = 0x004B
E_SL_MSG_COMPLEX_DESCRIPTOR_REQUEST     = 0x004C
E_SL_MSG_DEVICE_ANNOUNCE                = 0x004D
E_SL_MSG_MANAGEMENT_LQI_REQUEST         = 0x004E
E_SL_MSG_MANAGEMENT_LQI_RESPONSE        = 0x804E
# /* Group Cluster */
E_SL_MSG_ADD_GROUP                      = 0x0006
E_SL_MSG_VIEW_GROUP                     = 0x0061
E_SL_MSG_GET_GROUP_MEMBERSHIP           = 0x0062
E_SL_MSG_GET_GROUP_MEMBERSHIP_RESPONSE  = 0x8062
E_SL_MSG_REMOVE_GROUP                   = 0x0063
E_SL_MSG_REMOVE_ALL_GROUP               = 0x0064
E_SL_MSG_ADD_GROUP_IF_IDENTIFY          = 0x0065

# /* Identify Cluster */
E_SL_MSG_IDENTIFY_SEND                  = 0x0070
E_SL_MSG_IDENTIFY_QUERY                 = 0x0071

# /* Level Cluster */
E_SL_MSG_MOVE_TO_LEVEL                  = 0x0080
E_SL_MSG_MOVE_TO_LEVEL_ONOFF            = 0x0081
E_SL_MSG_MOVE_STEP                      = 0x0082
E_SL_MSG_MOVE_STOP_MOVE                 = 0x0083
E_SL_MSG_MODE_STOP_ONOFF                = 0x0084

# /* On/Off Cluster */
E_SL_MSG_ONOFF_NOEFFECTS                = 0x0092
E_SL_MSG_ONOFF_TIMED                    = 0x0093
E_SL_MSG_ONOFF_EFFECTS                  = 0x0094

# /* Scenes Cluster */
E_SL_MSG_VIEW_SCENE                     = 0x00A0
E_SL_MSG_ADD_SCENE                      = 0x00A1
E_SL_MSG_REMOVE_SCENE                   = 0x00A2
E_SL_MSG_REMOVE_ALL_SCENES              = 0x00A3
E_SL_MSG_STORE_SCENE                    = 0x00A4
E_SL_MSG_RECALL_SCENE                   = 0x00A5
E_SL_MSG_SCENE_MEMBERSHIP_REQUEST       = 0x00A6

# /* Colour Cluster */
E_SL_MSG_MOVE_TO_HUE                    = 0x00B0
E_SL_MSG_MOVE_HUE                       = 0x00B1
E_SL_MSG_STEP_HUE                       = 0x00B2
E_SL_MSG_MOVE_TO_SATURATION             = 0x00B3
E_SL_MSG_MOVE_SATURATION                = 0x00B4
E_SL_MSG_STEP_SATURATION                = 0x00B5
E_SL_MSG_MOVE_TO_HUE_SATURATION         = 0x00B6
E_SL_MSG_MOVE_TO_COLOUR                 = 0x00B7
E_SL_MSG_MOVE_COLOUR                    = 0x00B8
E_SL_MSG_MOVE_STEP_COLOUR               = 0x00B9

# /* Zll Commands */
# /* Touchlink */
E_SL_MSG_INITIATE_TOUCHLINK             = 0x00D0
E_SL_MSG_TOUCHLINK_STATUS               = 0x00D1
E_SL_MSG_TOUCHLINK_FACTORY_RESET        = 0x00D2
# /* Identify Cluster */
E_SL_MSG_INDENTIFY_TRIGGER_EFFECT       = 0x00E0

# /* Scenes Cluster */
E_SL_MSG_ADD_ENHANCED_SCENE             = 0x00A7
E_SL_MSG_VIEW_ENHANCED_SCENE            = 0x00A8
E_SL_MSG_COPY_SCENE                     = 0x00A9

# /* Colour Cluster */
E_SL_MSG_ENHANCED_MOVE_TO_HUE           = 0x00BA
E_SL_MSG_ENHANCED_MOVE_HUE              = 0x00BB
E_SL_MSG_ENHANCED_STEP_HUE              = 0x00BC
E_SL_MSG_ENHANCED_MOVE_TO_HUE_SATURATION = 0x00BD
E_SL_MSG_COLOUR_LOOP_SET                = 0x00BE
E_SL_MSG_STOP_MOVE_STEP                 = 0x00BF
E_SL_MSG_MOVE_TO_COLOUR_TEMPERATURE     = 0x00C0
E_SL_MSG_MOVE_COLOUR_TEMPERATURE        = 0x00C1
E_SL_MSG_STEP_COLOUR_TEMPERATURE        = 0x00C2

# /* ZHA Command */
E_SL_MSG_LOCK_UNLOCK_DOOR               = 0x00F0
E_SL_MSG_READ_ATTRIBUTE_REQUEST         = 0x0100
E_SL_MSG_READ_ATTRIBUTE_RESPONSE        = 0x8100
E_SL_MSG_SAVE_PDM_RECORD                = 0x0200
E_SL_MSG_SAVE_PDM_RECORD_RESPONSE       = 0x8200
E_SL_MSG_LOAD_PDM_RECORD_REQUEST        = 0x0201
E_SL_MSG_LOAD_PDM_RECORD_RESPONSE       = 0x8201
E_SL_MSG_DELETE_PDM_RECORD              = 0x0202
E_SL_MSG_PDM_HOST_AVAILABLE             = 0x0300
E_SL_MSG_PDM_HOST_AVAILABLE_RESPONSE    = 0x8300

# Global flag to the threads
bRunning = True

class cPDMFunctionality(threading.Thread):
    """Class implementing the binary serial protocol to the control bridge node"""
    def __init__(self, port):
        threading.Thread.__init__(self, name="PDM")

        # Message queue used to pass message between reader thread and WaitMessage()
        self.dMessageQueue = {}
        self.logger = logging.getLogger(str(port))
        # Start reader thread
        self.daemon=True
        self.start()


class cSerialLink(threading.Thread):
    """Claass implementing the binary serial protocol to the control bridge node"""
    def __init__(self, port, baudrate=115200):
        threading.Thread.__init__(self, name="SL")
        self.logger = logging.getLogger(str(port))
        self.commslogger = logging.getLogger("Comm("+str(port)+")")
        
        # Turn this up to see traffic between node and host
        self.commslogger.setLevel(logging.WARNING)

        self.oPort = serial.Serial(port, baudrate)

        # Message queue used to pass message between reader thread and WaitMessage()
        self.dMessageQueue = {}

        # Start read thread
        self.daemon=True
        self.start()

    def _WriteByte(self, oByte, bSpecial=False, bAscii=False):
        """ Internal function
            Send a single byte to the serial por. Takes care of byte stuffing
        """
        if bAscii:
            if not bSpecial and oByte < 0x10:
                self.commslogger.info("Ascii Host->Node: 0x02 ESC")
                oByte = struct.pack("B", oByte ^ 0x10)
                self.oPort.write(struct.pack("B", 0x02))
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
            Send a complete message to the special port. Takes care of byte stuffing
            and checksum generation. eMessageType should be a 16bit message number
            sData is a string containing the packed message data
        """
        self.logger.info("Host->Node: MessageType 0x%04x, length %d %s", eMessageType, len(sData), sData)

        u8Checksum = ((eMessageType >> 8) & 0xFF) ^ ((eMessageType >> 0) & 0xFF)
        u8Checksum = u8Checksum ^ (((len(sData)//2) >> 8) & 0xFF) ^ (((len(sData)//2) >> 0) & 0xFF)
        bIn=True
        for byte in sData:
            if bIn:
                u8Byte = int(byte,16)<<4 & 0xFF
                bIn=False
            else:
                u8Byte |= int(byte,16)<<0 & 0xFF
                u8Checksum = u8Checksum ^ u8Byte
                bIn=True

        u16Length = len(sData)//2

        # Send header frame
        self._WriteByte(struct.pack("B", 0x01), True)
        self._WriteByte(struct.pack("B", (eMessageType >> 8) & 0xFF))
        self._WriteByte(struct.pack("B", (eMessageType >> 0) & 0xFF))
        self._WriteByte(struct.pack("B", (u16Length >> 8) & 0xFF))
        self._WriteByte(struct.pack("B", (u16Length >> 0) & 0xFF))
        self._WriteByte(struct.pack("B", u8Checksum & 0xFF))
        bIn=True

        # Send payload
        for byte in sData:
            if bIn:
                u8Byte = int(byte,16)<<4 & 0xFF
                bIn=False
            else:
                u8Byte |= int(byte,16)>>0 & 0xFF
                self._WriteByte(u8Byte,False,True)
                bIn=True

        # Send stop
        self._WriteByte(struct.pack("B", 0x03),True)

    def _ReadMessage(self):
        """ Internal function
            Read a complete message from the serial port. Takes care of byte stuffing
            Length and checksum message integrity checks.
            Return tuple of message type and buffer of data.
        """
        bInEsc=False

        u8Checksum=0
        eMessageType=0
        u16Length=0
        sData=""
        state=0
        
        while (bRunning):
            byte = self.oPort.read(1)
            #sys.stdout.write(byte)
            if True:
                self.commslogger.info("Node->Host: 0x%02x", ord(byte))

                if (ord(byte) == 0x01):
                    self.commslogger.debug("Start message")
                    u8Checksum=0
                    eMessageType=0
                    u16Length=0
                    sData=""
                    state=0
                elif (ord(byte) == 0x02):
                    self.commslogger.debug("ESC")
                    bInEsc=True
                elif (ord(byte) == 0x03):
                    self.commslogger.debug("End message")
                    self.logger.info("Data Received: " + ":".join("{:02x}".format(ord(c)) for c in sData))

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

                    self.commslogger.info("Checksum ok")
                    return (eMessageType, sData)
                else:
                    if bInEsc:
                        bInEsc=False
                        byte = struct.pack("B", ord(byte) ^ 0x10)

                    if state == 0:
                        # Type MSB
                        eMessageType = ord(byte) << 8
                        state = state + 1
                    elif state == 1:
                        eMessageType = eMessageType + ord(byte)
                        self.commslogger.info("Message Type: 0x%04x", eMessageType)
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
                        self.commslogger.debug("Message Add Data: 0x%02x, %s", ord(byte), str(byte))
                        sData = sData + chr(ord(byte))
                        
        return (0, "")

    def run(self):
        """ Read thread function.
            Keep reading message from the port.
            Log message are sent straight to the logger.
            Everything else is queued for listers that are waiting for message types via WaitMessage().
        """
        self.logger.debug("Read thread starting")
        try:
            while (bRunning):
                (eMessageType, sData) = self._ReadMessage()
                self.logger.info("Noe->Host: Response 0x%04x, length %d", eMessageType, len(sData))

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
                        self.logger.info("Module: : %s", logMessage)

                    if (eMessageType == E_SL_MSG_NODE_CLUSTER_LIST):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Node->Host: Cluster List Received %s", stringme)
                    if (eMessageType == E_SL_MSG_NODE_ATTRIBUTE_LIST):
                        self.logger.info("Node->Host: Attribute List")

                    if (eMessageType == E_SL_MSG_NODE_COMMAND_ID_LIST):
                        self.logger.info("Node->Host: Commands List")

                    if (eMessageType == E_SL_MSG_NETWORK_JOINED_FORMED):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Network joined/formed event received %s", stringme)
                    
                    if (eMessageType == E_SL_MSG_MATCH_DESCRIPTOR_RESPONSE):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Match Descriptor response %s", stringme)

                    if (eMessageType == E_SL_MSG_DEVICE_ANNOUCE):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Device Announce response %s", stringme)

                    if (eMessageType == E_SL_MSG_READ_ATTRIBUTE_RESPONSE):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Read Attribute response %s", stringme)

                    if (eMessageType == E_SL_MSG_GET_GROUP_MEMBERSHIP_RESPONSE):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("Get Group response %s", stringme)

                    if (eMessageType == E_SL_MSG_MANAGEMENT_LQI_RESPONSE):
                        stringme=(':'.join(x.encode('hex') for x in sData))
                        self.logger.info("LQI response %s", stringme)
                else:
                    try:
                        # Yield control to other thread to allow it to set up the listener
                        if ((eMessageType == E_SL_MSG_SAVE_PDM_RECORD) or
                            (eMessageType == E_SL_MSG_LOAD_PDM_RECORD_REQUEST) or
                            (eMessageType == E_SL_MSG_DELETE_PDM_RECORD) or
                            (eMessageType == E_SL_MSG_PDM_HOST_AVAILABLE)):
                                self.dMessageQueue[eMessageType] = queue.Queue(30)
                        time.sleep(0)
                        self.dMessageQueue[eMessageType].put(sData)
                    except KeyError:
                        self.logger.warning("Unhandled message 0x%04x", eMessageType)

        finally:
            self.logger.debug("Read thread terminated")


    def SendMessage(self, eMessageType, sData=""):
        """ Send a message to the node and wait its synchronous response
            Rais cSerialLinkError or cModuleError on failure
        """
        self.logger.info("Host->Node: Command 0x%04x, length %d", eMessageType, len(sData))
        self._WriteMessage(eMessageType, sData)
        try:
            status = self.WaitMessage(E_SL_MSG_STATUS, 1)
        except cSerialLinkError:
            raise cSerialLinkError("Module did not acknowledge command 0x%04x" % eMessageType)

        status = struct.unpack("B", status[0])[0]
        message = "" if len(sData) == 0 else sData

        if status == 0:
            stringme= (':'.join(x.encode('hex') for x in sData))
            self.logger.info("Command success. %s" % message)
        else:
            # Error status code
            raise cModuleError(status, message)


class cControlBridge():
    """Class implementing commands to the control bridge node"""
    def __init__(self, port, baudrate=115200):
        self.oSL = cSerialLink(port, baudrate)
        self.oPdm = cPDMFunctionality(port)

    def parseCommand(self, IncCommand):
        """parse commands"""
        command = str.split(IncCommand, ",")
        if command[0] == 'EXIT':
            return False
        if command[0] == 'EXP':
            self.SetExtendedPANID(command[1])
        if command[0] == 'GTV':
            print('Node Version: {0}'.format(self.GetVersion()))
        
        print("")
        return True
    
    def GetVersion(self):
        """Get the version of the connected node"""
        self.oSL.SendMessage(E_SL_MSG_GET_VERSION)

if __name__ == "__main__":
    from optparse import OptionParser
    parse = OptionParser()

    parse.add_option("-p", "--port", dest="port",
            help="Serial port device name to use", default=None)

    parse.add_option("-b", "--baudrate", dest="baudrate",
            help="Baudrate", default=1000000)

    (options, args) = parse.parse_args()

    logging.basicConfig(format="%(asctime)-15s %(levelname)s:%(name)s:%(message)s", level=logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)

    if options.port is None:
        parser.print_help()
        sys.exit(1)

    conn = sqlite3.connect('pdm.db')
    c = conn.cursor()
    conn.text_factory = str
    # Create table
    c.execute("""CREATE TABLE IF NOT EXISTS PdmData
                (PdmRecId text, PdmRecSize text, PersistedData text)""")

    conn.commit()
    conn.close()

    oCB = cControlBridge(options.port, options.baudrate)
    continueToRun = True
    oCB.oSL._WriteMessage(E_SL_MSG_PDM_HOST_AVAILABLE_RESPONSE, "00")
    useString = str(options.port)+ ""
    while continueToRun:
        command = input(useString+'$ ')
        if (command==""):
            continueToRun = True
        else:
            continueToRun = oCB.parseCommand(command.strip())

    print("Terminating current session...")
    sys.exit(1)
