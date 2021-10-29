# system imports
import sys
import socket
from threading import Thread
import pygubu
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
# local import from "protocol.py"
from protocol import Protocol, User


class Assignment3VPN:
    # Constructor
    def __init__(self, master=None):
        # Initializing UI
        self.builder = builder = pygubu.Builder()
        builder.add_from_file("UI.ui")
        
        # Getting references to UI elements
        self.mainwindow = builder.get_object('toplevel', master)
        self.hostNameEntry  = builder.get_object('ipEntry', self.mainwindow)
        self.connectButton  = builder.get_object('connectButton', self.mainwindow)
        self.secureButton  = builder.get_object('secureButton', self.mainwindow)
        self.clientRadioButton = builder.get_object('clientRadioButton', self.mainwindow)
        self.serverRadioButton = builder.get_object('serverRadioButton', self.mainwindow)
        self.ipEntry = builder.get_object('ipEntry', self.mainwindow)
        self.portEntry = builder.get_object('portEntry', self.mainwindow)
        self.secretEntry = builder.get_object('secretEntry', self.mainwindow)
        self.sendButton = builder.get_object('sendButton', self.mainwindow)
        self.logsText = builder.get_object('logsText', self.mainwindow)
        self.messagesText = builder.get_object('messagesText', self.mainwindow)
        
        # Getting bound variables
        self.mode = None
        self.hostName = None
        self.port = None
        self.sharedSecret = None
        self.textMessage = None
        builder.import_variables(self, ['mode', 'hostName', 'port', 'sharedSecret', 'textMessage'])               
        builder.connect_callbacks(self)
        
        # Network socket and connection
        self.s = None
        self.conn = None
        self.addr = None
        
        # Server socket threads
        self.server_thread = Thread(target=self._AcceptConnections, daemon=True)
        self.receive_thread = Thread(target=self._ReceiveMessages, daemon=True)
        
        # Creating a protocol object
        self.prtcl = Protocol()
     
    # Distructor     
    def __del__(self):
        # Closing the network socket
        if self.s is not None:
            self.s.close()
            
        # Killing the spawned threads
        if self.server_thread.is_alive():
            self.server_thread.terminate()
        if self.receive_thread.is_alive():
            self.receive_thread.terminate()
            
    
    # Handle client mode selection
    def ClientModeSelected(self):
        self.hostName.set("localhost")


    # Handle sever mode selection
    def ServerModeSelected(self):
        pass


    # Create a TCP connection between the client and the server
    def CreateConnection(self):
        # Change button states
        self._ChangeConnectionMode()
        
        # Create connection
        if self._CreateTCPConnection():
            if self.mode.get() == 0:
                # enable the secure and send buttons
                self.secureButton["state"] = "enable"
                self.sendButton["state"] = "enable"
        else:
            # Change button states
            self._ChangeConnectionMode(False)


    # Establish TCP connection/port
    def _CreateTCPConnection(self):
        if not self._ValidateConnectionInputs():
            return False
        
        self.prtcl.SetSessionKey(self.secretEntry.get())

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.mode.get() == 0:
                self._AppendLog("CONNECTION: Initiating client mode...")
                self.s.connect((self.hostName.get(), int(self.port.get())))
                self.conn = self.s
                self.prtcl._id = User.CLIENT
                self.receive_thread.start()
                self._AppendLog("CLIENT: Connection established successfully. You can now send/receive messages.")
            else:
                self._AppendLog("CONNECTION: Initiating server mode...")
                self.s.bind((self.hostName.get(), int(self.port.get())))
                self.s.listen(1)
                self.prtcl._id = User.SERVER
                self.server_thread.start()
            return True
        except Exception as e:
            self._AppendLog("CONNECTION: connection failed: {}".format(str(e)))
            return False
            
     
    # Accepting connections in a separate thread
    def _AcceptConnections(self):
        try:
            # Accepting the connection
            self._AppendLog("SERVER: Waiting for connections...")
            self.conn, self.addr = self.s.accept()
            self._AppendLog("SERVER: Received connection from {}. You can now send/receive messages".format(self.addr))
            
            # Starting receiver thread
            self.receive_thread.start()
            
            # Enabling the secure and send buttons
            self.secureButton["state"] = "enable"
            self.sendButton["state"] = "enable"
        except Exception as e:
            self._AppendLog("SERVER: Accepting connection failed: {}".format(str(e)))
            return False


    # Receive data from the other party
    def _ReceiveMessages(self):
        while True:
            try:
                # Receiving all the data
                cipher_text = self.conn.recv(4096)

                # Check if socket is still open
                if cipher_text == None or len(cipher_text) == 0:
                    self._AppendLog("RECEIVER_THREAD: Received empty message")
                    break

                # Checking if the received message is part of your protocol
                # TODO: MODIFY THE INPUT ARGUMENTS AND LOGIC IF NECESSARY
                if self.prtcl.IsMessagePartOfProtocol(cipher_text):
                    # Disabling the button to prevent repeated clicks
                    self.secureButton["state"] = "disabled"
                    # Processing the protocol message
                    auth_msg = cipher_text.decode("utf-8")
                    print("Authenticate Message by other: {}".format(auth_msg))
                    session_key, return_message = self.prtcl.ProcessReceivedProtocolMessage(auth_msg)

                    if session_key:
                        self.prtcl.SetSessionKey(session_key)
                        # 1-side Authentication was successful when shared key is generated
                        other_id = User.SERVER.name if self.prtcl._id == User.CLIENT else User.CLIENT.name
                        self._AppendMessage('You successfully authenticated {}!'.format(other_id))
                        self._AppendMessage('Your new shared key is {}'.format(self.prtcl._key))

                    if return_message:
                        self._SendMutualAuthentication(return_message)

                # Otherwise, decrypting and showing the messaage
                else:
                    plain_text = self.prtcl.DecryptAndVerifyMessage(cipher_text)
                    self._AppendMessage("Other: {}".format(plain_text.decode()))
                    
            except Exception as e:
                self._AppendLog("RECEIVER_THREAD: Error receiving data: {}".format(str(e)))
                return False

    # Send authentication message without encrypting
    def _SendMutualAuthentication(self, message):
        self.conn.send(message.encode())
        print("Authenticate Message by you: {}".format(message))

    # Send data to the other party
    def _SendMessage(self, message):
        plain_text = message
        cipher_text = self.prtcl.EncryptAndProtectMessage(plain_text)
        self.conn.send(cipher_text.encode())
            

    # Secure connection with mutual authentication and key establishment
    def SecureConnection(self):
        # disable the button to prevent repeated clicks
        self.secureButton["state"] = "disabled"

        # TODO: THIS IS WHERE YOU SHOULD IMPLEMENT THE START OF YOUR MUTUAL AUTHENTICATION AND KEY ESTABLISHMENT PROTOCOL, MODIFY AS YOU SEEM FIT
        init_message = self.prtcl.GetProtocolInitiationMessage()
        self._SendMutualAuthentication(init_message)


    # Called when SendMessage button is clicked
    def SendMessage(self):
        text = self.textMessage.get()
        if  text != "" and self.s is not None:
            try:
                self._SendMessage(text)
                self._AppendMessage("You: {}".format(text))
                self.textMessage.set("")
            except Exception as e:
                self._AppendLog("SENDING_MESSAGE: Error sending data: {}".format(str(e)))
                
        else:
            messagebox.showerror("Networking", "Either the message is empty or the connection is not established.")


    # Clear the logs window
    def ClearLogs(self):
        self.logsText.configure(state='normal')
        self.logsText.delete('1.0', tk.END)
        self.logsText.configure(state='disabled')

    
    # Append log to the logs view
    def _AppendLog(self, text):
        self.logsText.configure(state='normal')
        self.logsText.insert(tk.END, text + "\n\n")
        self.logsText.see(tk.END)
        self.logsText.configure(state='disabled')

        
    def _AppendMessage(self, text):
        self.messagesText.configure(state='normal')
        self.messagesText.insert(tk.END, text + "\n\n")
        self.messagesText.see(tk.END)
        self.messagesText.configure(state='disabled')


    # Enabling/disabling buttons based on the connection status
    def _ChangeConnectionMode(self, connecting=True):
        value = "disabled" if connecting else "enabled"
        
        # change mode changing
        self.clientRadioButton["state"] = value
        self.serverRadioButton["state"] = value
        
        # change inputs
        self.ipEntry["state"] = value
        self.portEntry["state"] = value
        self.secretEntry["state"] = value
        
        # changing button states
        self.connectButton["state"] = value

        
    # Verifying host name and port values
    def _ValidateConnectionInputs(self):
        if self.hostName.get() in ["", None]:
            messagebox.showerror("Validation", "Invalid host name.")
            return False
        
        try:
            port = int(self.port.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Validation", "Invalid port range.")
                return False
        except:
            messagebox.showerror("Validation", "Invalid port number.")
            return False
            
        return True

        
    # Main UI loop
    def run(self):
        self.mainwindow.mainloop()


# Main logic
if __name__ == '__main__':
    app = Assignment3VPN()
    app.run()
