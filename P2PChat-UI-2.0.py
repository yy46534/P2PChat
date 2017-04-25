#!/usr/bin/python3

# Student name and No.: Fong Yuet Yi, 3035096412
# Student name and No.: Yiu Lok Yan Serena, 3035179721
# Development platform: Windows 10 and macOS Sierra
# Python version: 3.5
# Version: 2.0


from tkinter import *
import sys
import socket
import threading
import collections
import time

#
# Global variables
#

username = ""
roomname = ""
joined = False
ser_addr = ""
ser_port = ""
local_port = ""
chatroom_list = {}
local_IP = ""
TheSoc =socket.socket()
MSID = 0
backward_list = {}
forwardSoc = socket.socket()
listenSoc = socket.socket()
msgID = 0
flag = 0
userID = 0
forward_userID = 0
msg_records = [-1]*20

#
# Global Threading objects
#
all_thread_running = True
cthread = []
gLock = threading.Lock()

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

#
# Setup connection
#
def Connect(address, port): #//////////S
	global local_IP
	global TheSoc
	try:
		TheSoc.connect((address, port))
	except socket.error as emsg:
		print("There is error with connecting: ", emsg)
		sys.exit(0)
	local_addr = TheSoc.getsockname()
	local_IP = local_addr[0]
	print(local_IP)

#
# Create userIP
#
def create_myHashID():
	global userID
	idDraft = username+local_IP+local_port
	userID = sdbm_hash(idDraft)
	print(str(userID))
	return userID
#
# Sort a dictionary
#
def sort_list(list):
	return collections.OrderedDict(sorted(list.items()))


#
# Select a P2PChat peer ofr initiating forward link
#
def create_forwardlink():
	global forwardSoc
	global forward_userID
	global flag

	MyHashID = create_myHashID()
	start = (int(list(chatroom_list.keys()).index(str(MyHashID)))+1)%len(chatroom_list)
    # list of the value, which are the user's information [hashid,name,IP addr, port]
	items = list(chatroom_list.values())
	print("Try to create forward link")
	if flag == 0:
		if len(items) > 1:
			print(items[start][0])
			print("trying: ", items[start][1])
			# items[start][0] = the hashid of the users
			while items[start][0] != str(MyHashID) :
				# backward_list stores the hashid of the peers that have connection with the user (backward link)
				if items[start][0] in list(backward_list.keys()):
					start = (start+1)%len(chatroom_list)
					print("fail, already in backwardlist")
					continue
				else:
					forward_userID = items[start][0]
					member_addr = items[start][2]
					member_port = items[start][3]
					member_name = items[start][1]
					try:
						forwardSoc.connect((member_addr,int(member_port)+1))
						msg =  "P:"+roomname+":"+username+":"+local_IP+":"+local_port+":"+str(msgID)+"::\r\n"
						forwardSoc.send(msg.encode("ascii"))
						rMsg = forwardSoc.recv(50)
						if rMsg == '':
							print("fail, no response from  ", member_name)
							start = (start+1)%len(chatroom_list)
							continue
						else:
							#Start thread for that new backward link
							message_thr_obj = threading.Thread(target=message_thr, name="Message", args=(forwardSoc,member_name))
							message_thr_obj.start()
							cthread.append(message_thr_obj)

							print(rMsg.decode("ascii"))
							print("Establish forward link sucessfully to peer ", member_name) #items[start][1]
							flag = 1
							break

					except socket.error as emsg:
						print("There is error with connecting: ", emsg)
						print("Try another guy")
						start = (start+1)%len(chatroom_list)
						continue
		else:
			print("There is only one user in the chatroom, can't create forward link.")
	else:
		print("already have forward link, no need to create again.")
	if flag == 0:
		print("There is error in creating a forward link.")


#
# Setup listening socket for backward connection
#
def setup_listening():
	global listenSoc

	listening_port = int(local_port)+1
	# allow reuse of port number without holding up port number
	listenSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	# set socket blocking duration to 1.0s
	listenSoc.settimeout(1.0)

	# bind to the listening socket address
	try:
		listenSoc.bind(('', listening_port))
	except socket.error as emsg:
		print("Listening Socket bind error: ", emsg)
		sys.exit(1)

	# set socket listening queue
	listenSoc.listen(10)

	print("Finish listening socket set up.")

#
# listening thread: listening to backward link connection
#
def listen_thr():
	global all_thread_running, msgID
	myName = threading.current_thread().name
	while(all_thread_running):
		try:
			# wait for incoming connection request
			# however, the socket may unblock after 1.0 second
			try:
				newfd, caddr = listenSoc.accept()
			except socket.timeout:
				# catch a timeout exception if the timeout
				# duration has elapsed
				# well, if no other exception, just call
				# accept again
				continue

			# the system just accepted a new client connection
			print("A new backward link has arrived. It is at:", caddr)

			# generate a name to this client
			cname = caddr[0]+':'+str(caddr[1])

			# receive message
			msg = newfd.recv(500)
			rMsg = msg.decode("ascii")
			print(rMsg)
			sMsg = rMsg.split(":")
			fd_username = sMsg[2]
			fd_IP = sMsg[3]
			fd_port = sMsg[4]
			instr = fd_username+fd_IP+str(fd_port)
			fd_hash = sdbm_hash(instr)

			# add the new client socket to the backward list
			gLock.acquire()
			backward_list[str(fd_hash)] = newfd
			gLock.release()

			#send confirm message
			msgID += 1
			msg = "S:"+str(msgID)+"::\r\n"
			newfd.send(msg.encode("ascii"))

			#Start thread for that new backward link
			message_thr_obj = threading.Thread(target=message_thr, name="Message", args=(newfd,fd_username))
			message_thr_obj.start()
			cthread.append(message_thr_obj)


		except KeyboardInterrupt:
			# if Cltr-C is detected, break out of main loop
			# and run the shutdown procedure
			print("At listening thread, caught the KeyboardInterrupt")
			do_Quit()

	print("[%s] Thread termination" % myName)
	return

#
# function to handle received message
#
def process_recvMsg(recvMsg, newfd):
    global msg_records, userID, flag, forwardSoc, chatroom_list, backward_list, username

    #TEXT = "T:roomname:userID:username:msgID:length_of_msg:message_content::\r\n"
    original_msg = recvMsg.decode("ascii")
    sMsg = original_msg.split(':')
    #check chatroom
    if sMsg[1] != roomname:
        print("Error! Received message from other chatroom")
    else:
		#check if the message has been seen by this user before
        if msg_records[int(sMsg[2])%20] == sMsg[4]:
            print("This message has been received before, no need forward again.")
        else:
            #check if the message is a quit message:::"Q:roomname:userid:username:msgID:flag_raise(if from forward socket)"
            if sMsg[0] == "Q":
                print(sMsg)
                #update the chatroom_list
                #Send Join message
                msg = "J:"+roomname+":"+username+":"+local_IP+":"+local_port+"::\r\n"
                TheSoc.send(msg.encode("ascii"))
                #Handle chatroom user list
                msg = TheSoc.recv(1000)
                rMsg = msg.decode("ascii")
                pMsg = rMsg.split(':')
                chatroom_list.clear()
                update_chatroom_list(pMsg)
                #check where it comes from and remove it from
                if sMsg[5] == '1':
                    flag = 0
                    forwardSoc.close()
                    forwardSoc = socket.socket()
                    create_forwardlink()
                else:
                    if newfd in list(backward_list.values()):
                        print("delete the link in backward list.")
                        del backward_list[sMsg[2]]
                return

            if sMsg[0] == "T":
                #length_of_smsg = len(sMsg)
                if sMsg[2] != userID:
                    message_length = int(sMsg[5])
                    mContent = original_msg[-4-message_length:-4]
                    MMsg = sMsg[3]+" : "+ mContent + "\n"
                    MsgWin.insert(1.0, MMsg)

                    #memorize the msgID
                    msg_records[int(sMsg[2])%20] = sMsg[4]

                    # relay message to forward link, other backward link
                    #if have forward link
                    if flag == 1:
                        if forwardSoc != newfd:
                            print("relay to forward socket.")
                            forwardSoc.send(recvMsg)
                    for soc in list(backward_list.values()):
                        if soc != newfd:
                            print("relay to backward socket.")
                            soc.send(recvMsg)


#
# Update chatroom list
#
def update_chatroom_list(sMsg):
    global chatroom_list,MSID
    if sMsg[0] == 'M':
        #update the userlist
        MSID = sMsg[1]
        i = 2
        user = [0,0,0,0]
        while sMsg[i] != '':
            k = i-2
            if k%3 == 0:
                user[1] = sMsg[i]
            if k%3 == 1:
                user[2] = sMsg[i]
            if k%3 == 2:
                user[3] = sMsg[i]
            if user[3] != 0:
                imsg = user[1]+user[2]+user[3]
                usr_id = str(sdbm_hash(imsg))
                user[0]=usr_id
                chatroom_list[usr_id]=user
                user = [0,0,0,0]
                MMsg = "\nname: "+chatroom_list[usr_id][1]+" user_ip: "+chatroom_list[usr_id][2]+" user_port: "+chatroom_list[usr_id][3]
                CmdWin.insert(1.0,MMsg)
            i += 1
        chatroom_list = sort_list(chatroom_list)
        CmdWin.insert(1.0,"\nChatroom member list:")
        print("##Keepalive:: Sorted chatroom_list : ", chatroom_list)

    return



#
# message transfer thread (for each connection in backward list and the forward link)
#
def message_thr(newfd, fd_name):
    print("start message thread of " + fd_name + ".")
    # get the name of this thread
    myName = threading.current_thread().name

    # set the blocking duration of this client socket
    # set this to 1.0 second
    newfd.settimeout(1.0)

    # while loop
    # check whether the termination condition has reached
    while (all_thread_running):
        # wait for any message to arrive
        # as the socket is set to return if no activity happened
        # in 1.0 second, you need to handle the timeout event correctly
        try:
            try:
                rmsg = newfd.recv(500)
            except socket.timeout:
                continue
        except socket.error:
            print("Connection drop: " + fd_name)
            return


		# if has message arrived, do the following
        if rmsg:
            print("Got a message!!")
            process_recvMsg(rmsg, newfd)
        else:
            print("Connection drop: " + fd_name)
            return

    # if the termination condition has reached, print the following
    # and go away
    print("[%s] Thread termination" % myName)
    return


#
# Keep Alive
#
def keepalive_thr():
    global MSID
    global chatroom_list
    global cthread, all_thread_running

    myName = threading.current_thread().name
    while(all_thread_running):
        time.sleep(20)
        try:
    		#Send Join message
            msg = "J:"+roomname+":"+username+":"+local_IP+":"+local_port+"::\r\n"
            TheSoc.send(msg.encode("ascii"))

            #Handle chatroom user list
            msg = TheSoc.recv(1000)
            rMsg = msg.decode("ascii")
            sMsg = rMsg.split(':')
            if sMsg[0] == 'M':
                #check if the user list has changed
                if MSID == sMsg[1]:
                    print("keepalive: There is no change in userlist")
                else:
                    update_chatroom_list(sMsg)
                    create_forwardlink()
        except socket.error:
            print("Keepalive termination.")
            return
    print("Keepalive termination.")



#
# Functions to handle user input
#

def do_User():
    print(str(joined))
    if joined == True:
        CmdWin.insert(1.0,"\nYou have joined a chatroom. You cannot change your username.")
        userentry.delete(0,END)
    else:
        global username
        user_input = userentry.get()
        if user_input != '':
            username = userentry.get()
            outstr = "\n[User] username: "+username
            CmdWin.insert(1.0, outstr)
            userentry.delete(0, END)
        else:
            CmdWin.insert(1.0,"\nPlease input your username")


def do_List():
	msg = "L::\r\n"
	TheSoc.send(msg.encode("ascii"))
	msg = TheSoc.recv(1000)
	rMsg = msg.decode("ascii")
	if rMsg == "G::\r\n":
		CmdWin.insert(1.0,"\nThere is no chatroom group")
	else:
		msg = rMsg.split(':')
		if msg[0] != 'F':
			CmdWin.insert(1.0,"\nNow listing the chatroom groups......")
			i = 1
			while msg[i] != '':
				CmdWin.insert(1.0, "\n"+msg[i])
				i +=1
		else:
			CmdWin.insert(1.0,"\n There is error:")
			CmdWin.insert(1.0, msg[1])


def do_Join():
    global chatroom_list
    global joined
    global roomname
    global MSID

    user_input = userentry.get()
    if username != '':
        if user_input == '' :
            CmdWin.insert(1.0, "\nPlease input a chatroom name. If the chatroom you typed in does not exist, we will open up one for you. ")
        else:
            if joined == True:
                CmdWin.insert(1.0,"\nYou have joined a chatroom already.")
            else:
                # Send join message
                roomname = user_input
                joined = True
                userentry.delete(0, END)
                msg = "J:"+roomname+":"+username+":"+local_IP+":"+local_port+"::\r\n"
                TheSoc.send(msg.encode("ascii"))
                msg = TheSoc.recv(1000)
                rMsg = msg.decode("ascii")
                sMsg = rMsg.split(':')
                if sMsg[0] == 'M':
                    update_chatroom_list(sMsg)
                    CmdWin.insert(1.0, "\nYou have now joined the chatroom, "+ roomname )
                    keepalive_thr_obj = threading.Thread(target=keepalive_thr, name="Keepalive", args=())
                    keepalive_thr_obj.daemon = True
                    keepalive_thr_obj.start()
                    create_forwardlink()
                else:
                    CmdWin.insert(1.0,"\n There is error:")
                    CmdWin.insert(1.0, sMsg[1])
    else:
        CmdWin.insert(1.0, "\nPlease input a username first")

def do_Send():
    global username, msgID
    message = userentry.get()
    userentry.delete(0, END)

    if message != '' and roomname != '' :
        display = username + " : " + message + "\n"
        MsgWin.insert(1.0, display)

        if flag == 1 or backward_list:
            msgID += 1
            TEXT = "T:"+roomname+":"+ str(userID)+":"+username+":"+str(msgID)+":"+str(len(message))+":"+message+"::\r\n"
            #there is forwardlink
            if flag == 1:
                #send to forward link
                forwardSoc.send(TEXT.encode("ascii"))

            #send to backward links
            for soc in list(backward_list.values()):
                soc.send(TEXT.encode("ascii"))
    else:
        if message == '':
            CmdWin.insert(1.0, "\nPlease input message")
        if roomname == '':
            CmdWin.insert(1.0, "\nPlease join a room")



def do_Quit():
    global gLock, all_thread_running, cthread, msgID

    # close connection with server
    TheSoc.close()

    msgID += 1
    # send quit message to the links :::"Q:roomname:userid:username:msgID:flag_raise(if from forward socket)"
    MMsg = "Q:"+roomname+":"+str(userID)+":"+username+":"+str(msgID)+":"
    # rise the flag that indicates it is sent from the forward link of the target user
    backMMsg = MMsg + "1"
    for soc in list(backward_list.values()): #send to backward link
        soc.send(backMMsg.encode("ascii"))
    # there is a forward link
    if flag == 1:
        # rise the flag that indicates this message is sent from one of the backward link of the target user
        forMMsg = MMsg + "0"
        forwardSoc.send(forMMsg.encode("ascii"))

    # shutdown the server and its threads
    print("Shutdown Chatserver...")
    # set this global variable to False to terminate all threads
    all_thread_running = False
    # wait for all threads to terminate before termination of main thread
    for th in cthread:
        th.join()
    print("All threads terminated.")
    #close all sockest
    if flag == 1:
        forwardSoc.close()
    listenSoc.close()
    for soc in list(backward_list.values()):
        soc.close()
    print("All sockets closed.")
    print("Terminate program.")
    sys.exit(0)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)



def main():
    global ser_addr
    global ser_port
    global local_port
    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)
    else:
        ser_addr = sys.argv[1]
        ser_port = sys.argv[2]
        local_port = sys.argv[3]
        TheSoc.bind(("0.0.0.0", int(local_port)))
        Connect(ser_addr, int(ser_port))


        setup_listening()
        print("Enter main loop...")
        listen_thr_obj = threading.Thread(target=listen_thr, name="Listening", args=())
        listen_thr_obj.start()
        cthread.append(listen_thr_obj)

    win.mainloop()

if __name__ == "__main__":
    main()
