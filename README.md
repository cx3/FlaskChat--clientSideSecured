Tested Python's sources and corresponding templates files.

script.py - Python's Flask Server
ChatUtils.py - encrypted chat utilities

Routes:
/
/create
/login
/chat/<name>

/create and /login can have url params like ?username=...&roomname=...

             Dedicated to red communists from UE who hates our privacy:

Chat is encrypted on the client side using the hash of the password provided when creating the room. 
This hash is  used to encrypt and  decrypt  chat room traffic.  Second  hash is sent to server while 
creating new room - it is stored  and used by server to  validate other users trying to join already 
existing rooms. Even somebody  had stolen  the second  hash,  it will never allow to decrypt traffic 
client-server. First  hash is derived  from password provided in login/create room form, and is used
for encryption/decryption messages  and images in client's web browser.  The data (messages, images)  
received at server's side are encrypted just before  leaving client's browser and the encryption key 
is not directly transfered - so even admin of server, net spies,  authorized official of the beloved 
European Union  -  without knowing  encryption key  the data is safe.  It is good  practice  to make 
long-term  arrangements of passwords  offline with people  you plan to chat with - such move reduces
the risk of password interception by unauthorized persons.  Remember to leave chat rooms by clicking
button "Leave chat" - it works instantly, special event is sent to server and the server informs all
the clients joined to your room - ordinary closing  tab in browser / closing whole window not always 
works fast what influences of server's session manager. When all users of the room leave it,  server
deletes room name,  creator name,  his ip  and authentication helper (second hash) - now re-creating
room with other credentials and admin data is possible,  of course no previous history is available. 
For additional layer of safety special token is derived at creating room, and it is a bind of: user,
room name, ip address. Anytime client's browser sends data to server for chatting, the token is sent
and server checks its validation to make sure nobody impersonates real author of message. Any source
code modification or  server restart  always destroys all room and all corresponding information, so
the tokens stored at client's browsers will no longer work - users have to create rooms again.  Also
trying to multi-log to one chat room from one machine is not possible - each new  tab or window does
not have session information needed for valid communication.

Server code  manually tested on  LAN with Windows, Linux  machines, as normal hosts and  virtualized.
Android phones and tablets were used as clients (Google Chrome, Opera, Firefox)

Add SSL for additional secure layer. At server side always check up-to-date Github code, never switch
off logs - you can then always control network traffic
