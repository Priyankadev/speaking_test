from pymongo import MongoClient
from flask import jsonify
import traceback
import json
import datetime
from bson import ObjectId


class Mdb:

    def __init__(self):
        conn_str = 'mongodb://stuser:stpass@ds123956.mlab.com:23956/' \
                   'speakingtest'
        client = MongoClient(conn_str)
        self.db = client['speakingtest']
# mongodb://<dbuser>:<dbpassword>@ds123956.mlab.com:23956/speakingtest
        print("[Mdb] connected to database :: ", self.db)


############################################################################
#                                                                          #
#                                                                          #
#                                                                          #
#                               CANDIDATE PANNEL                           #
#                                                                          #
#                                                                          #
#                                                                          #
############################################################################
############################################################################
#                                                                          #
#                CHECK EMAIL USER ALREADY REGISTERED OR NOT                #
#                                                                          #
############################################################################
    def check_email(self, email):
        return self.db.candidate.find({'email': email}).count() > 0

############################################################################
#                                                                          #
#                       REGITRATION CANDIDATE IN DATABASE                  #
#                                                                          #
############################################################################
    def add_candidate(self, name, email, pw_hash, age, phone, address, gender):
        try:
            rec = {
                'name': name,
                'email': email,
                'password': pw_hash,
                'age': age,
                'phone': phone,
                'address': address,
                'gender': gender
            }
            self.db.candidate.insert(rec)

        except Exception as exp:
            print("add_candidate() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#        CHECK EMAIL EXIST OR NOT IN DATABASE BEFORE LOGIN CANDIDATE       #
#                                                                          #
############################################################################
    def user_exists(self, email):
        return self.db.candidate.find({'email': email}).count() > 0

############################################################################
#                                                                          #
#                   MATCH PASSWORD AND EMAIL THEN LOGIN                    #
#                                                                          #
############################################################################
    def get_password(self, email):
        result = self.db.candidate.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print('password in db class', password)
        return password

############################################################################
#                                                                          #
#                GET NAME AND EMAILID VIA EMAIL ADDRESS                    #
#                                                                          #
############################################################################
    def get_name(self, email):
        result = self.db.candidate.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name

############################################################################
#                                                                          #
#                            GET TEST FROM DATABASE                        #
#                                                                          #
############################################################################
    def get_test(self):
        collection = self.db["test"]
        # result = collection.find({})
        result = collection.find().skip(self.db.test.count()-1)
        ret = []
        for data in result:
            ret.append(data)
        return ret

############################################################################
#                                                                          #
#                            GET TEST FROM DATABASE                        #
#                                                                          #
############################################################################
    def get_result(self):
        collection = self.db["result"]
        # result = collection.find({})
        result = collection.find().skip(self.db.result.count()-1)
        ret = []
        for data in result:
            ret.append(data)
        return ret

############################################################################
#                                                                          #
#                        CANDIDATE SESSION INFORMATION                     #
#                                                                          #
############################################################################
    def save_login_info(self, user_email, mac, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")

            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.candidate_session.insert(rec)
        except Exception as exp:
            print("save_login_info() :: Got exception: %s", exp)
            print(traceback.format_exc())


############################################################################
#                                                                          #
#                                                                          #
#                                                                          #
#                             ADMIN PANNEL                                 #
#                                                                          #
#                                                                          #
#                                                                          #
############################################################################
############################################################################
#                                                                          #
#                      ADD ADMIN IN DATABASE BY HARD CODE                  #
#                                                                          #
############################################################################
    def add_admin(self, email, password):
        try:
            rec = {
                'email': email,
                'password': password
            }
            self.db.admin.insert(rec)
        except Exception as exp:
            print("add_admin() :: Got exception: %s", exp)
            print(traceback.format_exc())

############################################################################
#                                                                          #
#       CHECK EMAIL EXIST OR NOT IN DATABASE BEFORE LOGIN CANDIDATE        #
#                                                                          #
############################################################################
    def admin_exists(self, email, password):

        return self.db.admin.find({'email': email, 'password': password}).\
                   count() > 0

############################################################################
#                                                                          #
#                           GET CANDIDATES DATA                            #
#                                                                          #
############################################################################
    def get_candidates(self):
        collection = self.db["candidate"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

############################################################################
#                                                                          #
#                       REGITRATION CANDIDATE IN DATABASE                  #
#                                                                          #
############################################################################
    def add_test(self, name, test):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': name,
                'test': test,
                'timestamp': ts
            }
            self.db.test.insert(rec)

        except Exception as exp:
            print("add_test() :: Got exception: %s", exp)
            print(traceback.format_exc())


############################################################################
#                                                                          #
#                       REGITRATION CANDIDATE IN DATABASE                  #
#                                                                          #
############################################################################
    def save_result(self, candidate, test, comparison, test_name):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'candidate': candidate,
                'candidate_data': test,
                'result': comparison,
                'test_name': test_name,
                'timestamp': ts
            }
            self.db.result.insert(rec)

        except Exception as exp:
            print("save_result() :: Got exception: %s", exp)
            print(traceback.format_exc())


############################################################################
#                                                                          #
#                          GET ALL TEST FROM DATABASE                      #
#                                                                          #
############################################################################
    def get_all_test(self):
        collection = self.db["test"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

############################################################################
#                                                                          #
#                        GET ALL RESULT FROM DATABASE                      #
#                                                                          #
############################################################################
    def get_results(self):
        collection = self.db["result"]
        results = collection.find({})
        ret = []
        for data in results:
            ret.append(data)
        return ret


############################################################################
#                                                                          #
#                                                                          #
#                                                                          #
#                              MAIN                                        #
#                                                                          #
#                                                                          #
#                                                                          #
############################################################################
if __name__ == "__main__":
    mdb = Mdb()
    mdb.add_admin('tom@gmail.com', '123')
